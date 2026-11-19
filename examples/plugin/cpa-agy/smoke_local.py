"""Exercise a Linux CPA binary and cpa-agy.so against a loopback upstream.

Run in a network-isolated container: python3 smoke_local.py CPA_BINARY CPA_AGY_SO
"""

import datetime
import http.server
import json
import pathlib
import shutil
import socket
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.request
from queue import Queue


MODEL = "gemini-4-hydrogen-xhigh"
CATALOG_PATH = "/v1internal:fetchAvailableModels"
GENERATION_PATHS = ("/v1internal:generateContent", "/v1internal:streamGenerateContent")


class Upstream(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
        streaming = self.path.startswith(GENERATION_PATHS[1])
        if self.path == CATALOG_PATH:
            response = {"models": {MODEL: {}}}
        elif self.path.startswith(GENERATION_PATHS):
            self.server.requests.put((self.path, body))
            response = {
                "response": {
                    "candidates": [{"content": {"role": "model", "parts": [{"text": "OK"}]},
                                    "finishReason": "STOP"}],
                    "usageMetadata": {"promptTokenCount": 4, "candidatesTokenCount": 1, "totalTokenCount": 5},
                }
            }
        else:
            self.send_error(404)
            return
        raw = json.dumps(response)
        payload = (f"data: {raw}\n\n" if streaming else raw).encode()
        try:
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream" if streaming else "application/json")
            self.send_header("Content-Length", str(len(payload)))
            self.end_headers()
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            # CPA can cancel a background capability probe during shutdown.
            if self.path != CATALOG_PATH:
                raise

    def log_message(self, *_args):
        pass


def exercise(root, binary, library, upstream):
    plugin = root / "plugins/linux/amd64/cpa-agy.so"
    plugin.parent.mkdir(parents=True)
    shutil.copyfile(library, plugin)
    token = "synthetic-upstream-token"
    source, replacement, unmatched = "qa-source-marker", "qa-rewritten-marker", "qa-unmatched-marker"
    rules = root / "rules.json"
    rules.write_text(json.dumps({"mode": "merge", "literals": [{"find": source, "replace": replacement}]}))
    auth_dir = root / "auths"
    auth_dir.mkdir()
    expiry = datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=1)
    (auth_dir / "local.json").write_text(json.dumps({
        "type": "antigravity", "access_token": token, "expired": expiry.isoformat(timespec="seconds"),
        "project_id": "synthetic-project", "base_url": f"http://127.0.0.1:{upstream.server_port}",
    }))
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        port = sock.getsockname()[1]
    config = root / "config.yaml"
    config.write_text(f'''host: "127.0.0.1"
port: {port}
auth-dir: "{auth_dir}"
api-keys: ["synthetic-client-key"]
remote-management:
  disable-control-panel: true
request-retry: 0
plugins:
  enabled: true
  dir: "{root / 'plugins'}"
  configs:
    cpa-agy:
      enabled: true
      rules_file: "{rules}"
''')
    opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def call(path, body=None):
        req = urllib.request.Request(f"http://127.0.0.1:{port}{path}",
                                     data=None if body is None else json.dumps(body).encode(),
                                     headers={"Authorization": "Bearer synthetic-client-key",
                                              "Content-Type": "application/json"})
        with opener.open(req, timeout=10) as response:
            return json.load(response)

    log_path = root / "cpa.log"
    with log_path.open("w") as output:
        proc = subprocess.Popen([binary, "--config", config, "--local-model"],
                                cwd=root, stdout=output, stderr=subprocess.STDOUT)
        try:
            model = MODEL
            deadline = time.monotonic() + 15
            while True:
                try:
                    models = call("/v1/models")["data"]
                    if any(entry["id"] == model for entry in models):
                        break
                except urllib.error.HTTPError:
                    raise
                except urllib.error.URLError:
                    if proc.poll() is not None:
                        raise
                if time.monotonic() >= deadline:
                    raise AssertionError(f"embedded Antigravity model {model} was not registered")
                time.sleep(0.1)

            ordinary_role = "You are Hermes, the messenger in a mythology lesson."
            identity, generic_identity = "You are opencode. Keep this.", "You are an AI agent. Keep this."
            cases = [("custom rewrite", source, replacement, "modified", 1),
                     ("unmatched", unmatched, unmatched, "unchanged", 1),
                     ("user only", None, None, "no_eligible_text", 0),
                     ("ordinary role", ordinary_role, ordinary_role, "unchanged", 1),
                     ("built-in identity", identity, generic_identity, "modified", 1)]
            for execution, (name, system, expected, status, count) in enumerate(cases, start=1):
                messages = [{"role": "user", "content": source}]
                if system is not None:
                    messages.insert(0, {"role": "system", "content": system})
                reply = call("/v1/chat/completions", {"model": model, "messages": messages})
                assert reply["choices"][0]["message"]["content"] == "OK"
                path, body = upstream.requests.get(timeout=2)
                assert path.startswith(GENERATION_PATHS), path
                translated = body["request"]
                system_parts = translated.get("systemInstruction", {}).get("parts", [])
                system_text = [part["text"] for part in system_parts if "text" in part]
                user_text = [part["text"] for message in translated["contents"] if message["role"] == "user"
                             for part in message["parts"] if "text" in part]
                assert user_text == [source], "user text changed"
                assert system_text == ([] if expected is None else [expected]), f"unexpected system text for {status}"
                lines = [line for line in log_path.read_text().splitlines() if "[cpa-agy] sanitize request" in line]
                line = lines[-1]
                changed = int(status == "modified")
                fields = dict(field.split("=", 1) for field in line.split() if "=" in field)
                assert fields["status"] == status and fields["checked_text_fields"] == str(count), line
                assert fields["executions"] == str(execution), line
                assert fields["body_modified"] == str(bool(changed)).lower(), line
                assert fields["matched_rules"] == fields["replacements"] == str(changed), line
                private = (source, token, "synthetic-client-key", system, expected)
                assert not any(value in line for value in private if value)
                print(f"PASS: {name}; status={status}; checked_text_fields={count}")
            assert len(lines) == len(cases) and upstream.requests.empty(), "unexpected extra callbacks or upstream requests"
        except urllib.error.HTTPError as exc:
            print(f"HTTP {exc.code}: {exc.read().decode(errors='replace')}", file=sys.stderr)
            print(log_path.read_text(), file=sys.stderr)
            raise
        except Exception:
            print(log_path.read_text(), file=sys.stderr)
            raise
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait()


if __name__ == "__main__":
    binary, library = (pathlib.Path(arg).resolve(strict=True) for arg in sys.argv[1:])
    with tempfile.TemporaryDirectory(prefix="cpa-agy-smoke-") as tmp:
        with http.server.ThreadingHTTPServer(("127.0.0.1", 0), Upstream) as server:
            server.requests = Queue()
            threading.Thread(target=server.serve_forever, daemon=True).start()
            try:
                exercise(pathlib.Path(tmp), binary, library, server)
            finally:
                server.shutdown()
