# Install `cpa-agy` on an existing Linux VPS

This runbook is for an operator or agent deploying the `cpa-agy` shared-library plugin into an existing CLIProxyAPI (CPA) service. Do not create a second CPA instance. Do not install or upgrade the host, change credentials or routes, or restart an unidentified service as part of this runbook.

## 1. Identify the deployment

- Determine whether CPA runs under systemd, Docker Compose, or another supervisor. Identify the actual unit or Compose service, the active `config.yaml`, and the plugin directory visible to CPA. Run Compose commands from the existing deployment directory, using its existing project and file options.
- Determine the CPA process architecture. On native Linux, `uname -m` usually maps `x86_64` to `amd64` and `aarch64` to `arm64`. For Docker, verify the running container's architecture; do not assume it matches the VPS if emulation is in use.
- Confirm that the CPA release supports dynamic C ABI plugins and the `request.intercept_after` hook. A Linux host built without cgo cannot load the plugin. If the current host is incompatible or the operator has not authorized a restart, stop and report the blocker; do not replace the host automatically.
- Back up the active config and any existing `cpa-agy.so` before modifying them. Keep the library backup outside the plugin discovery directory. Do not copy or print auth files, API keys, or other credentials.

## 2. Build `cpa-agy.so`

Use the complete source checkout containing `examples/plugin/cpa-agy/go`, not just the plugin subdirectory: the nested Go module uses a local replacement for the CPA SDK. A fresh clone is not enough if the desired plugin changes are untracked or uncommitted; obtain the actual source tree or a trusted prebuilt artifact from the operator. Never use an unaudited download as a native plugin.

Build in an environment matching the CPA process architecture and compatible with its runtime libc. Use Go 1.26.10 or later and a C compiler. From the source repository root, on a matching native Linux builder:

```sh
ARCH=amd64  # change to arm64 when applicable
OUT="$PWD/plugins/linux/$ARCH"
mkdir -p "$OUT"
CGO_ENABLED=1 GOOS=linux GOARCH="$ARCH" \
  go -C ./examples/plugin/cpa-agy/go build -buildmode=c-shared -o "$OUT/cpa-agy.so" .
file "$OUT/cpa-agy.so"
```

Do not use the native command to cross-compile with an ordinary host GCC. Use a matching builder or a properly configured cross-toolchain. For the Debian Bookworm runtime in this repository's Dockerfile, a matching Docker build is:

```sh
ARCH=amd64  # change to arm64 when applicable
OUT="$PWD/plugins/linux/$ARCH"
mkdir -p "$OUT"
docker run --rm --platform "linux/$ARCH" \
  --user "$(id -u):$(id -g)" -e HOME=/tmp -e CGO_ENABLED=1 \
  --mount "type=bind,source=$PWD,target=/src,readonly" \
  --mount "type=bind,source=$OUT,target=/out" \
  -w /src golang:1.26-bookworm \
  go -C ./examples/plugin/cpa-agy/go build -buildmode=c-shared -o /out/cpa-agy.so .
file "$OUT/cpa-agy.so"
```

Use this Docker example only if the host can run that architecture and the builder's libc is compatible with the actual CPA runtime. Install only `cpa-agy.so`; the generated header is not needed. Keep the exact filename because its stem is the plugin ID.

## 3. Install and enable

Copy the library to `<plugins-dir>/linux/<arch>/cpa-agy.so`. Make it readable by the CPA process. For a native installation, one example is `/opt/cli-proxy-api/plugins/linux/amd64/cpa-agy.so`. For repository-style Docker Compose, `${CLI_PROXY_PLUGIN_PATH:-./plugins}` on the VPS is mounted at `/CLIProxyAPI/plugins` inside the container. Install the file under `linux/<arch>/` in that host-side mount source. If there is no plugin mount, add one to the existing Compose service and apply it by recreating that service; a restart alone does not apply mount changes.

Merge this into the active config. Do not create a second `plugins:` key or overwrite other plugin entries. If `plugins.dir` already points to the intended directory, leave it as-is.

```yaml
plugins:
  enabled: true
  dir: /opt/cli-proxy-api/plugins  # Docker example: /CLIProxyAPI/plugins
  configs:
    cpa-agy:
      enabled: true
      priority: 50
```

Omit `rules_file` for the initial deployment unless custom rules are intended. Be aware that `CPA_AGY_RULES_FILE` or an existing `antigravity-sanitize-rules.json` in the CPA process working directory can still supply rules by default. If configuring an explicit rules path, use an absolute path visible inside the CPA process (including inside the container). The plugin does not supply Antigravity credentials or change routing.

## 4. Verify and report

Restart only the identified CPA service after obtaining approval. Examples (replace names with the actual unit or Compose service):

```sh
# systemd
sudo systemctl restart cli-proxy-api
sudo systemctl is-active cli-proxy-api
sudo journalctl -u cli-proxy-api --since '5 minutes ago' --no-pager | grep -Ei 'cpa-agy|pluginhost'

# Docker Compose, when mounts did not change
docker compose restart cli-proxy-api
docker compose ps cli-proxy-api
docker compose logs --since 5m cli-proxy-api | grep -Ei 'cpa-agy|pluginhost'
```

If a Compose mount was added or changed, use `docker compose up -d --no-deps cli-proxy-api` instead of `restart`, following the deployment's existing image and pull policy. Look for a **new** `pluginhost: plugin loaded` entry for `cpa-agy`, check for loader errors, and verify CPA is still healthy using its existing local health check. A running service alone is not proof that the plugin loaded. If loading fails, check the directory from inside the service/container, the file's architecture and libc compatibility, and the host's plugin support before making any further changes.

If the service regresses, restore the backed-up configuration and previous library (or remove the newly installed library if there was none), undo any added mount if necessary, restart/recreate only the affected CPA service, and verify recovery. Report the service name, installed path, architecture, and actual log/health results, without secrets. Do not send a real upstream request unless separately authorized. Successful loading does not verify upstream rate-limit behavior.
