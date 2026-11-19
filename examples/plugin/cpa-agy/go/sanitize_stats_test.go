package main

import (
	"bytes"
	"net/http"
	"strings"
	"testing"

	"github.com/MoeForge/moego/json"
	"github.com/MoeForge/moego/ojson"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginabi"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/pluginapi"
	log "github.com/sirupsen/logrus"
)

func TestSanitizeReplacementCounts(t *testing.T) {
	rules, err := compileRuleSet(&SanitizeRuleConfig{
		Mode: "merge",
		Literals: []LiteralSanitizeRule{
			{Find: "TAG", Replace: new("SAFE")},
			{Find: "NOOP", Replace: new("NOOP")},
		},
		Replacements: []RegexSanitizeRule{{Pattern: `(A)(B)|(CC)`, Replace: new(`${2}${1}${3}`)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	body := []byte(`{"system":"You are opencode. TAG TAG AB CC AB\u200b\u200c NOOP","instructions":"TAG AB CC","messages":[{"role":"user","content":"TAG AB"}]}`)
	var stats sanitizeStats
	out := rules.sanitizeBodyWithStats(body, &stats)
	if want := rules.sanitizeBody(body); !bytes.Equal(out, want) {
		t.Fatalf("counting changed rewrite output: %s, want %s", out, want)
	}
	if got := ojson.GetBytes(out, "system").String(); got != "You are an AI agent. SAFE SAFE BA CC BA NOOP" {
		t.Fatalf("system = %q", got)
	}
	if len(stats.matched) != 4 || stats.replacements != 9 {
		t.Fatalf("matched rules = %d, replacements = %d; want 4, 9", len(stats.matched), stats.replacements)
	}
}

func TestInterceptSanitizeLogsOnlyCounts(t *testing.T) {
	logger := log.StandardLogger()
	originalOutput, originalLevel, originalFormatter := logger.Out, logger.GetLevel(), logger.Formatter
	var output bytes.Buffer
	logger.SetOutput(&output)
	logger.SetLevel(log.InfoLevel)
	logger.SetFormatter(&log.TextFormatter{DisableColors: true, DisableTimestamp: true})
	t.Cleanup(func() {
		logger.SetOutput(originalOutput)
		logger.SetLevel(originalLevel)
		logger.SetFormatter(originalFormatter)
	})

	invoke := func(method, target, body string) []byte {
		t.Helper()
		raw, err := json.Marshal(pluginapi.RequestInterceptRequest{
			ToFormat: target,
			Body:     []byte(body),
			Headers:  http.Header{"Authorization": {"Bearer fake-secret-marker"}},
		})
		if err != nil {
			t.Fatal(err)
		}
		result, err := handleMethod(method, raw)
		if err != nil {
			t.Fatal(err)
		}
		return interceptResultBody(t, result)
	}
	const matched = `{"system":"You are opencode. private-system-marker"}`
	start := sanitizeExecutions.Load()
	invoke(pluginabi.MethodRequestInterceptBefore, "antigravity", matched)
	invoke(pluginabi.MethodRequestInterceptAfter, "openai", matched)
	if output.Len() != 0 || sanitizeExecutions.Load() != start {
		t.Fatalf("skipped requests were counted or logged: %s", output.String())
	}
	cases := []struct {
		body, status, fields string
		modified             bool
	}{
		{matched, "modified", "1", true},
		{`{"system":"private-unmatched-marker","instructions":[{"text":"private-unmatched-part"},{"text":""}]}`, "unchanged", "2", false},
		{`{"messages":[{"role":"user","content":"You are opencode. private-user-marker"}]}`, "no_eligible_text", "0", false},
		{"", "empty_body", "0", false},
		{`{"system":"private-invalid-marker"`, "invalid_json", "0", false},
	}
	for _, tc := range cases {
		if got := invoke(pluginabi.MethodRequestInterceptAfter, "antigravity", tc.body); (len(got) > 0) != tc.modified {
			t.Errorf("status %s: returned a body = %t, want %t", tc.status, len(got) > 0, tc.modified)
		}
	}
	lines := strings.Split(strings.TrimSpace(output.String()), "\n")
	if len(lines) != len(cases) || sanitizeExecutions.Load() != start+uint64(len(cases)) {
		t.Fatalf("expected %d execution logs, got: %s", len(cases), output.String())
	}
	for i, line := range lines {
		tc := cases[i]
		matchedFields := []string{"body_modified=false", "matched_rules=0", "replacements=0"}
		if tc.modified {
			matchedFields = []string{"body_modified=true", "matched_rules=1", "replacements=1"}
		}
		for _, field := range append(matchedFields, "[cpa-agy] sanitize request", "status="+tc.status, "checked_text_fields="+tc.fields+" ") {
			if !strings.Contains(line, field) {
				t.Errorf("log missing %q: %s", field, line)
			}
		}
		if strings.Contains(line, "private-") || strings.Contains(line, "fake-secret-marker") || strings.Contains(line, "Authorization") {
			t.Errorf("request data leaked in log: %s", line)
		}
		t.Log(line)
	}
}
