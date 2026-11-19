package main

import (
	"bytes"
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/MoeForge/moego/json"
	"github.com/MoeForge/moego/ojson"
	"github.com/MoeForge/moego/regexp"
	log "github.com/sirupsen/logrus"
)

const (
	defaultSanitizeRulesFile = "antigravity-sanitize-rules.json"
	sanitizeRulesFileEnv     = "CPA_AGY_RULES_FILE"
	rulesReloadInterval      = 5 * time.Second
)

type SanitizeRuleConfig struct {
	Mode            string                `json:"mode,omitempty"`
	IdentityOpeners []string              `json:"identity_openers,omitempty"`
	Literals        []LiteralSanitizeRule `json:"literals,omitempty"`
	Replacements    []RegexSanitizeRule   `json:"replacements,omitempty"`
}

type LiteralSanitizeRule struct {
	Name    string  `json:"name,omitempty"`
	Find    string  `json:"find"`
	Replace *string `json:"replace"`
}

type RegexSanitizeRule struct {
	Name    string  `json:"name,omitempty"`
	Pattern string  `json:"pattern"`
	Replace *string `json:"replace"`
}

type compiledLiteralRule struct {
	find    string
	replace string
}

type compiledRegexRule struct {
	re      *regexp.Regexp
	replace string
}

type compiledSanitizeRules struct {
	stripInvisible bool
	openers        []*regexp.Regexp
	literals       []compiledLiteralRule
	replacements   []compiledRegexRule
}

func builtInIdentityRule(identity, suffix string) RegexSanitizeRule {
	// Consume and restore the boundary: a period followed by whitespace or end,
	// or the end of the line with no period. A comma alone is not a boundary.
	return RegexSanitizeRule{
		Pattern: `(?im)^([ \t]*)You[ \t]+are[ \t]+(?:` + identity + `)(` + suffix + `)(?:\.([ \t\r\n]|$)|([ \t]*\r?$))`,
		Replace: new(`${1}You are an AI agent${2}.${3}${4}`),
	}
}

var defaultIdentityRules = []RegexSanitizeRule{
	builtInIdentityRule(`opencode`, `(?:,[ \t]+an interactive CLI tool(?: that helps users with software engineering tasks)?)?`),
	builtInIdentityRule(`Claude[ \t]+Code(?:,[ \t]*Anthropic'?s[ \t]+official[ \t]+CLI[ \t]+for[ \t]+Claude)?(?:,[ \t]*running[ \t]+within[ \t]+the[ \t]+Claude[ \t]+Agent[ \t]+SDK)?`, ""),
	builtInIdentityRule(`(?:an?[ \t]+)?(?:AI[ \t]+)?(?:coding[ \t]+)?(?:agent|assistant)[ \t]+powered[ \t]+by[ \t]+DeepSeek[ \t]+Harness(?:[ \t]+v?[0-9]+(?:\.[0-9]+)*(?:-[a-z0-9-]+)?)?`, ""),
	builtInIdentityRule(`(?:an?[ \t]+)?(?:expert[ \t]+)?coding[ \t]+(?:assistant|agent)[ \t]+(?:running|operating|working)[ \t]+inside[ \t]+pi(?:,?[ \t]+a[ \t]+coding[ \t]+agent[ \t]+harness)?`, ""),
	builtInIdentityRule(`pi`, ""),
	builtInIdentityRule(`(?:an?[ \t]+)?(?:coding[ \t]+)?(?:agent|assistant)[ \t]+running[ \t]+in[ \t]+the[ \t]+Codex[ \t]+CLI`, ""),
	builtInIdentityRule(`Hermes(?:[ \t]+Agent)?(?:,[ \t]*(?:built[ \t]+by|an[ \t]+intelligent[ \t]+AI[ \t]+assistant[ \t]+(?:created|built)[ \t]+by)[ \t]+Nous[ \t]+Research)?`, ""),
	builtInIdentityRule(`ZCode`, ""),
	builtInIdentityRule(`a Claude agent, built on Anthropic'?s Claude Agent SDK`, ""),
	builtInIdentityRule(`Codex,? (?:a coding agent |an agent )?based on GPT-[0-9]+(?:\.[0-9]+)*(?:-[a-z0-9]+)*`, ""),
	builtInIdentityRule(`GPT-[0-9]+(?:\.[0-9]+)*(?:-[a-z0-9]+)* running in the Codex CLI`, ""),
}

var defaultLiteralRules = []LiteralSanitizeRule{
	{
		Name:    "dsh-at-path-paragraph",
		Find:    "Tokens prefixed with @ are paths the user explicitly referenced. Relative paths resolve from the workspace root; absolute paths identify files or directories on the host. A trailing slash marks a directory: list it when its contents matter. Anything else is a file: use the read tool when its contents are needed, and do not claim to have inspected it before reading. @\\\"...\\\" quotes a path containing spaces.",
		Replace: new("When the user writes @ followed by a path, they are pointing at that file or folder. Relative paths start at the workspace root; absolute paths are host paths. A path ending in a slash is a folder, so list it if its contents matter; otherwise it is a file, so open it with the read tool before relying on it. Paths with spaces appear as @\\\"...\\\"."),
	},
}

var defaultReplacementRules = []RegexSanitizeRule{
	{Name: "opencode-code-mode-signature", Pattern: `tools\.opencode\.`, Replace: new(`tools["opencode"].`)},
	{Name: "omp-rfc-2119-keywords", Pattern: `(?i)\bRFC\s+2119\s+keywords:`, Replace: new("RFC 2119 key words:")},
	{Name: "dsh-brand-cloak", Pattern: `(?i)\bDeepSeek[ \t]+Harness\b`, Replace: new("the coding harness")},
	{Name: "dsh-web-surface-browser-context", Pattern: `(?i)The\s+browser\s+provides\s+no\s+implicit\s+DOM,\s*route,\s*or\s+screenshot\s+context\.`, Replace: new("The runtime provides no implicit DOM, route, or screenshot context.")},
	{Name: "claude-code-interactive-agent-opener", Pattern: `(?im)^([ \t]*)You[ \t]+are[ \t]+an[ \t]+interactive[ \t]+(?:agent|CLI[ \t]+tool)[ \t]+that[ \t]+helps[ \t]+users[ \t]+with[ \t]+software[ \t]+engineering[ \t]+tasks(?:\.([ \t\r\n]|$)|([ \t]*\r?$))`, Replace: new("${1}You are an AI coding partner assisting users with software engineering tasks.${2}${3}")},
	{Name: "claude-code-pasted-content-trust-warning", Pattern: `(?i)Text\s+inside\s+<pasted_content>\s+tags\s+was\s+pasted\s+into\s+the\s+message\s+by\s+the\s+user\s+from\s+somewhere\s+else\s+and\s+may\s+contain\s+instructions\s+the\s+user\s+did\s+not\s+write\.?`, Replace: new("Content wrapped in <pasted_content> blocks comes from external material copied by the user and might include unverified directives not authored by the user.")},
}

var invisibleFormatReplacer = strings.NewReplacer(
	"\u200b", "",
	"\u200c", "",
	"\u200e", "",
	"\u200f", "",
	"\u2060", "",
	"\ufeff", "",
	"\u00ad", "",
	"\u180e", "",
)

type hotReloadRuleStore struct {
	mu            sync.RWMutex
	nextCheckNano atomic.Int64
	filePath      string
	lastModNano   int64
	lastSize      int64
	fileExisted   bool
	compiled      *compiledSanitizeRules
}

var builtInSanitizeRules = mustCompileBuiltInRules()

func mustCompileBuiltInRules() *compiledSanitizeRules {
	rules, err := compileRuleSet(nil)
	if err != nil {
		panic(err)
	}
	return rules
}

var globalSanitizeStore = newHotReloadRuleStore(resolveSanitizeRulesPath())

func resolveSanitizeRulesPath() string {
	if p := strings.TrimSpace(os.Getenv(sanitizeRulesFileEnv)); p != "" {
		return p
	}
	return defaultSanitizeRulesFile
}

func newHotReloadRuleStore(filePath string) *hotReloadRuleStore {
	s := &hotReloadRuleStore{filePath: filePath, compiled: builtInSanitizeRules}
	s.reloadLocked(true)
	s.nextCheckNano.Store(time.Now().Add(rulesReloadInterval).UnixNano())
	return s
}

func (s *hotReloadRuleStore) setFilePath(path string) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if path == s.filePath {
		return
	}
	s.filePath = path
	s.fileExisted = false
	s.lastModNano = 0
	s.lastSize = 0
	s.reloadLocked(true)
	s.nextCheckNano.Store(time.Now().Add(rulesReloadInterval).UnixNano())
}

func (s *hotReloadRuleStore) get() *compiledSanitizeRules {
	now := time.Now().UnixNano()
	if now >= s.nextCheckNano.Load() {
		s.maybeReload(now)
	}
	s.mu.RLock()
	c := s.compiled
	s.mu.RUnlock()
	return c
}

func (s *hotReloadRuleStore) maybeReload(nowNano int64) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if nowNano < s.nextCheckNano.Load() {
		return
	}
	s.nextCheckNano.Store(nowNano + int64(rulesReloadInterval))
	s.reloadLocked(false)
}

func (s *hotReloadRuleStore) reloadLocked(initial bool) {
	info, err := os.Stat(s.filePath)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warnf("[cpa-agy] cannot stat %s (keeping previous rules): %v", s.filePath, err)
			return
		}
		if initial || s.compiled != builtInSanitizeRules {
			s.fileExisted = false
			s.lastModNano = 0
			s.lastSize = 0
			s.compiled = builtInSanitizeRules
			if !initial {
				log.Warnf("[cpa-agy] external rule file %s removed; reverted to built-in defaults", s.filePath)
			}
		}
		return
	}
	modNano := info.ModTime().UnixNano()
	size := info.Size()
	if !initial && s.fileExisted && modNano == s.lastModNano && size == s.lastSize {
		return
	}
	raw, readErr := os.ReadFile(s.filePath)
	if readErr != nil {
		log.Warnf("[cpa-agy] failed reading %s (keeping previous rules): %v", s.filePath, readErr)
		return
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var cfg *SanitizeRuleConfig
	if errDecode := decoder.Decode(&cfg); errDecode != nil {
		log.Warnf("[cpa-agy] invalid rule file %s (keeping previous rules): %v", s.filePath, errDecode)
		return
	}
	if errDecode := decoder.Decode(new(json.RawMessage)); errDecode != io.EOF {
		log.Warnf("[cpa-agy] trailing data in rule file %s (keeping previous rules)", s.filePath)
		return
	}
	if cfg == nil {
		log.Warnf("[cpa-agy] expected a rule object in %s (keeping previous rules)", s.filePath)
		return
	}
	compiled, errCompile := compileRuleSet(cfg)
	if errCompile != nil {
		log.Warnf("[cpa-agy] invalid rules in %s (keeping previous rules): %v", s.filePath, errCompile)
		return
	}
	s.fileExisted = true
	s.lastModNano = modNano
	s.lastSize = size
	s.compiled = compiled
	log.Infof("[cpa-agy] loaded %s (mode=%s, openers=%d, literals=%d, replacements=%d)",
		s.filePath, effectiveMode(cfg.Mode), len(s.compiled.openers), len(s.compiled.literals), len(s.compiled.replacements))
}

func effectiveMode(mode string) string {
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		return "merge"
	}
	return mode
}

func compileRuleSet(cfg *SanitizeRuleConfig) (*compiledSanitizeRules, error) {
	mode := "merge"
	if cfg != nil {
		mode = effectiveMode(cfg.Mode)
		if mode != "merge" && mode != "replace" {
			return nil, fmt.Errorf("unknown rule mode %q", cfg.Mode)
		}
	}
	replaceAll := mode == "replace"
	var openerSources []string
	var literalSources []LiteralSanitizeRule
	var regexSources []RegexSanitizeRule
	if !replaceAll {
		literalSources = append(literalSources, defaultLiteralRules...)
		regexSources = append(regexSources, defaultIdentityRules...)
		regexSources = append(regexSources, defaultReplacementRules...)
	}
	if cfg != nil {
		openerSources = append(openerSources, cfg.IdentityOpeners...)
		literalSources = append(literalSources, cfg.Literals...)
		regexSources = append(regexSources, cfg.Replacements...)
	}
	out := &compiledSanitizeRules{stripInvisible: !replaceAll}
	for i, pat := range openerSources {
		if strings.TrimSpace(pat) == "" {
			return nil, fmt.Errorf("identity opener %d has an empty pattern", i+1)
		}
		re, err := regexp.Compile(pat)
		if err != nil {
			return nil, fmt.Errorf("invalid identity opener %d: %w", i+1, err)
		}
		out.openers = append(out.openers, re)
	}
	for i, lit := range literalSources {
		if lit.Find == "" {
			return nil, fmt.Errorf("literal rule %d (%q) has an empty find value", i+1, lit.Name)
		}
		if lit.Replace == nil {
			return nil, fmt.Errorf("literal rule %d (%q) requires a replace string", i+1, lit.Name)
		}
		out.literals = append(out.literals, compiledLiteralRule{find: lit.Find, replace: *lit.Replace})
	}
	for i, r := range regexSources {
		if strings.TrimSpace(r.Pattern) == "" {
			return nil, fmt.Errorf("replacement rule %d (%q) has an empty pattern", i+1, r.Name)
		}
		if r.Replace == nil {
			return nil, fmt.Errorf("replacement rule %d (%q) requires a replace string", i+1, r.Name)
		}
		re, err := regexp.Compile(r.Pattern)
		if err != nil {
			return nil, fmt.Errorf("invalid replacement rule %d (%q): %w", i+1, r.Name, err)
		}
		out.replacements = append(out.replacements, compiledRegexRule{re: re, replace: *r.Replace})
	}
	return out, nil
}

func ApplyCustomSanitizeRules(text string) string {
	if text == "" {
		return ""
	}
	return applyCompiledSanitizeRules(text, globalSanitizeStore.get())
}

type sanitizeStats struct {
	matched           map[int]struct{}
	replacements      int
	checkedTextFields int
	skipReason        string
}

func (s *sanitizeStats) record(ruleID, count int) {
	if s == nil || count == 0 {
		return
	}
	if s.matched == nil {
		s.matched = make(map[int]struct{})
	}
	s.matched[ruleID] = struct{}{}
	s.replacements += count
}

func applyCompiledSanitizeRules(text string, rules *compiledSanitizeRules) string {
	return sanitizeText(text, rules, nil)
}

func sanitizeText(text string, rules *compiledSanitizeRules, stats *sanitizeStats) string {
	if text == "" || rules == nil {
		return text
	}
	if stats != nil {
		stats.checkedTextFields++
	}
	const invisibleChars = "\u200b\u200c\u200e\u200f\u2060\ufeff\u00ad\u180e"
	if rules.stripInvisible && strings.ContainsAny(text, invisibleChars) {
		if stats != nil {
			count := 0
			for _, ch := range text {
				if strings.ContainsRune(invisibleChars, ch) {
					count++
				}
			}
			stats.record(-1, count)
		}
		text = invisibleFormatReplacer.Replace(text)
	}
	if updated, index := applyIdentityOpeners(text, rules.openers); updated != text {
		stats.record(index, 1)
		text = updated
	}
	literalBase := len(rules.openers)
	for i, lit := range rules.literals {
		if lit.find != lit.replace && strings.Contains(text, lit.find) {
			if stats != nil {
				stats.record(literalBase+i, strings.Count(text, lit.find))
			}
			text = strings.ReplaceAll(text, lit.find, lit.replace)
		}
	}
	regexBase := literalBase + len(rules.literals)
	for i, rule := range rules.replacements {
		updated := rule.re.ReplaceAllString(text, rule.replace)
		if stats != nil && updated != text {
			count := 0
			var expanded []byte
			for _, match := range rule.re.FindAllStringSubmatchIndex(text, -1) {
				expanded = rule.re.ExpandString(expanded[:0], rule.replace, text, match)
				if string(expanded) != text[match[0]:match[1]] {
					count++
				}
			}
			stats.record(regexBase+i, count)
		}
		text = updated
	}
	return text
}

func applyIdentityOpeners(text string, openers []*regexp.Regexp) (string, int) {
	for i, re := range openers {
		loc := re.FindStringIndex(text)
		if loc == nil || loc[0] != 0 || loc[1] == 0 {
			continue
		}
		matched := text[loc[0]:loc[1]]
		rest := text[loc[1]:]
		if strings.HasPrefix(rest, ",") {
			return "You are an AI agent" + rest, i
		}
		if rest == "" || strings.HasPrefix(rest, "\n") || strings.HasPrefix(rest, "\r") {
			return "You are an AI agent." + rest, i
		}
		if strings.HasSuffix(matched, ".") && (strings.HasPrefix(rest, " ") || strings.HasPrefix(rest, "\t")) {
			return "You are an AI agent." + rest, i
		}
	}
	return text, -1
}

func sanitizeRequestBody(body []byte) []byte {
	return sanitizeRequestBodyWithStats(body, nil)
}

func sanitizeRequestBodyWithStats(body []byte, stats *sanitizeStats) []byte {
	if len(body) == 0 {
		if stats != nil {
			stats.skipReason = "empty_body"
		}
		return body
	}
	if !ojson.ValidBytes(body) {
		if stats != nil {
			stats.skipReason = "invalid_json"
		}
		return body
	}
	return globalSanitizeStore.get().sanitizeBodyWithStats(body, stats)
}

func (rules *compiledSanitizeRules) sanitizeBody(body []byte) []byte {
	return rules.sanitizeBodyWithStats(body, nil)
}

type requestSanitizer struct {
	rules *compiledSanitizeRules
	stats *sanitizeStats
}

func (rules *compiledSanitizeRules) sanitizeBodyWithStats(body []byte, stats *sanitizeStats) []byte {
	s := requestSanitizer{rules: rules, stats: stats}
	doc := ojson.NewDoc(body)
	changed := false
	for _, path := range []string{
		"system",
		"instructions",
		"systemInstruction",
		"system_instruction",
		"request.systemInstruction",
		"request.system_instruction",
	} {
		if s.sanitizeJSONValue(doc, path) {
			changed = true
		}
	}
	for _, path := range []string{"messages", "input", "request.contents", "contents"} {
		if s.sanitizeMessages(doc, path) {
			changed = true
		}
	}
	if !changed {
		return body
	}
	return doc.Bytes()
}

func (s requestSanitizer) sanitizeJSONValue(doc *ojson.Doc, path string) bool {
	if doc == nil {
		return false
	}
	node := doc.Get(path)
	if !node.Exists() {
		return false
	}
	switch {
	case node.Type == ojson.String:
		updated := sanitizeText(node.String(), s.rules, s.stats)
		if updated == node.String() {
			return false
		}
		return doc.Set(path, updated) == nil
	case node.IsArray():
		changed := false
		items := node.Array()
		for i := range items {
			itemPath := path + "." + itoa(i)
			if items[i].Type == ojson.String {
				updated := sanitizeText(items[i].String(), s.rules, s.stats)
				if updated != items[i].String() && doc.Set(itemPath, updated) == nil {
					changed = true
				}
				continue
			}
			if s.sanitizeTextNode(doc, itemPath+".text") {
				changed = true
			}
			if s.sanitizeParts(doc, itemPath+".parts") {
				changed = true
			}
		}
		return changed
	case node.IsObject():
		changed := s.sanitizeTextNode(doc, path+".text")
		if s.sanitizeParts(doc, path+".parts") {
			changed = true
		}
		return changed
	default:
		return false
	}
}

func (s requestSanitizer) sanitizeMessages(doc *ojson.Doc, path string) bool {
	node := doc.Get(path)
	if !node.IsArray() {
		return false
	}
	changed := false
	items := node.Array()
	for i := range items {
		role := strings.ToLower(items[i].Get("role").String())
		if role != "system" && role != "developer" {
			continue
		}
		itemPath := path + "." + itoa(i)
		if s.sanitizeJSONValue(doc, itemPath+".content") {
			changed = true
		}
		if s.sanitizeParts(doc, itemPath+".parts") {
			changed = true
		}
	}
	return changed
}

func (s requestSanitizer) sanitizeParts(doc *ojson.Doc, path string) bool {
	node := doc.Get(path)
	if !node.IsArray() {
		return false
	}
	changed := false
	items := node.Array()
	for i := range items {
		if s.sanitizeTextNode(doc, path+"."+itoa(i)+".text") {
			changed = true
		}
	}
	return changed
}

func (s requestSanitizer) sanitizeTextNode(doc *ojson.Doc, path string) bool {
	node := doc.Get(path)
	if node.Type != ojson.String {
		return false
	}
	updated := sanitizeText(node.String(), s.rules, s.stats)
	if updated == node.String() {
		return false
	}
	return doc.Set(path, updated) == nil
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b [20]byte
	pos := len(b)
	for i > 0 {
		pos--
		b[pos] = byte('0' + i%10)
		i /= 10
	}
	return string(b[pos:])
}
