package useragent

import (
	"os"
	"sync"
	"testing"
)

// The identity must come from the engagement, not from a compiled-in product
// name, or two engagements on the same box look identical to a target.
func TestGetReadsTheEngagementIdentity(t *testing.T) {
	Set("")
	value = ""
	once = sync.Once{}
	t.Setenv("ARTEX_USER_AGENT", "Mozilla/5.0 (X11; Linux x86_64) TestIdentity/1.0")
	if got := Get(); got != "Mozilla/5.0 (X11; Linux x86_64) TestIdentity/1.0" {
		t.Fatalf("Get() = %q, want the environment identity", got)
	}
}

// An unconfigured build must still not announce its language. This is the
// regression that matters: Go-http-client/1.1 is the default, and every request
// that omits the header sends it.
func TestGetNeverReturnsTheLanguageDefault(t *testing.T) {
	Set("")
	value = ""
	once = sync.Once{}
	os.Unsetenv("ARTEX_USER_AGENT")
	t.Setenv("ARTEX_USER_AGENT", "")
	got := Get()
	if got == "" || got == "Go-http-client/1.1" {
		t.Fatalf("Get() = %q, want a browser identity", got)
	}
}

// A caller that deliberately sets its own User-Agent keeps it.
func TestSetIfAbsentRespectsACallerChoice(t *testing.T) {
	set := map[string]string{}
	SetIfAbsent(func(k, v string) { set[k] = v }, "already-chosen/1.0")
	if set["User-Agent"] != "" {
		t.Fatalf("overwrote a deliberate User-Agent with %q", set["User-Agent"])
	}
	SetIfAbsent(func(k, v string) { set[k] = v }, "")
	if set["User-Agent"] != Get() {
		t.Fatalf("did not fill an absent User-Agent: %q", set["User-Agent"])
	}
}
