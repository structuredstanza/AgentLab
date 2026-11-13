package server

import "testing"

// TestValidateTrigger directly calls the pure function validateTrigger to check that missing-condition and no-tool-
// selected paths return English message constants and valid input returns an empty string. This return value is
// pgCreateTrigger and pgUpdateTrigger expose the msg directly to the user via writeErr(400, msg).
func TestValidateTrigger(t *testing.T) {
	if msg := validateTrigger(&triggerReq{}); msg != errTriggerNoCondition {
		t.Fatalf("missing-condition message = %q, expected = %q", msg, errTriggerNoCondition)
	}
	if msg := validateTrigger(&triggerReq{OnToolCall: true}); msg != errTriggerToolSetEmpty {
		t.Fatalf("no-tool-selected message = %q, expected = %q", msg, errTriggerToolSetEmpty)
	}
	if msg := validateTrigger(&triggerReq{OnFinding: true}); msg != "" {
		t.Fatalf("valid-input message = %q, expected = empty string", msg)
	}
	if msg := validateTrigger(&triggerReq{OnToolCall: true, ToolNames: []string{"nmap"}}); msg != "" {
		t.Fatalf("valid tool-call message = %q, expected = empty string", msg)
	}
}
