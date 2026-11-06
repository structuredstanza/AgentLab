package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// intent_intervention.go handler tests: Worker intervention error responses checked over HTTP.

// TestSendWorkerMessageInputValidationLocalized checks the four input-validation paths return the expected status.
func TestSendWorkerMessageInputValidationLocalized(t *testing.T) {
	s := &Server{m: &Manager{tasks: map[string]*Task{"t1": {ID: "t1"}}}}

	call := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPost, "/api/tasks/t1/intents/1/message", strings.NewReader(body))
		req.SetPathValue("id", "t1")
		req.SetPathValue("iid", "1")
		rec := httptest.NewRecorder()
		s.sendWorkerMessage(rec, req)
		return rec
	}

	cases := []struct {
		name string
		body string
		code int
	}{
		// A valid JSON body exceeding the 64KB limit. MaxBytesReader returns the over-limit error mid-read.
		{"request_too_large", `{"message":"` + strings.Repeat("a", maxWorkerMessageBytes+1024) + `"}`, http.StatusRequestEntityTooLarge},
		{"message_empty", `{"message":"  "}`, http.StatusBadRequest},
		{"message_too_long", `{"message":"` + strings.Repeat("a", 4001) + `"}`, http.StatusBadRequest},
		{"bad_request_id", `{"message":"hello","request_id":"contains whitespace"}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := call(c.body)
			if rec.Code != c.code {
				t.Fatalf("status code = %d, want %d (body %q)", rec.Code, c.code, rec.Body.String())
			}
		})
	}
}
