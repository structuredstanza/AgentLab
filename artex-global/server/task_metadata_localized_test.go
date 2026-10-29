package server

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestUpdateTaskMetadataResponsesLocalized checks that the four input-validation rejections
// of updateTaskMetadata return their real HTTP status. These paths return before
// s.m.UpdateTaskMetadata (DB), so a tasks map with one task is enough.
func TestUpdateTaskMetadataResponsesLocalized(t *testing.T) {
	s := &Server{m: &Manager{tasks: map[string]*Task{"t1": {ID: "t1"}}}}

	call := func(body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(http.MethodPatch, "/api/tasks/t1/metadata", strings.NewReader(body))
		req.SetPathValue("id", "t1")
		rec := httptest.NewRecorder()
		s.updateTaskMetadata(rec, req)
		return rec
	}

	cases := []struct {
		name string
		body string
		code int
	}{
		// A valid JSON body exceeding the 16KB limit. MaxBytesReader returns the over-limit error during the read.
		{"request_too_large", `{"name":"` + strings.Repeat("a", maxTaskMetadataRequestSize+1024) + `"}`, http.StatusRequestEntityTooLarge},
		// If both name and pinned are removed, there are no fields left to modify.
		{"no_fields", `{}`, http.StatusBadRequest},
		{"name_empty", `{"name":"  "}`, http.StatusBadRequest},
		{"name_too_long", `{"name":"` + strings.Repeat("가", maxTaskNameRunes+1) + `"}`, http.StatusBadRequest},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := call(c.body)
			if rec.Code != c.code {
				t.Fatalf("status code = %d, expected = %d (body %q)", rec.Code, c.code, rec.Body.String())
			}
		})
	}
}
