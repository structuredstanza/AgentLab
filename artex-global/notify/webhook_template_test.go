package notify

import (
	"context"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// This file locks down the **capability boundary** of the generic Webhook template.
//
// This is the one place in the whole package where a user-supplied string is evaluated as code, so it should be explicit about what it can do,
// what it cannot do, and pin those properties down with tests. Otherwise, if someone later adds a method to the template context,
// or a readFile to the FuncMap, the capability surface grows silently, and the diff looks like
// nothing more than a harmless little helper.

// TestTemplateContextHasNoMethods is the most important of these.
//
// text/template calls exported methods ({{.Foo}} can access either a field or a method). So if the template context
// can reach **any** type that has exported methods, those methods are effectively exposed to the template author.
// The context of this feature is deliberately pure data (exported fields only, zero methods).
//
// If this fails, it means someone added a method to webhookTemplateData / webhookItem.
// Before deciding to allow it, first think through whether that method could be used by a template to read something that should not be exposed.
func TestTemplateContextHasNoMethods(t *testing.T) {
	for _, v := range []any{webhookTemplateData{}, webhookItem{}} {
		typ := reflect.TypeOf(v)
		if n := typ.NumMethod(); n != 0 {
			var names []string
			for i := 0; i < n; i++ {
				names = append(names, typ.Method(i).Name)
			}
			t.Fatalf("%s exposes %d methods (%s): text/template can call them, "+
				"which hands the capabilities of these methods to template authors", typ.Name(), n, strings.Join(names, ", "))
		}
	}
}

// TestTemplateFuncsAreMinimal locks down the set of functions exposed to templates.
//
// Every additional function in the FuncMap adds one more capability. Currently there are only json / jsons, whose job is to serialize values
// into JSON fragments. They cannot read files, send requests, or execute commands.
func TestTemplateFuncsAreMinimal(t *testing.T) {
	var got []string
	for name := range webhookTemplateFuncs {
		got = append(got, name)
	}
	sort.Strings(got)
	want := []string{"json", "jsons"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("template function set changed: got %v, want %v. Before adding a function, confirm it does not expand the capability surface "+
			"(no reading or writing files, no network requests, no command execution)", got, want)
	}
}

// TestTemplateCannotReachUnknownData covers out-of-bounds access in templates:
// accessing something that does not exist must fail rather than echo back some value, and the failure message must not leak internal data.
func TestTemplateCannotReachUnknownData(t *testing.T) {
	_, err := renderWebhookBody(`{"x": {{.Environment}}, "y": {{.Env}}}`, singleMsg())
	if err == nil {
		t.Fatal("accessing a nonexistent field should fail")
	}
	// Error messages must not contain the actual content from the template context (vulnerability titles/summaries).
	for _, leak := range []string{"SQL注入", "参数 id"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("template error leaked message content %q: %v", leak, err)
		}
	}
}

// TestTemplateRenderFailsPermanently: a broken template is a configuration error, so retrying will not fix it.
// If it were classified as retryable, a single bad template would make every delivery waste three rounds of backoff.
func TestTemplateRenderFailsPermanently(t *testing.T) {
	cfg := map[string]any{
		"url":           "https://example.com/hook",
		"body_template": `{{.Items.`,
	}
	if err := (webhookChannel{}).Validate(cfg); err == nil {
		t.Fatal("template syntax error should be caught at save time")
	}
	// Even if validation is bypassed and delivery goes ahead directly, it must be treated as a permanent failure rather than retried repeatedly.
	_, err := (webhookChannel{}).Send(context.Background(), cfg, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("bad template should fail permanently, got %v", err)
	}
}

// TestTemplateCanOnlyProduceJSON covers the constraint that "the template rendering result must be valid JSON".
// It also incidentally blocks uses that generate plain text from a template to trigger other protocols.
func TestTemplateCanOnlyProduceJSON(t *testing.T) {
	// Valid templates pass.
	ok := map[string]any{"url": "https://example.com/hook", "body_template": `{"t":{{json .Title}}}`}
	if err := (webhookChannel{}).Validate(ok); err != nil {
		t.Fatalf("valid template should pass validation: %v", err)
	}
	// When the rendered output is not JSON, it must be rejected (rather than sent as-is).
	bad := map[string]any{"url": "http://127.0.0.1:1/hook", "body_template": `not json {{.Count}}`}
	_, err := (webhookChannel{}).Send(context.Background(), bad, singleMsg())
	if err == nil || !IsPermanent(err) {
		t.Fatalf("rendering non-JSON should fail permanently, got %v", err)
	}
	if !strings.Contains(err.Error(), "not valid JSON") {
		t.Errorf("error message should say it is a JSON problem, got %v", err)
	}
}
