package notify

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"text/template"
	"time"
)

// webhookChannel is the generic Webhook adapter: users define the URL, method, request headers, and JSON template.
// Its existence means this feature does not need a separate implementation for Slack, Mattermost, Discord, or self-hosted systems each.
// Those platforms can all be covered by one configurable template.
type webhookChannel struct{}

func (webhookChannel) Kind() string { return KindWebhook }

// The generic Webhook has no official rate limit, so returning 0 means no rate limiting by default; the user sets it according to what the receiving end can handle.
func (webhookChannel) DefaultRatePerMin() int { return 0 }

// Masking url and headers: the target address itself often carries a token, and custom headers usually hold auth credentials,
// both of which would appear in the API echo, so both must be blocked.
// The trade-off is that editing one header means re-entering the whole header set (a masked value is interpreted as "keep the original value") ——
// this trade-off is deliberate: it is better to ask the user to re-enter values than to echo credentials back to the browser.
func (webhookChannel) SecretKeys() []string { return []string{"url", "headers"} }

// The destination is url. When url changes, headers must be restated explicitly — otherwise the original Authorization header
// would be sent unchanged to the new address, which is the main path for bypassing the masking.
func (webhookChannel) DestinationKeys() []string { return []string{"url"} }

// webhookDefaultTemplate is the fallback request body used when no template is set: a plain JSON structure,
// covering the vast majority of self-hosted receivers that simply accept one JSON payload and store it.
const webhookDefaultTemplate = `{
  "title": {{json .Title}},
  "batch": {{.Batch}},
  "count": {{.Count}},
  "items": [
{{- range $i, $it := .Items}}
{{- if $i}},{{end}}
    {
      "finding_id": {{$it.FindingID}},
      "name": {{json $it.Name}},
      "vulnclass": {{json $it.VulnClass}},
      "severity": {{json $it.Severity}},
      "summary": {{json $it.Summary}},
      "assets": {{json $it.Assets}},
      "detail_url": {{json $it.DetailURL}}
    }
{{- end}}
  ]
}`

// webhookTemplateData is the context exposed to user-defined templates.
type webhookTemplateData struct {
	Title   string
	Batch   bool
	Count   int
	Items   []webhookItem
	HomeURL string
	// SentAt is the delivery time of this request (RFC3339), for the receiver to record.
	SentAt string
}

type webhookItem struct {
	FindingID     int64
	Name          string
	VulnClass     string
	Severity      string
	SeverityLabel string
	Summary       string
	Assets        []string
	DetailURL     string
	FromStatus    string
	ToStatus      string
	// StatusLabel is a human-readable description of a status change, such as "Pending → Fixed"; it is empty when the change is not a status change.
	StatusLabel string
}

func (webhookChannel) Validate(cfg map[string]any) error {
	raw := cfgString(cfg, "url")
	if raw == "" {
		return errors.New("target URL is missing")
	}
	if err := validateHTTPURL(raw); err != nil {
		return fmt.Errorf("target URL is invalid: %w", err)
	}
	if m := strings.ToUpper(cfgString(cfg, "method")); m != "" && m != http.MethodGet && m != http.MethodPost && m != http.MethodPut && m != http.MethodPatch {
		return fmt.Errorf("unsupported method: %s (choose from GET/POST/PUT/PATCH)", m)
	}
	if tpl := cfgString(cfg, "body_template"); tpl != "" {
		if _, err := parseWebhookTemplate(tpl); err != nil {
			return fmt.Errorf("request body template syntax is invalid: %w", err)
		}
	}
	return nil
}

func (c webhookChannel) Send(ctx context.Context, cfg map[string]any, m Message) (int, error) {
	if err := c.Validate(cfg); err != nil {
		return 0, Permanent(err)
	}
	method := strings.ToUpper(cfgString(cfg, "method"))
	if method == "" {
		method = http.MethodPost
	}

	// GET carries no request body: stuffing the content into the query string is beyond what the template can do and does not fit GET semantics,
	// so GET is only suitable for receivers that just trigger a hook when hit.
	var payload any
	if method != http.MethodGet {
		body, err := renderWebhookBody(cfgString(cfg, "body_template"), m)
		if err != nil {
			return 0, Permanent(err)
		}
		// The template renders a JSON string, which is converted to json.RawMessage here and sent as-is,
		// Avoid double escaping, which would wrap the user's carefully crafted structure inside a JSON string.
		if !json.Valid([]byte(body)) {
			return 0, Permanent(errors.New("the rendered request body template is not valid JSON"))
		}
		payload = json.RawMessage(body)
	}

	headers := cfgMap(cfg, "headers")
	if ct := cfgString(cfg, "content_type"); ct != "" {
		// Overriding is allowed, but it is applied after headers so that explicit configuration takes precedence.
		if headers == nil {
			headers = map[string]string{}
		}
		headers["Content-Type"] = ct
	}
	if _, err := doJSON(ctx, method, cfgString(cfg, "url"), headers, payload); err != nil {
		return 0, err
	}
	// The generic Webhook does not truncate the body (the receiver is the user's own service, and its size is determined by body_template),
	// so the entire batch is counted as delivered.
	return len(m.Items), nil
}

// renderWebhookBody renders the request body using the user's template (or the default template).
func renderWebhookBody(tpl string, m Message) (string, error) {
	if strings.TrimSpace(tpl) == "" {
		tpl = webhookDefaultTemplate
	}
	t, err := parseWebhookTemplate(tpl)
	if err != nil {
		return "", fmt.Errorf("request body template syntax is invalid: %w", err)
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, newWebhookTemplateData(m)); err != nil {
		return "", fmt.Errorf("failed to render request body template: %w", err)
	}
	return buf.String(), nil
}

// parseWebhookTemplate parses the template.
//
// missingkey=zero makes missing map keys render as zero values instead of raising an error. However, the context in this file is a struct,
// Its main purpose is to keep range from failing when .Items is empty. What actually needs guarding against is .Items being nil.
func parseWebhookTemplate(tpl string) (*template.Template, error) {
	return template.New("body").Funcs(webhookTemplateFuncs).Option("missingkey=zero").Parse(tpl)
}

// webhookTemplateFuncs are the helper functions exposed to templates.
var webhookTemplateFuncs = template.FuncMap{
	// json serializes an arbitrary value into JSON.
	//
	// This function is not a nice-to-have but a necessity: without it, users can only write {{.Title}} to interpolate directly,
	// Once a vulnerability title contains a quote or a newline, the entire request body is no longer valid JSON, and the receiving end will
	// rejects it, and the error message points to "JSON parse failure", with no hint that the cause is a quote in the title.
	"json": func(v any) (string, error) {
		raw, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		return string(raw), nil
	},
	// jsons is used to embed a JSON fragment inside a JSON string value (applying one layer of string escaping).
	"jsons": func(v any) (string, error) {
		raw, err := json.Marshal(v)
		if err != nil {
			return "", err
		}
		quoted, err := json.Marshal(string(raw))
		if err != nil {
			return "", err
		}
		// The outer quotes are removed: the caller decides whether to add quotes.
		return string(quoted[1 : len(quoted)-1]), nil
	},
}

func newWebhookTemplateData(m Message) webhookTemplateData {
	d := webhookTemplateData{
		Title:   markdownTitle(m),
		Batch:   m.Batch,
		Count:   len(m.Items),
		HomeURL: m.HomeURL,
		SentAt:  time.Now().Format(time.RFC3339),
		Items:   make([]webhookItem, 0, len(m.Items)),
	}
	for _, it := range m.Items {
		wi := webhookItem{
			FindingID:     it.FindingID,
			Name:          it.Name,
			VulnClass:     it.VulnClass,
			Severity:      it.Severity,
			SeverityLabel: SeverityLabel(it.Severity),
			Summary:       it.Summary,
			Assets:        append([]string{}, it.Assets...),
			DetailURL:     it.DetailURL,
			FromStatus:    it.FromStatus,
			ToStatus:      it.ToStatus,
		}
		if it.IsStatusChange() {
			wi.StatusLabel = StatusLabel(it.FromStatus) + " → " + StatusLabel(it.ToStatus)
		}
		d.Items = append(d.Items, wi)
	}
	return d
}
