// Package notify implements the IM / email push channel adapter layer for vulnerability findings.
//
// Layering: this package is a **leaf package** and depends only on the standard library. It knows nothing about the database and nothing about the server. Channel configuration
// is passed in as map[string]any (corresponding to the notification_channels.config JSONB column),
// The message to be pushed is passed in as a Message. The benefit of splitting it this way is that signature computation, UTF-8 truncation, and filter matching
// The parts that are genuinely error-prone can be unit-tested without PostgreSQL; the host only needs to handle orchestration on the server side.
//
// Concurrency contract: Channel implementations must be **stateless**. The same Channel instance may be reused concurrently by multiple channel configurations
// (or even by multiple bot instances of the same channel). All credentials must be taken from the cfg parameter,
// Do not cache things like the webhook URL in the implementation's own fields.
package notify

// Channel type identifier. The accepted values are also the valid set for notification_channels.kind, and are validated by a whitelist on the server side
// (same reasoning as findings.status: no DB CHECK constraint, so that new channels are easier to add later).
const (
	KindDingTalk = "dingtalk" // DingTalk custom robot
	KindFeishu   = "feishu"   // Feishu (including Lark) custom bot
	KindWeCom    = "wecom"    // WeCom group bot
	KindWebhook  = "webhook"  // Generic webhook: custom method, headers, and JSON template
	KindTelegram = "telegram" // Telegram Bot API
	KindEmail    = "email"    // SMTP email
)

// Event type, corresponding to notification_events.kind.
const (
	EventFindingCreated       = "finding_created"
	EventFindingStatusChanged = "finding_status_changed"
)

// InitKind is the fallback value for a kind that is empty in config.
const InitKind = KindDingTalk

// severityRank maps vulnerability severity levels to comparable ordinal values. Unknown levels return 0, so any
// min_severity setting will filter out unknown levels — when in doubt, do not push, to avoid false-alarm floods.
var severityRank = map[string]int{
	"low":      1,
	"medium":   2,
	"high":     3,
	"critical": 4,
}

// SeverityRank returns the ordinal of the severity level; unknown levels return 0.
func SeverityRank(severity string) int { return severityRank[severity] }

// severityLabels / statusLabels hold the English display strings for push and email messages.
var severityLabels = map[string]string{
	"critical": "🔴 Critical", "high": "🟠 High", "medium": "🟡 Medium", "low": "🔵 Low",
}

var statusLabels = map[string]string{
	"pending": "Pending", "in_progress": "In progress", "confirmed": "Confirmed", "resolved": "Resolved", "fixed": "Fixed", "false_positive": "False positive", "ignored": "Ignored", "duplicate": "Duplicate", "risk_accepted": "Risk accepted",
}

// SeverityLabel returns the English name of the severity level with an emoji, used for message titles and card colors.
// Unknown levels are echoed back as-is, without guessing.
func SeverityLabel(severity string) string {
	if v, ok := severityLabels[severity]; ok {
		return v
	}
	return severity
}

// StatusLabel translates the handling status into English, for use in status-change messages. Unknown statuses are echoed back as-is.
func StatusLabel(status string) string {
	if v, ok := statusLabels[status]; ok {
		return v
	}
	return status
}

// AtLeast reports whether severity meets the min threshold. An empty min means no threshold is set, so every value passes.
// Note that an unknown severity has ordinal 0, so it will be rejected by any non-empty min (see the severityRank comment).
func AtLeast(severity, min string) bool {
	if min == "" {
		return true
	}
	return SeverityRank(severity) >= SeverityRank(min)
}
