package notify

// Snapshot is the contract for the notification_events.snapshot JSONB column. The writer is the db layer.
// vulnerability-persistence transaction in the db layer, and the readers are the delivery engine and filter matching in the server layer. The definition lives in this package because it is
// the payload of the "notification domain": db only handles serialization and does not interpret the meaning of the fields.
//
// Why the vulnerability fields are stored redundantly instead of being looked up again at render time: vulnerabilities may later be renamed, have their severity changed, or change status,
// The pushed content should reflect the conclusion as of **the time of the event**. Looking it up afterward would return one that has since been changed to "low".
// misleading "later changed to low" result. In addition, fan-out and rendering therefore do not need to JOIN the findings/tasks/assets tables.
type Snapshot struct {
	// Event types: finding_created / finding_status_changed
	Kind      string  `json:"kind"`
	FindingID int64   `json:"finding_id"`
	TaskID    int64   `json:"task_id"`
	VulnClass string  `json:"vulnclass"`
	Name      string  `json:"name"`
	Severity  string  `json:"severity"`
	Summary   string  `json:"summary"`
	AssetIDs  []int64 `json:"asset_ids"`
	// Non-empty only when kind=finding_status_changed.
	FromStatus string `json:"from_status,omitempty"`
	ToStatus   string `json:"to_status,omitempty"`
}

// Item is a pending vulnerability to be pushed, for channels to render.
type Item struct {
	FindingID int64
	Name      string
	VulnClass string
	Severity  string
	Summary   string
	// Assets is the resolved asset display name (such as a domain or IP). It is populated by the server layer——
	// This package does not touch the database, so it cannot obtain the name.
	Assets []string
	// DetailURL is the back-link to the vulnerability details; empty means public_base_url is not configured, and it is omitted when rendering.
	DetailURL string
	// Used exclusively for status change events; when both fields are non-empty, it renders as "pending → fixed".
	FromStatus string
	ToStatus   string
}

// IsStatusChange reports whether this item is a status change event.
func (i Item) IsStatusChange() bool { return i.FromStatus != "" || i.ToStatus != "" }

// Title returns the display title of the item: it prefers the manually named name, falling back to the vulnerability class vulnclass,
// When both are empty, use a placeholder — never output an empty title.
func (i Item) Title() string {
	if i.Name != "" {
		return i.Name
	}
	if i.VulnClass != "" {
		return i.VulnClass
	}
	return "(unnamed vulnerability)"
}

// Message is the complete content of one channel send.
type Message struct {
	// For a single push the length is 1; for a digest push it is an entire batch.
	// An empty slice is invalid; the caller must guarantee at least one entry.
	Items []Item
	// When Batch=true, render as a digest message (with a new title, including the time window and item count).
	Batch bool
	// WindowMinutes is the summary period in minutes. It is used only when Batch=true, for the copy "in the last N minutes".
	// Deliberately passed explicitly via config rather than computed with time.Since at render time: rendering stays deterministic, which makes it testable.
	WindowMinutes int
	// HomeURL is the platform dashboard address (global public_base_url); if empty, no dashboard entry link is included.
	HomeURL string
}
