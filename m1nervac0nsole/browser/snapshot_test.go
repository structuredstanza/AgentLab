package browser

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

const axFixture = `{"nodes":[
 {"nodeId":"1","role":{"value":"RootWebArea"},"name":{"value":"Test"},"childIds":["2","5"]},
 {"nodeId":"2","parentId":"1","role":{"value":"form"},"name":{"value":""},"childIds":["3","4"]},
 {"nodeId":"3","parentId":"2","role":{"value":"textbox"},"name":{"value":"Email"},"value":{"value":"a@b"},"backendDOMNodeId":11,"properties":[{"name":"required","value":{"value":true}}]},
 {"nodeId":"4","parentId":"2","role":{"value":"checkbox"},"name":{"value":"Remember"},"backendDOMNodeId":12,"properties":[{"name":"checked","value":{"value":true}},{"name":"disabled","value":{"value":true}}]},
 {"nodeId":"5","parentId":"1","ignored":true,"childIds":["6"]},
 {"nodeId":"6","parentId":"5","role":{"value":"button"},"name":{"value":"Go"},"backendDOMNodeId":13}
]}`

// The model reads this text, so role, name, state and depth all have to be
// present and stable.
func TestSnapshotRendersRolesStateAndDepth(t *testing.T) {
	f := newFakeConn()
	f.replies["Accessibility.getFullAXTree"] = json.RawMessage(axFixture)
	d := newTestDriver(t, f, nil)

	snap, err := d.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	want := strings.Join([]string{
		`- RootWebArea "Test" [ref=g1e1]`,
		`  - form "" [ref=g1e2]`,
		`    - textbox "Email" [ref=g1e3] value="a@b" required`,
		`    - checkbox "Remember" [ref=g1e4] checked=true disabled`,
		`  - button "Go" [ref=g1e5]`,
	}, "\n")
	if snap.Tree != want {
		t.Fatalf("tree:\n%s\nwant:\n%s", snap.Tree, want)
	}
	if len(snap.Refs) != 5 {
		t.Fatalf("refs = %d, want 5", len(snap.Refs))
	}
	if got := snap.Refs["g1e3"].BackendNodeID; got != 11 {
		t.Fatalf("g1e3 backend node = %d, want 11", got)
	}
	if snap.Truncated {
		t.Fatal("small tree reported as truncated")
	}
}

// A huge page must not blow the model's context: the tree stops at the cap and
// says so.
func TestSnapshotCapsAt2000Lines(t *testing.T) {
	var children strings.Builder
	for i := range 2500 {
		if i > 0 {
			children.WriteString(",")
		}
		fmt.Fprintf(&children, `"n%d"`, i)
	}
	nodes := []string{
		`{"nodeId":"1","role":{"value":"RootWebArea"},"name":{"value":"many"},"childIds":[` + children.String() + `]}`,
	}
	for i := range 2500 {
		nodes = append(nodes, fmt.Sprintf(
			`{"nodeId":"n%d","parentId":"1","role":{"value":"StaticText"},"name":{"value":"item %d"},"backendDOMNodeId":%d}`,
			i, i, i+10))
	}

	f := newFakeConn()
	f.replies["Accessibility.getFullAXTree"] = json.RawMessage(`{"nodes":[` + strings.Join(nodes, ",") + `]}`)
	d := newTestDriver(t, f, nil)

	snap, err := d.Snapshot(context.Background())
	if err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	lines := strings.Split(snap.Tree, "\n")
	if len(lines) != maxSnapshotLines {
		t.Fatalf("lines = %d, want %d", len(lines), maxSnapshotLines)
	}
	if !snap.Truncated {
		t.Fatal("truncated tree not reported")
	}
	if !strings.Contains(lines[len(lines)-1], "truncated") {
		t.Fatalf("last line = %q, want a truncation marker", lines[len(lines)-1])
	}
	if len(snap.Refs) != maxSnapshotLines-1 {
		t.Fatalf("refs = %d, want %d", len(snap.Refs), maxSnapshotLines-1)
	}
}

// A ref snapshot costs only that node's descendants, not the whole page.
func TestSnapshotSubtreeRendersOnlyTheRef(t *testing.T) {
	f := newFakeConn()
	f.replies["Accessibility.getFullAXTree"] = json.RawMessage(axFixture)
	d := newTestDriver(t, f, nil)
	ctx := context.Background()

	if _, err := d.Snapshot(ctx); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sub, err := d.SnapshotSubtree(ctx, "g1e2", 0)
	if err != nil {
		t.Fatalf("subtree: %v", err)
	}
	want := strings.Join([]string{
		`- form "" [ref=g1e1]`,
		`  - textbox "Email" [ref=g1e2] value="a@b" required`,
		`  - checkbox "Remember" [ref=g1e3] checked=true disabled`,
	}, "\n")
	if sub.Tree != want {
		t.Fatalf("subtree:\n%s\nwant:\n%s", sub.Tree, want)
	}
	if len(sub.Refs) != 3 {
		t.Fatalf("refs = %d, want 3", len(sub.Refs))
	}
	if sub.Truncated {
		t.Fatal("small subtree reported as truncated")
	}
	if _, err := d.SnapshotSubtree(ctx, "g1e99", 0); err != errStaleRef {
		t.Fatalf("unknown ref error = %v, want %v", err, errStaleRef)
	}
}

// A leaf is its own subtree: one line, no children invented.
func TestSnapshotSubtreeLeaf(t *testing.T) {
	f := newFakeConn()
	f.replies["Accessibility.getFullAXTree"] = json.RawMessage(axFixture)
	d := newTestDriver(t, f, nil)
	ctx := context.Background()

	if _, err := d.Snapshot(ctx); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sub, err := d.SnapshotSubtree(ctx, "g1e3", 0)
	if err != nil {
		t.Fatalf("subtree: %v", err)
	}
	want := `- textbox "Email" [ref=g1e1] value="a@b" required`
	if sub.Tree != want {
		t.Fatalf("leaf subtree = %q, want %q", sub.Tree, want)
	}
}

// The caller's line budget truncates the subtree and says so.
func TestSnapshotSubtreeCapsLines(t *testing.T) {
	var children strings.Builder
	nodes := make([]string, 0, 11)
	for i := range 10 {
		if i > 0 {
			children.WriteString(",")
		}
		fmt.Fprintf(&children, `"n%d"`, i)
	}
	nodes = append(nodes, `{"nodeId":"1","role":{"value":"RootWebArea"},"name":{"value":"many"},"childIds":[`+children.String()+`]}`)
	for i := range 10 {
		nodes = append(nodes, fmt.Sprintf(
			`{"nodeId":"n%d","parentId":"1","role":{"value":"StaticText"},"name":{"value":"item %d"},"backendDOMNodeId":%d}`,
			i, i, i+10))
	}

	f := newFakeConn()
	f.replies["Accessibility.getFullAXTree"] = json.RawMessage(`{"nodes":[` + strings.Join(nodes, ",") + `]}`)
	d := newTestDriver(t, f, nil)
	ctx := context.Background()

	if _, err := d.Snapshot(ctx); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sub, err := d.SnapshotSubtree(ctx, "g1e1", 3)
	if err != nil {
		t.Fatalf("subtree: %v", err)
	}
	lines := strings.Split(sub.Tree, "\n")
	if len(lines) != 3 {
		t.Fatalf("lines = %d, want 3", len(lines))
	}
	if !sub.Truncated {
		t.Fatal("truncated subtree not reported")
	}
	if !strings.Contains(lines[2], "truncated at 3 lines") {
		t.Fatalf("last line = %q, want a truncation marker", lines[2])
	}
}

// maxLines above the cap is clamped to 4000, not honoured.
func TestSnapshotSubtreeCapsAt4000(t *testing.T) {
	var children strings.Builder
	nodes := make([]string, 0, 4002)
	for i := range 4001 {
		if i > 0 {
			children.WriteString(",")
		}
		fmt.Fprintf(&children, `"n%d"`, i)
	}
	nodes = append(nodes, `{"nodeId":"1","role":{"value":"RootWebArea"},"name":{"value":"many"},"childIds":[`+children.String()+`]}`)
	for i := range 4001 {
		nodes = append(nodes, fmt.Sprintf(
			`{"nodeId":"n%d","parentId":"1","role":{"value":"StaticText"},"name":{"value":"item %d"},"backendDOMNodeId":%d}`,
			i, i, i+10))
	}

	f := newFakeConn()
	f.replies["Accessibility.getFullAXTree"] = json.RawMessage(`{"nodes":[` + strings.Join(nodes, ",") + `]}`)
	d := newTestDriver(t, f, nil)
	ctx := context.Background()

	if _, err := d.Snapshot(ctx); err != nil {
		t.Fatalf("snapshot: %v", err)
	}
	sub, err := d.SnapshotSubtree(ctx, "g1e1", 9999)
	if err != nil {
		t.Fatalf("subtree: %v", err)
	}
	lines := strings.Split(sub.Tree, "\n")
	if len(lines) != maxSubtreeLines {
		t.Fatalf("lines = %d, want %d", len(lines), maxSubtreeLines)
	}
	if !strings.Contains(lines[len(lines)-1], "truncated at 4000 lines") {
		t.Fatalf("last line = %q, want the cap marker", lines[len(lines)-1])
	}
}
