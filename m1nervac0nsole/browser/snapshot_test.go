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
