package browser

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// maxSnapshotLines bounds what the model reads. A page with more nodes is
// narrowed by acting on a ref, not by dumping the whole tree.
const maxSnapshotLines = 2000

// maxSubtreeLines is the most a caller may ask of one subtree.
const maxSubtreeLines = 4000

// errStaleRef is the exact text the tool layer surfaces: the model has to
// snapshot again rather than guess what a ref now points at.
var errStaleRef = errors.New("stale reference, take a new snapshot")

// Snapshot is the rendered accessibility tree and the refs it defines.
type Snapshot struct {
	Tree      string
	Refs      map[string]Ref
	Truncated bool
}

// Ref is one rendered node. Only the backend node id is needed to resolve
// geometry later; the rest of the AX node is already in Tree. NodeID is the
// accessibility node the ref came from, which a subtree snapshot needs because
// some rendered nodes carry no backend id.
type Ref struct {
	BackendNodeID int64
	NodeID        string
}

// Snapshot renders the page's accessibility tree with refs for the current
// generation. A ref from a snapshot taken before a top-level navigation is
// rejected by every action.
func (d *Driver) Snapshot(ctx context.Context) (*Snapshot, error) {
	raw, err := d.Send(ctx, "Accessibility.getFullAXTree", nil)
	if err != nil {
		return nil, err
	}
	var result struct {
		Nodes []axNode `json:"nodes"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return nil, fmt.Errorf("browser: decode accessibility tree: %w", err)
	}

	d.mu.Lock()
	gen := d.gen
	d.mu.Unlock()

	tree, refs, truncated := renderAX(result.Nodes, gen)

	d.mu.Lock()
	if d.gen == gen {
		d.refs = refs
	}
	d.mu.Unlock()

	return &Snapshot{Tree: tree, Refs: refs, Truncated: truncated}, nil
}

// SnapshotSubtree renders only the accessibility subtree under ref, so a form
// buried in a large page costs its own size instead of the whole document.
// The returned refs are numbered from 1 like any other snapshot and replace
// the driver's ref table, so a caller acts on the refs it just received.
func (d *Driver) SnapshotSubtree(ctx context.Context, ref string, maxLines int) (Snapshot, error) {
	r, err := d.resolve(ref)
	if err != nil {
		return Snapshot{}, err
	}
	if maxLines <= 0 {
		maxLines = maxSnapshotLines
	}
	if maxLines > maxSubtreeLines {
		maxLines = maxSubtreeLines
	}

	raw, err := d.Send(ctx, "Accessibility.getFullAXTree", nil)
	if err != nil {
		return Snapshot{}, err
	}
	var result struct {
		Nodes []axNode `json:"nodes"`
	}
	if err := json.Unmarshal(raw, &result); err != nil {
		return Snapshot{}, fmt.Errorf("browser: decode accessibility tree: %w", err)
	}

	node := findAXNode(result.Nodes, r)
	if node == nil {
		return Snapshot{}, errStaleRef
	}

	d.mu.Lock()
	gen := d.gen
	d.mu.Unlock()

	tree, refs, truncated := renderAXLimit(subtreeNodes(result.Nodes, node.NodeID), gen, maxLines)

	d.mu.Lock()
	if d.gen == gen {
		d.refs = refs
	}
	d.mu.Unlock()

	return Snapshot{Tree: tree, Refs: refs, Truncated: truncated}, nil
}

// findAXNode locates the AX node a ref points at. The node id is the exact
// key; the backend id is the fallback for refs taken before it was kept.
func findAXNode(nodes []axNode, r Ref) *axNode {
	if r.NodeID != "" {
		for i := range nodes {
			if nodes[i].NodeID == r.NodeID && !nodes[i].Ignored {
				return &nodes[i]
			}
		}
	}
	if r.BackendNodeID != 0 {
		for i := range nodes {
			if nodes[i].BackendDOMNodeID == r.BackendNodeID && !nodes[i].Ignored {
				return &nodes[i]
			}
		}
	}
	return nil
}

// subtreeNodes returns root and its descendants in document order. Child
// lists are rebuilt from parentId, so a tree that only carries parents still
// renders, and a malformed cycle cannot spin the walk.
func subtreeNodes(nodes []axNode, root string) []axNode {
	byID := make(map[string]*axNode, len(nodes))
	children := make(map[string][]string, len(nodes))
	for i := range nodes {
		byID[nodes[i].NodeID] = &nodes[i]
		children[nodes[i].ParentID] = append(children[nodes[i].ParentID], nodes[i].NodeID)
	}
	n, ok := byID[root]
	if !ok {
		return nil
	}

	out := make([]axNode, 0, len(nodes))
	first := *n
	first.ChildIDs = append([]string(nil), children[root]...)
	out = append(out, first)
	seen := map[string]bool{root: true}
	var walk func(id string)
	walk = func(id string) {
		for _, child := range children[id] {
			if seen[child] {
				continue
			}
			seen[child] = true
			node := *byID[child]
			node.ChildIDs = append([]string(nil), children[child]...)
			out = append(out, node)
			walk(child)
		}
	}
	walk(root)
	return out
}

// bumpGeneration invalidates every ref. Called on top-level navigation and on
// relaunch, both of which replace the document.
func (d *Driver) bumpGeneration() {
	d.mu.Lock()
	d.gen++
	d.refs = map[string]Ref{}
	d.mu.Unlock()
}

// resolve turns a ref into its DOM node, or reports that the page moved.
func (d *Driver) resolve(ref string) (Ref, error) {
	d.mu.Lock()
	defer d.mu.Unlock()
	r, ok := d.refs[ref]
	if !ok {
		return Ref{}, errStaleRef
	}
	return r, nil
}

type axNode struct {
	NodeID           string       `json:"nodeId"`
	ParentID         string       `json:"parentId"`
	Ignored          bool         `json:"ignored"`
	Role             *axValue     `json:"role"`
	Name             *axValue     `json:"name"`
	Value            *axValue     `json:"value"`
	Properties       []axProperty `json:"properties"`
	ChildIDs         []string     `json:"childIds"`
	BackendDOMNodeID int64        `json:"backendDOMNodeId"`
}

type axValue struct {
	Type  string `json:"type"`
	Value any    `json:"value"`
}

type axProperty struct {
	Name  string  `json:"name"`
	Value axValue `json:"value"`
}

// renderAX flattens the AX tree into indented lines. Ignored nodes are walked
// but not rendered, so their children keep their visible depth.
func renderAX(nodes []axNode, gen int) (string, map[string]Ref, bool) {
	return renderAXLimit(nodes, gen, maxSnapshotLines)
}

// renderAXLimit is renderAX with the caller's line budget. A tree over the
// budget loses its last line to the truncation marker, so the result never
// exceeds maxLines.
func renderAXLimit(nodes []axNode, gen int, maxLines int) (string, map[string]Ref, bool) {
	byID := make(map[string]*axNode, len(nodes))
	for i := range nodes {
		byID[nodes[i].NodeID] = &nodes[i]
	}
	var roots []*axNode
	for i := range nodes {
		n := &nodes[i]
		if n.ParentID == "" || byID[n.ParentID] == nil {
			roots = append(roots, n)
		}
	}

	total := 0
	for i := range nodes {
		if !nodes[i].Ignored {
			total++
		}
	}
	truncated := total > maxLines
	limit := maxLines
	if truncated {
		limit = maxLines - 1
	}

	var b strings.Builder
	refs := make(map[string]Ref)
	rendered := 0
	index := 0
	var walk func(n *axNode, depth int)
	walk = func(n *axNode, depth int) {
		if rendered >= limit {
			return
		}
		childDepth := depth
		if !n.Ignored {
			index++
			ref := "g" + strconv.Itoa(gen) + "e" + strconv.Itoa(index)
			role := axString(n.Role)
			if role == "" {
				role = "unknown"
			}
			name := axString(n.Name)

			b.WriteString(strings.Repeat("  ", depth))
			b.WriteString("- ")
			b.WriteString(role)
			b.WriteString(" ")
			b.WriteString(strconv.Quote(name))
			b.WriteString(" [ref=")
			b.WriteString(ref)
			b.WriteString("]")
			if value := axString(n.Value); value != "" {
				b.WriteString(" value=")
				b.WriteString(strconv.Quote(value))
			}
			if checked, ok := prop(n, "checked"); ok {
				b.WriteString(" checked=")
				b.WriteString(axString(checked))
			}
			if propBool(n, "disabled") {
				b.WriteString(" disabled")
			}
			if propBool(n, "required") {
				b.WriteString(" required")
			}
			b.WriteString("\n")

			refs[ref] = Ref{BackendNodeID: n.BackendDOMNodeID, NodeID: n.NodeID}
			rendered++
			childDepth = depth + 1
		}
		for _, id := range n.ChildIDs {
			if child := byID[id]; child != nil {
				walk(child, childDepth)
			}
		}
	}
	for _, root := range roots {
		walk(root, 0)
	}
	if truncated {
		fmt.Fprintf(&b, "- (truncated at %d lines)\n", maxLines)
	}
	return strings.TrimSuffix(b.String(), "\n"), refs, truncated
}

func axString(v *axValue) string {
	if v == nil {
		return ""
	}
	switch value := v.Value.(type) {
	case string:
		return value
	case bool:
		return strconv.FormatBool(value)
	case float64:
		return strconv.FormatFloat(value, 'f', -1, 64)
	default:
		return ""
	}
}

func prop(n *axNode, name string) (*axValue, bool) {
	for i := range n.Properties {
		if n.Properties[i].Name == name {
			return &n.Properties[i].Value, true
		}
	}
	return nil, false
}

func propBool(n *axNode, name string) bool {
	value, ok := prop(n, name)
	if !ok {
		return false
	}
	on, _ := value.Value.(bool)
	return on
}
