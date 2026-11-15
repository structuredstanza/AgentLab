package manifest

import (
	"embed"
	"fmt"
	"io/fs"
	"sort"
	"sync"
)

// builtinFS holds the manifests shipped with the binary.
//
// Embedding rather than reading a directory is deliberate: a manifest that is
// missing at run time looks like a tool that is simply unavailable, and a
// deployment that forgets to copy a directory would fail silently. Embedded,
// the tool set is a property of the binary.
//
//go:embed builtin/*.toml
var builtinFS embed.FS

// Builtin returns the manifests compiled into this binary.
func Builtin() (*Set, error) {
	return loadFS(builtinFS, "builtin")
}

// LoadBuiltin is Builtin with a panic-free error for callers that cannot
// propagate: the embedded set is validated by TestShippedManifestsLoad, so a
// failure here means the binary was built from a broken tree.
func LoadBuiltin() *Set {
	set, err := Builtin()
	if err != nil {
		return &Set{byID: map[string]*Manifest{}}
	}
	return set
}

// builtinSources maps each shipped manifest id to its raw TOML. It is keyed by
// the id inside the file, not the file name, so renaming a file cannot make a
// built-in unreachable by the id the catalog shows.
var builtinSources = sync.OnceValue(func() map[string]string {
	out := map[string]string{}
	entries, _ := fs.ReadDir(builtinFS, "builtin")
	for _, e := range entries {
		data, err := fs.ReadFile(builtinFS, "builtin/"+e.Name())
		if err != nil {
			continue
		}
		if m, err := Parse(string(data)); err == nil {
			out[m.ID] = string(data)
		}
	}
	return out
})

// BuiltinSource returns the embedded TOML text of a built-in manifest, so an
// editor can start from it and "reset to built-in" has something to restore.
func BuiltinSource(id string) (string, bool) {
	text, ok := builtinSources()[id]
	return text, ok
}

// loadFS parses every *.toml in dir within fsys.
func loadFS(fsys fs.FS, dir string) (*Set, error) {
	entries, err := fs.ReadDir(fsys, dir)
	if err != nil {
		return nil, fmt.Errorf("read manifest dir: %w", err)
	}
	set := &Set{byID: map[string]*Manifest{}}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		data, err := fs.ReadFile(fsys, dir+"/"+e.Name())
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		m, err := Parse(string(data))
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if _, dup := set.byID[m.ID]; dup {
			return nil, fmt.Errorf("%s: duplicate manifest id %q", e.Name(), m.ID)
		}
		set.byID[m.ID] = m
		set.ids = append(set.ids, m.ID)
	}
	sort.Strings(set.ids)
	return set, nil
}
