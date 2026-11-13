package manifest

import (
	"bufio"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// Record is one parsed output row: a flat map of field name to scalar. Nested
// JSON is flattened with dot-joined keys so a template can name
// `info.severity` without the parser inventing a type system.
type Record map[string]any

// Parse splits a tool's output into records according to the manifest's emit
// spec. A malformed line is skipped rather than fatal: a scanner that prints a
// banner before its JSONL must still yield the rows it did print.
func (m *Manifest) Parse(output string) ([]Record, error) {
	switch m.Emit.Parser {
	case "json":
		return m.parseJSON(output)
	case "jsonl":
		return parseJSONL(output, m.Emit.Fields)
	case "lines":
		return parseLines(output, m.Emit.Fields)
	case "regex":
		return parseRegex(output, m.Emit.Pattern, m.Emit.Fields)
	case "xml":
		return parseXML(output)
	}
	return nil, fmt.Errorf("%s: unknown parser %q", m.ID, m.Emit.Parser)
}

func (m *Manifest) parseJSON(output string) ([]Record, error) {
	trimmed := strings.TrimSpace(output)
	if trimmed == "" {
		return nil, nil
	}
	var doc any
	if err := json.Unmarshal([]byte(trimmed), &doc); err != nil {
		return nil, fmt.Errorf("%s: output is not JSON: %w", m.ID, err)
	}
	// `records: "$"` means the document is itself the row; a path selects an
	// array inside it.
	selected := selectPath(doc, m.Emit.Records)
	rows, ok := selected.([]any)
	if !ok {
		// A single object is a one-row result, which several tools emit when
		// given one target.
		if obj, isObj := selected.(map[string]any); isObj {
			return []Record{flatten(obj, m.Emit.Fields)}, nil
		}
		return nil, nil
	}
	out := make([]Record, 0, len(rows))
	scalarField := "value"
	if len(m.Emit.Fields) > 0 {
		scalarField = m.Emit.Fields[0]
	}
	for _, row := range rows {
		switch typed := row.(type) {
		case map[string]any:
			out = append(out, flatten(typed, m.Emit.Fields))
		case string, float64, bool:
			// theHarvester reports `hosts` as plain strings; keep them rather
			// than dropping every row because it is not an object.
			out = append(out, Record{scalarField: typed})
		}
	}
	return out, nil
}

func parseJSONL(output string, fields []string) ([]Record, error) {
	var out []Record
	sc := bufio.NewScanner(strings.NewReader(output))
	// Scanners cap a line at 64 KiB by default; a nuclei row with a long
	// matched-at URL and a request dump can exceed that.
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || !strings.HasPrefix(line, "{") {
			continue
		}
		var obj map[string]any
		if err := json.Unmarshal([]byte(line), &obj); err != nil {
			continue
		}
		out = append(out, flatten(obj, fields))
	}
	return out, nil
}

func parseLines(output string, fields []string) ([]Record, error) {
	var out []Record
	sc := bufio.NewScanner(strings.NewReader(output))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" {
			continue
		}
		// A lines parser keeps the value under the first declared field, so a
		// manifest still says what the value means.
		key := "value"
		if len(fields) > 0 {
			key = fields[0]
		}
		out = append(out, Record{key: line})
	}
	return out, nil
}

func parseRegex(output, pattern string, fields []string) ([]Record, error) {
	re, err := regexp.Compile(pattern)
	if err != nil {
		return nil, fmt.Errorf("emit.pattern: %w", err)
	}
	names := re.SubexpNames()
	var out []Record
	sc := bufio.NewScanner(strings.NewReader(output))
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)
	for sc.Scan() {
		match := re.FindStringSubmatch(sc.Text())
		if match == nil {
			continue
		}
		rec := Record{}
		for i, name := range names {
			if i == 0 || name == "" || i >= len(match) {
				continue
			}
			rec[name] = match[i]
		}
		if len(rec) > 0 {
			out = append(out, rec)
		}
	}
	return out, nil
}

// nmapRun is the subset of nmap's XML that a scan actually carries.
type nmapRun struct {
	Hosts []struct {
		Address []struct {
			Addr     string `xml:"addr,attr"`
			AddrType string `xml:"addrtype,attr"`
		} `xml:"address"`
		Hostnames struct {
			Hostname []struct {
				Name string `xml:"name,attr"`
			} `xml:"hostname"`
		} `xml:"hostnames"`
		Ports struct {
			Port []struct {
				Protocol string `xml:"protocol,attr"`
				PortID   string `xml:"portid,attr"`
				State    struct {
					State string `xml:"state,attr"`
				} `xml:"state"`
				Service struct {
					Name    string `xml:"name,attr"`
					Product string `xml:"product,attr"`
					Version string `xml:"version,attr"`
				} `xml:"service"`
			} `xml:"port"`
		} `xml:"ports"`
	} `xml:"host"`
}

// parseXML handles nmap's -oX output, which is the only structured form it
// offers: the grepable -oG format flattens every port on a host into one
// comma-separated field, so a per-port fact would be impossible to derive.
func parseXML(output string) ([]Record, error) {
	var run nmapRun
	if err := xml.Unmarshal([]byte(output), &run); err != nil {
		return nil, fmt.Errorf("output is not nmap XML: %w", err)
	}
	var out []Record
	for _, h := range run.Hosts {
		addr := ""
		for _, a := range h.Address {
			if a.AddrType == "ipv4" || a.AddrType == "ipv6" {
				addr = a.Addr
				break
			}
		}
		if addr == "" {
			continue
		}
		hostname := ""
		if len(h.Hostnames.Hostname) > 0 {
			hostname = h.Hostnames.Hostname[0].Name
		}
		for _, port := range h.Ports.Port {
			out = append(out, Record{
				"host":     addr,
				"hostname": hostname,
				"port":     port.PortID,
				"protocol": port.Protocol,
				"state":    port.State.State,
				"service":  port.Service.Name,
				"product":  port.Service.Product,
				"version":  port.Service.Version,
			})
		}
		// A host with no open ports still exists; record it so an asset sweep
		// does not silently drop a live host.
		if len(h.Ports.Port) == 0 {
			out = append(out, Record{"host": addr, "hostname": hostname, "state": "no-ports"})
		}
	}
	return out, nil
}

// selectPath walks a dotted path into a decoded JSON document. "$" is the
// document itself; an empty path is treated as "$".
func selectPath(doc any, path string) any {
	path = strings.TrimSpace(path)
	if path == "" || path == "$" {
		return doc
	}
	path = strings.TrimPrefix(path, "$.")
	cur := doc
	for _, part := range strings.Split(path, ".") {
		obj, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = obj[part]
	}
	return cur
}

// flatten renders nested maps as dot-joined keys and keeps only the requested
// fields when the manifest narrowed them. A field listed but absent is simply
// not present, which lets an emit rule treat it as unresolved.
func flatten(obj map[string]any, fields []string) Record {
	out := Record{}
	walk(obj, "", out)
	if len(fields) == 0 {
		return out
	}
	kept := Record{}
	for _, f := range fields {
		if v, ok := out[f]; ok {
			kept[f] = v
		}
	}
	return kept
}

func walk(obj map[string]any, prefix string, out Record) {
	for k, v := range obj {
		key := k
		if prefix != "" {
			key = prefix + "." + k
		}
		if nested, ok := v.(map[string]any); ok {
			walk(nested, key, out)
			continue
		}
		// An array of objects is indexed (`ports.0.port`) so a tool that nests a
		// list, as masscan does for ports, can still be templated.
		if list, ok := v.([]any); ok {
			// Keep the joined value under the base key as well, so a manifest can
			// name `cname` without knowing the element index.
			out[key] = v
			for i, item := range list {
				indexed := key + "." + strconv.Itoa(i)
				if nested, ok := item.(map[string]any); ok {
					walk(nested, indexed, out)
					continue
				}
				out[indexed] = item
			}
			continue
		}
		out[key] = v
	}
}

// Scalar renders a record value as the string a template produced. Numbers are
// rendered without a trailing ".0" so a port reads as 443 rather than 443.0.
func Scalar(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case json.Number:
		return t.String()
	case []any:
		// A tool that emits a list for a field (dnsx records, amass addresses)
		// is rendered comma-joined, which is what an emit template wants.
		parts := make([]string, len(t))
		for i, item := range t {
			parts[i] = Scalar(item)
		}
		return strings.Join(parts, ",")
	}
	return fmt.Sprint(v)
}

// Interpolate resolves a `{{ record.x }}` template against one record. It
// returns false when the field is absent, so an emit rule can be skipped rather
// than emitting an empty string that would be stored as a real value.
func Interpolate(tmpl string, rec Record) (string, bool) {
	t := strings.TrimSpace(tmpl)
	if !strings.HasPrefix(t, "{{") || !strings.HasSuffix(t, "}}") {
		return tmpl, true
	}
	expr := strings.TrimSpace(strings.TrimSuffix(strings.TrimPrefix(t, "{{"), "}}"))
	name, ok := strings.CutPrefix(expr, "record.")
	if !ok {
		return "", false
	}
	// `{{ record.x? }}` marks a field as optional: a sparse tool (dnsx emits only
	// the record types it found) would otherwise lose the whole fact because one
	// field was absent.
	name = strings.TrimSuffix(name, "?")
	v, present := rec[name]
	if !present {
		return "", false
	}
	return Scalar(v), true
}

// FieldNames returns a record's keys in sorted order, for diagnostics.
func (r Record) FieldNames() []string {
	out := make([]string, 0, len(r))
	for k := range r {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
