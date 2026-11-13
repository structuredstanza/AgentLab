package server

import (
	"sort"
	"strconv"

	pgdb "github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	"github.com/structuredstanza/AgentLab/m1nervac0nsole/report"
)

// uncoveredAssets lists the in-scope assets this task never explored. The
// generated report otherwise enumerates findings only, which reads as "the rest
// of the scope was clean" even when a host was never touched. A disabled asset
// store or a failed graph build returns nil, which the report renders as
// "could not be determined" rather than as full coverage; a non-nil empty slice
// means every in-scope asset was touched.
func uncoveredAssets(as *pgdb.AssetStore, t *Task) []report.UncoveredAsset {
	if as == nil || t == nil {
		return nil
	}
	taskID, err := strconv.ParseInt(t.ID, 10, 64)
	if err != nil {
		return nil
	}
	g, err := as.BuildCoverageGraph(taskID, t.ExpID)
	if err != nil || g == nil {
		return nil
	}
	// A node with children is a container: a root domain whose subdomains were
	// explored, or a service whose endpoints were, is not itself an untested
	// target. Edges are child→parent, so Dst is the parent key.
	containers := make(map[string]bool, len(g.Edges))
	for _, e := range g.Edges {
		containers[e.Dst] = true
	}
	out := make([]report.UncoveredAsset, 0, len(g.Nodes))
	for _, n := range g.Nodes {
		// AssetID 0 marks a connector (company, synthetic root domain) with no
		// asset row to test, so it can never be an untested target.
		if !n.InScope || n.Tested || n.AssetID == 0 || containers[n.Key] {
			continue
		}
		out = append(out, report.UncoveredAsset{Kind: n.Kind, Label: n.Label})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Label < out[j].Label
	})
	return out
}
