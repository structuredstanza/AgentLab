package agent

import (
	"encoding/json"
	"fmt"

	"github.com/structuredstanza/AgentLab/m1nervac0nsole/db"
	actool "github.com/structuredstanza/norma/tool"
)

const findingIDGuidance = "\n\n**Finding ID convention**: finding_id is the independent vulnerability record ID; finding_node_id is the exploration node ID. The id arguments of list_findings / list_task_findings / node_detail / get_task_node_detail remain exploration node IDs; read the independent number from the finding_id in the same response. get_finding_traffic / bind_finding_traffic use the independent finding_id. The finding_id parameter of the legacy update_finding_report still takes finding_node_id. Do not use the number on the first line of report_finding for evidence tools, and do not guess other numbers after an ID error."

// The server supplies the persisted setting. A missing setting/host is off.
// Consulted at assembly and again on writes so an already-running session
// cannot keep binding after the user switches the feature off.
var FindingTrafficBindingEnabled func() bool

func findingTrafficBindingEnabled() bool {
	return FindingTrafficBindingEnabled != nil && FindingTrafficBindingEnabled()
}

// Applied after ToolResolve: user descriptions and prompts remain intact, while
// all actual reporters (including Planner and custom chat agents) see the same
// API contract. Disabled/unbound tools are never reintroduced here.
func findingWorkflowTools(agentKey string, tools []actool.CoreTool) ([]actool.CoreTool, string) {
	if !findingTrafficBindingEnabled() {
		out := make([]actool.CoreTool, 0, len(tools))
		for _, tool := range tools {
			if tool.Name() == "bind_finding_traffic" {
				continue
			}
			if agentKey == "reporter" && (tool.Name() == "traffic_search" || tool.Name() == "traffic_get" || tool.Name() == "traffic_blob") {
				continue
			}
			switch tool.Name() {
			case "report_finding", "add_hint", "add_task_hint":
				// Work on a copy: toggling back on must restore the original schema.
				raw, _ := json.Marshal(tool.InputSchema())
				var schema map[string]any
				if json.Unmarshal(raw, &schema) == nil {
					stripTrafficParameters(schema)
					tool = DecorateTool(tool, tool.Description(), schema)
				}
			}
			out = append(out, tool)
		}
		return out, ""
	}
	out := append([]actool.CoreTool(nil), tools...)
	has := map[string]bool{}
	for i, tool := range out {
		has[tool.Name()] = true
		note := ""
		switch tool.Name() {
		case "report_finding":
			note = "\nBy default, the reporting Agent verifies and binds traffic before writing the report. Reporters keep the verification command, key output, existing real traffic IDs, and their purposes in evidence so the report Agent can check them against the execution record; no extra packet lookup is needed for binding. Explicit immediate binding is still supported: traffic_refs or evidence_hint_id may submit verified references, and the latter reads the structured references of the hint specified for this task. If any is invalid, the whole report fails. TCP or packet-less findings do not need these optional parameters. The returned finding_id and finding_node_id denote the independent record and the exploration node respectively."
		case "add_hint", "add_task_hint":
			note = "\nWhen handing off a confirmed vulnerability, keep the verified traffic IDs, purposes, descriptions, and order in the hint's traffic_refs (a single item at the top level, or in the corresponding hints element for batches), and state in text which specific vulnerability it proves. Callers must not hand off text alone and discard existing traffic references. Unverified candidates cannot be passed on as evidence."
		case "get_finding_traffic", "bind_finding_traffic", "list_findings", "list_task_findings", "node_detail", "get_task_node_detail", "update_finding_report":
			note = findingIDGuidance
		}
		if note != "" {
			out[i] = DecorateTool(tool, tool.Description()+note, tool.InputSchema())
		}
	}
	guidance := ""
	if has["report_finding"] || has["add_task_hint"] || has["add_hint"] {
		guidance = "\n\n**Traffic evidence handoff (optional)**: automatic binding is by default completed by the reporting Agent after the finding is stored and before writing the report. The reporter should keep the verification command, key output, existing real traffic IDs, and their purposes in evidence, and include intent_id in the task so the report Agent can trace it; do not fetch extra packets just for binding. When Auto or Planner reports on someone's behalf, do not discard the executor's existing references. add_hint / add_task_hint can hand off with traffic_refs; explicit immediate binding remains compatible via report_finding's traffic_refs / evidence_hint_id. For TCP or packet-less cases, register normally; do not guess IDs, and do not repeat probes just to fill in packets."
		if has["add_task_hint"] && !has["add_hint"] {
			guidance += "\nWhen the platform chat has no task context, do not call report_finding directly; hand off to an existing matching task via add_task_hint, let the task Agent register it, and verify the result with list_task_findings."
		}
		if has["prove_goal"] || has["goal_met"] {
			guidance += "\nBefore judging the goal complete, finish reporting or handing off the evidence already collected for this work. Do not end the task or cancel Workers just because a text finding is registered while evidence handoff is incomplete; for packet-less cases, do not require waiting or force a capture."
		}
	}
	if has["update_finding_report"] && has["bind_finding_traffic"] && has["get_finding_traffic"] {
		guidance += "\n\n**Auto-link traffic before report (enabled)**: you are responsible for verifying and binding traffic for the finding triggered this time, then writing the report. First obtain explicit finding_id and finding_node_id from the report_finding return JSON, or from get_task_node_detail / list_task_findings. Read the finding details, the execution record of the corresponding intent, and the existing evidence list, preferring the real IDs handed off by the reporter. If this verification is HTTP and traffic tools are available, use traffic_search to filter candidates, then use traffic_get to confirm request/response one by one actually supports the vulnerability; domain and time are only filters and do not prove ownership. Bind confirmed evidence in reproduction order with bind_finding_traffic(finding_id, traffic_refs), choosing baseline / proof / verification / supporting and stating each purpose. Only operate on this finding; do not create duplicate findings or re-probe the target. After a successful bind, call get_finding_traffic again to get the latest version, read the bodies you need, then pass the version actually read as evidence_version to update_finding_report (whose finding_id parameter still uses finding_node_id). Existing bindings need not be appended again. For TCP, traffic not captured, unavailable tools, or no exact match, skip automatic binding, write the report normally from text and command evidence, and state the reason; do not guess just to fill in traffic. Do not claim success if binding fails; keep existing evidence and state the reason for no binding in the report."
	}
	if guidance != "" || has["get_finding_traffic"] || has["update_finding_report"] {
		guidance += findingIDGuidance
	}
	return out, guidance
}

func stripTrafficParameters(schema map[string]any) {
	props, _ := schema["properties"].(map[string]any)
	delete(props, "traffic_refs")
	delete(props, "traffic_ids")
	delete(props, "evidence_hint_id")
	if required, ok := schema["required"].([]any); ok {
		kept := required[:0]
		for _, key := range required {
			if key != "traffic_refs" && key != "evidence_hint_id" {
				kept = append(kept, key)
			}
		}
		schema["required"] = kept
	}
	if hints, ok := props["hints"].(map[string]any); ok {
		if items, ok := hints["items"].(map[string]any); ok {
			stripTrafficParameters(items)
		}
	}
}

// HintTrafficSchema is shared by the task-local and cross-task hint tools.
func HintTrafficSchema() map[string]any {
	return map[string]any{"type": "array", "description": "Optional: verified traffic references that correspond to specific findings in this hint, in order; after handoff, report_finding can pass evidence_hint_id to carry these references.", "items": obj(map[string]any{"traffic_id": str("Real traffic ID"), "role": str("baseline / proof / verification / supporting"), "note": str("What conclusion this traffic supports")}, "traffic_id")}
}

func (t *ToolSet) findingRefsFromHint(hintID int64, explicit []db.TrafficRef) ([]db.TrafficRef, error) {
	if hintID <= 0 {
		return db.NormalizeTrafficRefs(explicit)
	}
	n, err := t.ts.GetNode(hintID) // local store only: inherited hints cannot supply evidence
	if err != nil {
		return nil, err
	}
	if n == nil || n.Kind != db.KindHint {
		return nil, fmt.Errorf("evidence_hint_id=%d must be a hint node of this task (inherited hints cannot be used directly for binding)", hintID)
	}
	var payload struct {
		Refs []db.TrafficRef `json:"traffic_refs"`
	}
	if err := json.Unmarshal(n.Payload, &payload); err != nil {
		return nil, err
	}
	return db.NormalizeTrafficRefs(append(append([]db.TrafficRef{}, explicit...), payload.Refs...))
}
