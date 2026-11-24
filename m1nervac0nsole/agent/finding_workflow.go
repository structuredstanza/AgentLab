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
			note = "\nPreserve the existing verification record's reference, the relevant non-sensitive observation, and the purposes of any traffic IDs so the report agent can check the evidence without repeating the action. Explicit immediate binding is optional via verified traffic_refs or evidence_hint_id. Invalid references reject the report; TCP and packet-less findings do not need them. The returned finding_id is the independent record ID and finding_node_id is the exploration node ID."
		case "add_hint", "add_task_hint":
			note = "\nWhen handing off a confirmed vulnerability, keep verified traffic IDs, purpose, description and order in traffic_refs, and identify the claim they support. Do not forward runnable payloads or ask another agent to repeat blocked work. Mark anything the records do not support as unverified."
		case "get_finding_traffic", "bind_finding_traffic", "list_findings", "list_task_findings", "node_detail", "get_task_node_detail", "update_finding_report":
			note = findingIDGuidance
		}
		if note != "" {
			out[i] = DecorateTool(tool, tool.Description()+note, tool.InputSchema())
		}
	}
	guidance := ""
	if has["report_finding"] || has["add_task_hint"] || has["add_hint"] {
		guidance = "\n\n**Traffic evidence handoff (optional)**: The reporting agent can verify and bind existing evidence before writing a report. Preserve the exact verification record, relevant non-sensitive observations, and traffic IDs and their purposes; include intent_id if available for attribution. Auto or Planner may preserve verified references when reporting an authorized task's evidence. add_hint / add_task_hint accept traffic_refs; report_finding accepts traffic_refs or evidence_hint_id for explicit binding. For TCP or packet-less cases, cite the relevant existing evidence without binding. Do not guess IDs, paste executable exploits, or repeat a probe to fill a gap."
		if has["add_task_hint"] && !has["add_hint"] {
			guidance += "\nWhen platform chat has no task context, do not call report_finding directly. If explicitly authorized, share verified evidence with its existing matching task via add_task_hint and verify the result with list_task_findings. Do not use a handoff to get around a refusal."
		}
		if has["prove_goal"] || has["goal_met"] {
			guidance += "\nBefore judging the goal complete, finish reporting or handing off the evidence already collected for this work. Do not end the task or cancel Workers just because a text finding is registered while evidence handoff is incomplete; for packet-less cases, do not require waiting or force a capture."
		}
	}
	if has["update_finding_report"] && has["bind_finding_traffic"] && has["get_finding_traffic"] {
		guidance += "\n\n**Auto-link traffic before report (enabled)**: Review only existing records for the triggered finding. Obtain the standalone finding_id and exploration finding_node_id from the return JSON or the finding details. Read underlying execution and evidence records. For HTTP, if traffic tools are available, prefer handed-off IDs or use traffic_search to find candidates; inspect each with traffic_get and check that the recorded content and task attribution actually support the claim. Domain, time, a digest or a binding version alone does not validate a citation. Bind only relevant records with bind_finding_traffic(finding_id, traffic_refs), choosing baseline / proof / verification / supporting and stating each purpose. Do not re-probe. After a successful bind, reread get_finding_traffic and pass the actual evidence_version to update_finding_report, whose finding_id parameter takes finding_node_id. Do not append existing bindings again. If no exact record was captured or binding is unavailable or fails, cite other existing evidence only where it supports the claim and state the gap; do not guess references or report binding success."
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
