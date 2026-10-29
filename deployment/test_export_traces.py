"""Behavioral tests for export_traces.

All fixtures are synthetic bodies written inline in this file and copied into a
temporary snapshot directory. No deployment data is read.

Run: cd deployment && python -m unittest test_export_traces
"""

import hashlib
import contextlib
import json
import os
import shutil
import stat
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import export_traces as et  # noqa: E402

USAGE = {"input_tokens": 10, "output_tokens": 5, "cache_read_tokens": 0, "cache_write_tokens": 0}

BASH_SCHEMA = {
    "type": "object",
    "properties": {"cmd": {"type": "string"}},
    "required": ["cmd"],
}
BASH_WIRE_TOOL = {"name": "bash", "description": "Run a shell command", "input_schema": BASH_SCHEMA}


def _sse_named(events):
    return "".join(f"event: {name}\ndata: {json.dumps(obj)}\n\n" for name, obj in events)


def _sse_data(frames):
    return "".join(f"data: {json.dumps(obj)}\n\n" for obj in frames) + "data: [DONE]\n\n"


def _default_request():
    return {
        "system": ["sys one", "sys two"],
        "messages": [{"role": "user", "content": [{"type": "text", "text": "hi"}]}],
        "max_tokens": 100,
        "tools": ["bash"],
        "tools_count": 1,
    }


def _default_wire(req):
    """Wire body in the shape the provider received: tool schemas, not names."""
    offered = set(req.get("tools") or [])
    wire = {"model": "m", "max_tokens": req.get("max_tokens"), "messages": req.get("messages", [])}
    tools = [t for t in [BASH_WIRE_TOOL] if t["name"] in offered]
    if tools:
        wire["tools"] = tools
    return json.dumps(wire)


def _record(rid, raw_response, text="", stop="end_turn", thinking=None, request=None, status="ok", error="", wire=None, profile="p"):
    req = request or _default_request()
    resp = {"text": text, "stop_reason": stop, "usage": USAGE}
    if thinking:
        resp["thinking"] = thinking
    return {
        "id": rid,
        "ts": "2026-01-01T00:00:00Z",
        "model": "m",
        "profile_name": profile,
        "session_id": "s",
        "task_id": "t",
        "worker": "w",
        "latency_ms": 5,
        "input_tokens": 10,
        "output_tokens": 5,
        "cache_read": 0,
        "cache_write": 0,
        "status": status,
        "error": error,
        "request_body": json.dumps(req),
        "response_body": json.dumps(resp),
        "raw_request": _default_wire(req) if wire is None else wire,
        "raw_response": raw_response,
    }


def _jsonl(path):
    with open(path, encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


class ExportTest(unittest.TestCase):
    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.raw = os.path.join(tmp.name, "snapshot")
        self.out = os.path.join(tmp.name, "training")
        os.mkdir(self.raw)

    def _export(self, items):
        lines = [i if isinstance(i, str) else json.dumps(i) for i in items]
        with open(os.path.join(self.raw, et.RECORDS_FILE), "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + ("\n" if lines else ""))
        counts = et.export(self.raw, self.out)
        train = _jsonl(os.path.join(self.out, et.TRAIN_FILE))
        rejects = _jsonl(os.path.join(self.raw, et.REJECTS_FILE))
        return counts, train, rejects

    @staticmethod
    def _target(sample):
        return sample["messages"][-1]

    def _sidecar(self):
        return _jsonl(os.path.join(self.raw, et.REASONING_FILE))

    def _write_provenance(self, text):
        with open(os.path.join(self.raw, et.PROVENANCE_FILE), "w", encoding="utf-8") as f:
            f.write(text)


class ToolAndReasoningNormalization(ExportTest):
    def test_anthropic_json_tool_call(self):
        raw = json.dumps(
            {
                "content": [
                    {"type": "text", "text": "Checking"},
                    {"type": "tool_use", "id": "tu1", "name": "bash", "input": {"cmd": "ls"}},
                ],
                "stop_reason": "tool_use",
            }
        )
        counts, train, rejects = self._export([_record("a1", raw, text="Checking", stop="tool_use")])
        self.assertEqual(counts["exported"], 1)
        self.assertEqual(rejects, [])
        sample = train[0]
        self.assertEqual(sample["messages"][0], {"role": "system", "content": "sys one\n\nsys two"})
        target = self._target(sample)
        self.assertEqual(target["role"], "assistant")
        self.assertEqual(target["content"], "Checking")
        call = target["tool_calls"][0]
        self.assertEqual(call["id"], "tu1")
        self.assertEqual(call["function"]["name"], "bash")
        self.assertEqual(json.loads(call["function"]["arguments"]), {"cmd": "ls"})
        self.assertEqual(sample["metadata"]["tools_called"], ["bash"])

    def test_anthropic_sse_thinking_split_tool_input_and_signature_not_exported(self):
        events = [
            ("message_start", {"type": "message_start", "message": {}}),
            ("content_block_start", {"type": "content_block_start", "index": 0, "content_block": {"type": "thinking", "thinking": ""}}),
            ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "Let me "}}),
            ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "thinking_delta", "thinking": "think"}}),
            ("content_block_delta", {"type": "content_block_delta", "index": 0, "delta": {"type": "signature_delta", "signature": "SIGSECRETVALUE"}}),
            ("content_block_stop", {"type": "content_block_stop", "index": 0}),
            ("content_block_start", {"type": "content_block_start", "index": 1, "content_block": {"type": "text", "text": ""}}),
            ("content_block_delta", {"type": "content_block_delta", "index": 1, "delta": {"type": "text_delta", "text": "Reading"}}),
            ("content_block_stop", {"type": "content_block_stop", "index": 1}),
            ("content_block_start", {"type": "content_block_start", "index": 2, "content_block": {"type": "tool_use", "id": "tu2", "name": "bash", "input": {}}}),
            ("content_block_delta", {"type": "content_block_delta", "index": 2, "delta": {"type": "input_json_delta", "partial_json": '{"cm'}}),
            ("content_block_delta", {"type": "content_block_delta", "index": 2, "delta": {"type": "input_json_delta", "partial_json": 'd":"ls"}'}}),
            ("content_block_stop", {"type": "content_block_stop", "index": 2}),
            ("message_delta", {"type": "message_delta", "delta": {"stop_reason": "tool_use"}}),
            ("message_stop", {"type": "message_stop"}),
        ]
        rec = _record("a2", _sse_named(events), text="Reading", stop="tool_use", thinking="Let me think")
        counts, train, rejects = self._export([rec])
        self.assertEqual(counts["exported"], 1, rejects)
        target = self._target(train[0])
        self.assertEqual(target["reasoning"], "Let me think")
        self.assertEqual(target["content"], "Reading")
        self.assertEqual(json.loads(target["tool_calls"][0]["function"]["arguments"]), {"cmd": "ls"})
        self.assertEqual(train[0]["metadata"]["reasoning_source"], "explicit")
        self.assertFalse(train[0]["metadata"]["reasoning_opaque"])
        with open(os.path.join(self.out, et.TRAIN_FILE), encoding="utf-8") as f:
            self.assertNotIn("SIGSECRETVALUE", f.read())
        self.assertEqual(train[0]["metadata"]["reasoning_kind"], "anthropic_thinking")
        self.assertEqual(train[0]["metadata"]["reasoning_fields"], ["anthropic.signature", "anthropic.thinking"])
        side = self._sidecar()
        self.assertEqual(len(side), 2)
        self.assertEqual(
            [(b["kind"], b["text"]) for b in side if b["kind"] == "anthropic_thinking"],
            [("anthropic_thinking", "Let me think")],
        )
        self.assertEqual(
            [(b["field"], b["bytes"], b["sha256"]) for b in side if b["kind"] == "opaque"],
            [("anthropic.signature", 14, hashlib.sha256(b"SIGSECRETVALUE").hexdigest())],
        )
        with open(os.path.join(self.raw, et.REASONING_FILE), encoding="utf-8") as f:
            self.assertNotIn("SIGSECRETVALUE", f.read())

    def test_signature_only_thinking_is_flagged_not_text(self):
        raw = json.dumps(
            {
                "content": [
                    {"type": "thinking", "thinking": "", "signature": "ENC"},
                    {"type": "text", "text": "Done"},
                ],
                "stop_reason": "end_turn",
            }
        )
        counts, train, rejects = self._export([_record("a3", raw, text="Done")])
        self.assertEqual(counts["exported"], 1, rejects)
        target = self._target(train[0])
        self.assertNotIn("reasoning", target)
        self.assertEqual(train[0]["metadata"]["reasoning_source"], "none")
        self.assertTrue(train[0]["metadata"]["reasoning_opaque"])
        self.assertEqual(train[0]["metadata"]["reasoning_kind"], "opaque")
        self.assertEqual(train[0]["metadata"]["reasoning_fields"], ["anthropic.signature"])
        self.assertEqual(
            [(b["kind"], b["field"], b["bytes"], b["sha256"]) for b in self._sidecar()],
            [("opaque", "anthropic.signature", 3, hashlib.sha256(b"ENC").hexdigest())],
        )

    def test_openai_chat_sse_split_arguments_and_reasoning(self):
        frames = [
            {"choices": [{"delta": {"role": "assistant"}}]},
            {"choices": [{"delta": {"reasoning_content": "Hmm"}}]},
            {"choices": [{"delta": {"content": "Ok"}}]},
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_1", "type": "function", "function": {"name": "bash", "arguments": '{"c'}}]}}]},
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "function": {"arguments": 'md":"ls"}'}}]}}]},
            {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]},
        ]
        rec = _record("o1", _sse_data(frames), text="Ok", stop="tool_use", thinking="Hmm")
        counts, train, rejects = self._export([rec])
        self.assertEqual(counts["exported"], 1, rejects)
        target = self._target(train[0])
        self.assertEqual(target["reasoning"], "Hmm")
        self.assertEqual(target["content"], "Ok")
        call = target["tool_calls"][0]
        self.assertEqual(call["id"], "call_1")
        self.assertEqual(call["function"]["name"], "bash")
        self.assertEqual(json.loads(call["function"]["arguments"]), {"cmd": "ls"})
        self.assertEqual(train[0]["metadata"]["reasoning_kind"], "unclassified")
        self.assertEqual(train[0]["metadata"]["model_backend"], "unknown")
        self.assertEqual(
            [(b["kind"], b["field"], b["text"]) for b in self._sidecar()],
            [("unclassified", "openai.reasoning_content", "Hmm")],
        )

    def test_responses_json_reasoning_summary_and_function_call(self):
        raw = json.dumps(
            {
                "output": [
                    {"type": "reasoning", "summary": [{"type": "summary_text", "text": "plan"}]},
                    {"type": "function_call", "call_id": "c1", "name": "bash", "arguments": '{"cmd": "ls"}'},
                ]
            }
        )
        rec = _record("r1", raw, text="", stop="tool_use", thinking="plan")
        counts, train, rejects = self._export([rec])
        self.assertEqual(counts["exported"], 1, rejects)
        target = self._target(train[0])
        self.assertEqual(target["reasoning"], "plan")
        self.assertEqual(json.loads(target["tool_calls"][0]["function"]["arguments"]), {"cmd": "ls"})
        self.assertEqual(train[0]["metadata"]["reasoning_kind"], "summary")
        self.assertEqual(train[0]["metadata"]["reasoning_fields"], ["responses.summary"])

    def test_retry_uses_last_successful_attempt(self):
        ok = json.dumps({"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"})
        raw = (
            "===== attempt 1/2 \u2014 HTTP 429 =====\n"
            '{"error": "slow"}\n'
            "===== attempt 2/2 \u2014 HTTP 200 =====\n"
            + ok
            + "\n"
        )
        counts, train, rejects = self._export([_record("retry1", raw, text="ok")])
        self.assertEqual(counts["exported"], 1, rejects)
        self.assertEqual(self._target(train[0])["content"], "ok")


class ToolSchemaAndHistory(ExportTest):
    OK_RESPONSE = json.dumps({"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"})

    def test_wire_tool_schema_is_preserved_in_openai_function_shape(self):
        anthropic_rec = _record("s1", self.OK_RESPONSE, text="ok")
        openai_wire = json.dumps(
            {
                "model": "m",
                "messages": [],
                "tools": [
                    {
                        "type": "function",
                        "function": {"name": "bash", "description": "Run a shell command", "parameters": BASH_SCHEMA},
                    }
                ],
            }
        )
        openai_rec = _record("s2", self.OK_RESPONSE, text="ok", wire=openai_wire)
        counts, train, rejects = self._export([anthropic_rec, openai_rec])
        self.assertEqual(counts["exported"], 2, rejects)
        expected = [
            {
                "type": "function",
                "function": {"name": "bash", "description": "Run a shell command", "parameters": BASH_SCHEMA},
            }
        ]
        self.assertEqual(train[0]["tools"], expected)
        self.assertEqual(train[1]["tools"], expected)
        self.assertEqual(train[0]["metadata"]["tools_schema_source"], "raw_request")
        self.assertEqual(train[0]["metadata"]["tools_offered"], ["bash"])

    def test_no_schema_when_wire_body_carries_no_tools(self):
        wire = json.dumps({"model": "m", "messages": []})
        counts, train, rejects = self._export([_record("s3", self.OK_RESPONSE, text="ok", wire=wire)])
        self.assertEqual(counts["exported"], 1, rejects)
        self.assertNotIn("tools", train[0])
        self.assertEqual(train[0]["metadata"]["tools_schema_source"], "none")

    def test_unknown_wire_tool_shape_is_rejected(self):
        wire = json.dumps({"model": "m", "messages": [], "tools": [{"type": "web_search_20250305", "name": "web_search"}]})
        rec = _record("s4", self.OK_RESPONSE, text="ok", request={**_default_request(), "tools": ["web_search"]}, wire=wire)
        counts, train, rejects = self._export([rec])
        self.assertEqual(train, [])
        self.assertEqual(rejects[0]["reason"], "unknown_tool_schema_format")
        self.assertEqual(rejects[0]["record"], rec)

    def test_history_tool_results_are_associated_by_id(self):
        history = [
            {"role": "user", "content": [{"type": "text", "text": "list files"}]},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "u1", "name": "bash", "input": {"cmd": "ls"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "u1", "content": [{"type": "text", "text": "a.txt"}]}]},
        ]
        good = _record("h1", self.OK_RESPONSE, text="ok", request={**_default_request(), "messages": history})
        bad_history = json.loads(json.dumps(history))
        bad_history[2]["content"][0]["tool_use_id"] = "zzz"  # answers no open call
        bad = _record("h2", self.OK_RESPONSE, text="ok", request={**_default_request(), "messages": bad_history})
        unanswered = json.loads(json.dumps(history[:2]))  # tool_use with no result
        unanswered_rec = _record("h3", self.OK_RESPONSE, text="ok", request={**_default_request(), "messages": unanswered})

        counts, train, rejects = self._export([good, bad, unanswered_rec])
        self.assertEqual(counts["exported"], 1, rejects)
        messages = train[0]["messages"]
        self.assertEqual([m["role"] for m in messages], ["system", "user", "assistant", "tool", "assistant"])
        call_ids = [c["id"] for c in messages[2]["tool_calls"]]
        self.assertEqual(call_ids, ["u1"])
        self.assertEqual(messages[3], {"role": "tool", "tool_call_id": call_ids[0], "content": "a.txt"})
        reasons = {r["id"]: r["reason"] for r in rejects}
        self.assertEqual(reasons, {"h2": "unmatched_tool_result", "h3": "unmatched_tool_call"})
        self.assertEqual(rejects[0]["record"], bad)


class Rejections(ExportTest):
    def test_failed_status_rejected_with_original_record(self):
        rec = _record("e1", "", status="error", error="boom")
        counts, train, rejects = self._export([rec])
        self.assertEqual(train, [])
        self.assertEqual(counts["rejected"], 1)
        self.assertEqual(rejects[0]["reason"], "status_error")
        self.assertEqual(rejects[0]["record"], rec)

    def test_missing_raw_response_rejected(self):
        rec = _record("m1", "", text="x")
        counts, train, rejects = self._export([rec])
        self.assertEqual(train, [])
        self.assertEqual(rejects[0]["reason"], "missing_raw_response")
        self.assertEqual(rejects[0]["record"], rec)

    def test_response_mismatch_rejected(self):
        raw = json.dumps({"content": [{"type": "text", "text": "Real"}], "stop_reason": "end_turn"})
        rec = _record("x1", raw, text="Different")
        counts, train, rejects = self._export([rec])
        self.assertEqual(train, [])
        self.assertEqual(rejects[0]["reason"], "response_mismatch")
        self.assertEqual(rejects[0]["record"], rec)

    def test_truncated_max_tokens_rejected(self):
        raw = json.dumps({"content": [{"type": "text", "text": "cut"}], "stop_reason": "max_tokens"})
        rec = _record("t1", raw, text="cut", stop="max_tokens")
        counts, train, rejects = self._export([rec])
        self.assertEqual(train, [])
        self.assertEqual(rejects[0]["reason"], "truncated_max_tokens")
        self.assertEqual(rejects[0]["record"], rec)

    def test_malformed_tool_arguments_rejected(self):
        frames = [
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "c", "function": {"name": "bash", "arguments": '{"cmd":'}}]}}]},
            {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]},
        ]
        rec = _record("p1", _sse_data(frames), stop="tool_use")
        counts, train, rejects = self._export([rec])
        self.assertEqual(train, [])
        self.assertEqual(rejects[0]["reason"], "malformed_tool_arguments")

    def test_unparseable_line_rejected_verbatim(self):
        counts, train, rejects = self._export(["{not json"])
        self.assertEqual(counts["records"], 1)
        self.assertEqual(train, [])
        self.assertEqual(rejects[0]["reason"], "malformed_record")
        self.assertEqual(rejects[0]["record"], "{not json")
        self.assertEqual(
            [(b["kind"], b["id"], b["reject"], b["accepted"], b["line"]) for b in self._sidecar()],
            [("not_recovered", None, "malformed_record", False, 1)],
        )


class Redaction(ExportTest):
    def test_train_is_redacted_and_snapshot_is_untouched(self):
        token = "sk-abcdefghijklmnop1234"
        req = {
            "system": [],
            "messages": [{"role": "user", "content": [{"type": "text", "text": f"use {token} now"}]}],
            "max_tokens": 100,
        }
        raw_resp = json.dumps({"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"})
        rec = _record("secret1", raw_resp, text="ok", request=req)
        records_path = os.path.join(self.raw, et.RECORDS_FILE)
        counts, train, rejects = self._export([rec])
        self.assertEqual(counts["exported"], 1, rejects)
        with open(os.path.join(self.out, et.TRAIN_FILE), encoding="utf-8") as f:
            train_text = f.read()
        self.assertNotIn(token, train_text)
        self.assertIn("[REDACTED]", train_text)
        with open(records_path, encoding="utf-8") as f:
            self.assertIn(token, f.read())  # snapshot keeps the wire bytes


class Layout(ExportTest):
    def test_training_dir_holds_only_train_and_notice_and_permissions(self):
        raw_resp = json.dumps({"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"})
        counts, train, rejects = self._export([_record("p1", raw_resp, text="ok"), _record("p2", "", status="error")])
        self.assertEqual(counts["records"], 2)
        self.assertEqual(counts["exported"], 1)
        self.assertEqual(counts["rejected"], 1)
        self.assertEqual(counts["rejects_by_reason"], {"status_error": 1})
        self.assertEqual(counts["rejects_file"], os.path.join(self.raw, et.REJECTS_FILE))

        self.assertEqual(sorted(os.listdir(self.out)), [et.NOTICE_FILE, et.TRAIN_FILE])

        def mode(p):
            return stat.S_IMODE(os.stat(p).st_mode)

        self.assertEqual(mode(self.out), 0o700)
        self.assertEqual(mode(os.path.join(self.out, et.TRAIN_FILE)), 0o600)
        self.assertEqual(mode(os.path.join(self.out, et.NOTICE_FILE)), 0o600)
        self.assertEqual(mode(os.path.join(self.raw, et.REJECTS_FILE)), 0o600)
        self.assertEqual(mode(os.path.join(self.raw, et.REASONING_FILE)), 0o600)


class EmptyInput(ExportTest):
    def test_empty_records_file_exports_nothing(self):
        counts, train, rejects = self._export([])
        self.assertEqual(counts["records"], 0)
        self.assertEqual(counts["exported"], 0)
        self.assertEqual(counts["rejected"], 0)
        self.assertEqual(train, [])
        self.assertEqual(rejects, [])
        self.assertTrue(os.path.isfile(os.path.join(self.out, et.TRAIN_FILE)))

    def test_missing_records_file_raises(self):
        with self.assertRaises(FileNotFoundError):
            et.export(self.raw, self.out)


class ToolArgumentRedaction(ExportTest):
    def test_arguments_json_stays_valid_after_redaction(self):
        args = json.dumps({"command": 'curl -H "token: abcdefgh"'})
        raw = json.dumps(
            {
                "choices": [
                    {
                        "message": {
                            "tool_calls": [
                                {"id": "c1", "type": "function", "function": {"name": "bash", "arguments": args}}
                            ]
                        },
                        "finish_reason": "tool_calls",
                    }
                ]
            }
        )
        counts, train, rejects = self._export([_record("r1", raw, stop="tool_use")])
        self.assertEqual(counts["exported"], 1)
        self.assertEqual(rejects, [])
        arguments = self._target(train[0])["tool_calls"][0]["function"]["arguments"]
        self.assertEqual(json.loads(arguments), {"command": 'curl -H "token: [REDACTED]"'})
        with open(os.path.join(self.out, et.TRAIN_FILE), encoding="utf-8") as f:
            self.assertNotIn("abcdefgh", f.read())


class MalformedProviderShape(ExportTest):
    def test_malformed_records_are_rejected_and_batch_continues(self):
        bad_openai = json.dumps(
            {"choices": [{"message": {"tool_calls": [{"id": "c", "function": "not-an-object"}]}, "finish_reason": "tool_calls"}]}
        )
        bad_anthropic = json.dumps({"content": [{"type": "text", "text": 5}], "stop_reason": "end_turn"})
        good = json.dumps({"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"})
        bad1 = _record("bad1", bad_openai, stop="tool_use")
        bad2 = _record("bad2", bad_anthropic)
        ok = _record("ok1", good, text="ok")
        counts, train, rejects = self._export([bad1, ok, bad2])
        self.assertEqual(counts["exported"], 1)
        self.assertEqual(self._target(train[0])["content"], "ok")
        self.assertEqual([r["reason"] for r in rejects], ["malformed_provider_record", "malformed_provider_record"])
        self.assertEqual([r["record"] for r in rejects], [bad1, bad2])


class ResponsesStreamContract(ExportTest):
    def test_responses_sse_text_reasoning_and_function_call(self):
        events = [
            ("response.created", {"type": "response.created", "response": {"status": "in_progress"}}),
            ("response.output_item.added", {"type": "response.output_item.added", "output_index": 0, "item": {"type": "reasoning", "id": "rs_1", "summary": []}}),
            ("response.reasoning_summary_text.delta", {"type": "response.reasoning_summary_text.delta", "output_index": 0, "delta": "thinking"}),
            ("response.output_item.done", {"type": "response.output_item.done", "output_index": 0, "item": {"type": "reasoning", "id": "rs_1", "summary": [{"type": "summary_text", "text": "thinking"}]}}),
            ("response.output_item.added", {"type": "response.output_item.added", "output_index": 1, "item": {"type": "message", "id": "msg_1", "role": "assistant", "content": []}}),
            ("response.output_text.delta", {"type": "response.output_text.delta", "output_index": 1, "delta": "Hello "}),
            ("response.output_text.delta", {"type": "response.output_text.delta", "output_index": 1, "delta": "there"}),
            ("response.output_item.added", {"type": "response.output_item.added", "output_index": 2, "item": {"type": "function_call", "id": "fc_1", "call_id": "call_1", "name": "Read", "arguments": ""}}),
            ("response.function_call_arguments.delta", {"type": "response.function_call_arguments.delta", "output_index": 2, "delta": '{"file_'}),
            ("response.function_call_arguments.delta", {"type": "response.function_call_arguments.delta", "output_index": 2, "delta": 'path":"a"}'}),
            ("response.function_call_arguments.done", {"type": "response.function_call_arguments.done", "output_index": 2, "arguments": '{"file_path":"a"}'}),
            ("response.completed", {"type": "response.completed", "response": {"status": "completed", "output": [], "usage": {"input_tokens": 10, "output_tokens": 5}}}),
        ]
        wire = json.dumps(
            {"model": "m", "messages": [], "tools": [{"name": "Read", "description": "read a file", "input_schema": BASH_SCHEMA}]}
        )
        request = {**_default_request(), "tools": ["Read"], "tools_count": 1}
        # norma's streaming accumulator records end_turn for response.completed even after a function call;
        # the recorded stop_reason is what the exporter checks against, so it is end_turn here.
        rec = _record("rs1", _sse_named(events), text="Hello there", stop="end_turn", thinking="thinking", request=request, wire=wire)
        counts, train, rejects = self._export([rec])
        self.assertEqual(counts["exported"], 1, rejects)
        target = self._target(train[0])
        self.assertEqual(target["content"], "Hello there")
        call = target["tool_calls"][0]
        self.assertEqual(call["id"], "call_1")
        self.assertEqual(call["function"]["name"], "Read")
        self.assertEqual(json.loads(call["function"]["arguments"]), {"file_path": "a"})
        self.assertEqual(train[0]["metadata"]["tools_called"], ["Read"])
        self.assertEqual(train[0]["metadata"]["reasoning_kind"], "summary")
        self.assertEqual(train[0]["metadata"]["reasoning_fields"], ["responses.summary"])


class ReasoningProvenance(ExportTest):
    BONSAI = "AgentLab Bonsai Thinking"
    MAPPING = {"reasoning_profiles": {BONSAI: {"model_backend": "llama.cpp", "provenance": "open-weight-local"}}}

    @staticmethod
    def _chat(message, **extra):
        return json.dumps({"choices": [{"message": message, "finish_reason": "stop"}], **extra})

    def test_unmapped_chat_reasoning_is_unclassified(self):
        counts, train, rejects = self._export(
            [_record("a", self._chat({"content": "ok", "reasoning_content": "Hmm"}), text="ok", thinking="Hmm")]
        )
        self.assertEqual(counts["exported"], 1, rejects)
        meta = train[0]["metadata"]
        self.assertEqual(meta["reasoning_kind"], "unclassified")
        self.assertEqual((meta["model_backend"], meta["provenance"]), ("unknown", "unknown"))
        self.assertEqual(
            [(b["kind"], b["field"], b["text"], b["model_backend"], b["provenance"]) for b in self._sidecar()],
            [("unclassified", "openai.reasoning_content", "Hmm", "unknown", "unknown")],
        )

    def test_mapped_profile_reasoning_is_raw_with_provenance(self):
        self._write_provenance(json.dumps(self.MAPPING))
        rec = _record("b1", self._chat({"content": "ok", "reasoning_content": "Hmm"}), text="ok", thinking="Hmm", profile=self.BONSAI)
        counts, train, rejects = self._export([rec])
        self.assertEqual(counts["exported"], 1, rejects)
        self.assertEqual(train[0]["metadata"]["reasoning_kind"], "raw")
        self.assertEqual(
            [(b["kind"], b["field"], b["text"], b["model_backend"], b["provenance"]) for b in self._sidecar()],
            [("raw", "openai.reasoning_content", "Hmm", "llama.cpp", "open-weight-local")],
        )

    def test_reasoning_field_is_unclassified_unless_profile_is_mapped(self):
        self._write_provenance(json.dumps(self.MAPPING))
        rows = [
            _record("v1", self._chat({"content": "ok", "reasoning": "Plan"}), text="ok", thinking="Plan"),
            _record("v2", self._chat({"content": "ok", "reasoning": "Plan"}), text="ok", thinking="Plan", profile=self.BONSAI),
        ]
        counts, train, rejects = self._export(rows)
        self.assertEqual(counts["exported"], 2, rejects)
        self.assertEqual([(b["id"], b["kind"]) for b in self._sidecar()], [("v1", "unclassified"), ("v2", "raw")])

    def test_chat_stream_takes_first_nonempty_reasoning_key_per_delta(self):
        frames = [
            {"choices": [{"delta": {"role": "assistant"}}]},
            {"choices": [{"delta": {"reasoning": "A", "reasoning_content": "B"}}]},
            {"choices": [{"delta": {"reasoning_text": "C"}}]},
            {"choices": [{"delta": {"tool_calls": [{"index": 0, "id": "call_1", "type": "function", "function": {"name": "bash", "arguments": '{"cmd": "ls"}'}}]}}]},
            {"choices": [{"delta": {}, "finish_reason": "tool_calls"}]},
        ]
        counts, train, rejects = self._export([_record("d1", _sse_data(frames), text="", stop="tool_use", thinking="BC")])
        self.assertEqual(counts["exported"], 1, rejects)
        self.assertEqual(self._target(train[0])["reasoning"], "BC")
        self.assertEqual(train[0]["metadata"]["reasoning_fields"], ["openai.reasoning_content", "openai.reasoning_text"])
        self.assertEqual([b["text"] for b in self._sidecar() if b["kind"] != "unselected"], ["B", "C"])

    def test_responses_summary_and_reasoning_text_keep_distinct_fields(self):
        raw = json.dumps(
            {
                "output": [
                    {
                        "type": "reasoning",
                        "summary": [{"type": "summary_text", "text": "plan"}],
                        "content": [{"type": "reasoning_text", "text": "raw"}],
                    },
                    {"type": "function_call", "call_id": "c1", "name": "bash", "arguments": '{"cmd": "ls"}'},
                ]
            }
        )
        counts, train, rejects = self._export([_record("e1", raw, text="", stop="tool_use", thinking="planraw")])
        self.assertEqual(counts["exported"], 1, rejects)
        self.assertEqual(self._target(train[0])["reasoning"], "planraw")
        self.assertEqual(train[0]["metadata"]["reasoning_kind"], "mixed")
        self.assertEqual(train[0]["metadata"]["reasoning_fields"], ["responses.reasoning_text", "responses.summary"])
        self.assertEqual(
            sorted((b["field"], b["kind"]) for b in self._sidecar()),
            [("responses.reasoning_text", "unclassified"), ("responses.summary", "summary")],
        )

    def test_redacted_thinking_is_opaque_and_never_exported(self):
        raw = json.dumps(
            {"content": [{"type": "redacted_thinking", "data": "BLOBSECRET"}, {"type": "text", "text": "Done"}], "stop_reason": "end_turn"}
        )
        counts, train, rejects = self._export([_record("f1", raw, text="Done")])
        self.assertEqual(counts["exported"], 1, rejects)
        self.assertEqual(train[0]["metadata"]["reasoning_kind"], "opaque")
        self.assertEqual(train[0]["metadata"]["reasoning_fields"], ["anthropic.redacted_thinking"])
        self.assertEqual(
            [(b["kind"], b["field"], b["bytes"], b["sha256"]) for b in self._sidecar()],
            [("opaque", "anthropic.redacted_thinking", 10, hashlib.sha256(b"BLOBSECRET").hexdigest())],
        )
        with open(os.path.join(self.out, et.TRAIN_FILE), encoding="utf-8") as f:
            self.assertNotIn("BLOBSECRET", f.read())
        with open(os.path.join(self.raw, et.REASONING_FILE), encoding="utf-8") as f:
            self.assertNotIn("BLOBSECRET", f.read())

    def test_responses_encrypted_reasoning_is_opaque(self):
        events = [
            ("response.output_item.added", {"type": "response.output_item.added", "output_index": 0, "item": {"type": "reasoning", "id": "rs_2", "summary": []}}),
            ("response.output_item.done", {"type": "response.output_item.done", "output_index": 0, "item": {"type": "reasoning", "id": "rs_2", "summary": [], "encrypted_content": "ENCBLOB"}}),
            ("response.output_item.added", {"type": "response.output_item.added", "output_index": 1, "item": {"type": "message", "id": "msg_2", "role": "assistant", "content": []}}),
            ("response.output_text.delta", {"type": "response.output_text.delta", "output_index": 1, "delta": "Hi"}),
            ("response.completed", {"type": "response.completed", "response": {"status": "completed", "output": [], "usage": {"input_tokens": 1, "output_tokens": 1}}}),
        ]
        counts, train, rejects = self._export([_record("g1", _sse_named(events), text="Hi")])
        self.assertEqual(counts["exported"], 1, rejects)
        self.assertEqual(train[0]["metadata"]["reasoning_kind"], "opaque")
        self.assertEqual(train[0]["metadata"]["reasoning_fields"], ["responses.encrypted_content"])
        self.assertEqual(
            [(b["kind"], b["field"], b["bytes"]) for b in self._sidecar()],
            [("opaque", "responses.encrypted_content", 7)],
        )
        with open(os.path.join(self.out, et.TRAIN_FILE), encoding="utf-8") as f:
            self.assertNotIn("ENCBLOB", f.read())
        with open(os.path.join(self.raw, et.REASONING_FILE), encoding="utf-8") as f:
            self.assertNotIn("ENCBLOB", f.read())

    def test_summarized_display_labels_anthropic_thinking_as_summary(self):
        wire = json.loads(_default_wire(_default_request()))
        wire["thinking"] = {"type": "enabled", "budget_tokens": 1024, "display": "summarized"}
        wire = json.dumps(wire)
        raw = json.dumps({"content": [{"type": "thinking", "thinking": "Plan it"}, {"type": "text", "text": "Done"}], "stop_reason": "end_turn"})
        counts, train, rejects = self._export([_record("h1", raw, text="Done", thinking="Plan it", wire=wire)])
        self.assertEqual(counts["exported"], 1, rejects)
        self.assertEqual(train[0]["metadata"]["reasoning_kind"], "summary")
        self.assertEqual(train[0]["metadata"]["reasoning_fields"], ["anthropic.thinking"])
        self.assertEqual([(b["kind"], b["text"]) for b in self._sidecar()], [("summary", "Plan it")])

    def test_reasoning_mismatch_rejects_row_and_keeps_sidecar_line(self):
        raw = json.dumps({"content": [{"type": "thinking", "thinking": "Hidden plan"}, {"type": "text", "text": "Real"}], "stop_reason": "end_turn"})
        counts, train, rejects = self._export([_record("i1", raw, text="Different", thinking="Hidden plan")])
        self.assertEqual(counts["exported"], 0)
        self.assertEqual(train, [])
        self.assertEqual(rejects[0]["reason"], "response_mismatch")
        self.assertEqual(
            [(b["kind"], b["text"], b["accepted"], b["reject"]) for b in self._sidecar()],
            [("anthropic_thinking", "Hidden plan", False, "response_mismatch")],
        )

    def test_unparseable_raw_response_is_not_recovered(self):
        counts, train, rejects = self._export([_record("j1", "not json {")])
        self.assertEqual(counts["exported"], 0)
        self.assertEqual(rejects[0]["reason"], "unknown_provider_format")
        self.assertEqual(
            [(b["kind"], b["field"], b["reject"], b["accepted"]) for b in self._sidecar()],
            [("not_recovered", "", "unknown_provider_format", False)],
        )

    def test_unknown_reasoning_like_key_is_flagged_in_sidecar_only(self):
        counts, train, rejects = self._export([_record("k1", self._chat({"content": "ok", "reasoning_summary_v2": "x"}), text="ok")])
        self.assertEqual(counts["exported"], 1, rejects)
        self.assertNotIn("reasoning", self._target(train[0]))
        self.assertEqual(train[0]["metadata"]["reasoning_kind"], "none")
        self.assertEqual(train[0]["metadata"]["reasoning_fields"], [])
        self.assertEqual(
            [(b["kind"], b["field"], b["bytes"]) for b in self._sidecar()],
            [("unsupported", "body.choices[0].message.reasoning_summary_v2", 3)],
        )

    def test_token_counts_and_tool_input_keys_are_not_flagged(self):
        chat = self._chat({"content": "ok"}, usage={"completion_tokens_details": {"reasoning_tokens": 3}})
        tool = json.dumps(
            {
                "content": [{"type": "tool_use", "id": "tu1", "name": "bash", "input": {"reason": "ls", "cmd": "ls"}}],
                "stop_reason": "tool_use",
            }
        )
        counts, train, rejects = self._export([_record("l1", chat, text="ok"), _record("l2", tool, text="", stop="tool_use")])
        self.assertEqual(counts["exported"], 2, rejects)
        self.assertEqual(self._sidecar(), [])

    def test_malformed_provenance_raises_before_anything_is_written(self):
        for text in ['{"reasoning_profiles": {"p": {"model_backend": "x"}}}', "{not json"]:
            with self.subTest(text=text):
                self._write_provenance(text)
                with self.assertRaises(ValueError):
                    self._export([_record("m1", self._chat({"content": "ok"}), text="ok")])
                self.assertFalse(os.path.exists(os.path.join(self.out, et.TRAIN_FILE)))
                self.assertFalse(os.path.exists(os.path.join(self.raw, et.REASONING_FILE)))

    def test_budget_flag_is_null_unless_observed(self):
        def row(rid, **extra):
            return _record(rid, self._chat({"content": "ok", "reasoning_content": "t"}, **extra), text="ok", thinking="t")

        rows = [
            row("bg1", timings={"reasoning_budget_exhausted": True}),
            row("bg2"),
            row("bg3", timings={"reasoning_budget_exhausted": False}),
        ]
        counts, train, rejects = self._export(rows)
        self.assertEqual(counts["exported"], 3, rejects)
        self.assertEqual([t["metadata"]["reasoning_budget_exhausted"] for t in train], [True, None, False])
        self.assertEqual({b["id"]: b["budget_exhausted"] for b in self._sidecar()}, {"bg1": True, "bg2": None, "bg3": False})

    def test_history_redacted_thinking_is_opaque_and_never_exported(self):
        req = {
            **_default_request(),
            "messages": [
                {"role": "user", "content": [{"type": "text", "text": "hi"}]},
                {"role": "assistant", "content": [{"type": "redacted_thinking", "data": "HISTBLOB"}, {"type": "text", "text": "prev"}]},
                {"role": "user", "content": [{"type": "text", "text": "go"}]},
            ],
        }
        raw = json.dumps({"content": [{"type": "text", "text": "ok"}], "stop_reason": "end_turn"})
        counts, train, rejects = self._export([_record("hi1", raw, text="ok", request=req)])
        self.assertEqual(counts["exported"], 1, rejects)
        with open(os.path.join(self.out, et.TRAIN_FILE), encoding="utf-8") as f:
            self.assertNotIn("HISTBLOB", f.read())
        with open(os.path.join(self.raw, et.REASONING_FILE), encoding="utf-8") as f:
            self.assertNotIn("HISTBLOB", f.read())

    def test_sidecar_is_rewritten_on_each_export(self):
        self._export([_record("w1", self._chat({"content": "ok", "reasoning_content": "a"}), text="ok", thinking="a")])
        self._export([_record("w2", self._chat({"content": "ok", "reasoning_content": "b"}), text="ok", thinking="b")])
        self.assertEqual([b["id"] for b in self._sidecar()], ["w2"])


class GeminiNativeContract(ExportTest):
    def test_nonstream_wrapped_thought_signature_and_function_call(self):
        raw = json.dumps({"response": {"candidates": [{"content": {"role": "model", "parts": [
            {"text": "plan", "thought": True, "thoughtSignature": "SIG_T"},
            {"text": "answer", "thoughtSignature": "SIG_X"},
            {"functionCall": {"name": "Bash", "args": {"command": "ls"}}, "thoughtSignature": "SIG_C"},
        ]}, "finishReason": "STOP"}]}})
        counts, train, rejects = self._export([_record("g1", raw, text="answer", stop="tool_use", thinking="plan")])
        self.assertEqual(counts["exported"], 1, rejects)
        target = self._target(train[0])
        self.assertEqual(target["content"], "answer")
        self.assertEqual(target["tool_calls"][0]["function"]["name"], "Bash")
        self.assertEqual(train[0]["metadata"]["tools_called"], ["Bash"])
        self.assertEqual(train[0]["metadata"]["reasoning_kind"], "summary")
        self.assertNotIn("SIG_C", json.dumps(train))
        self.assertNotIn("SIG_T", json.dumps(train))
        digests = {b["sha256"] for b in self._sidecar() if b["kind"] == "opaque"}
        for sig in ("SIG_T", "SIG_X", "SIG_C"):
            self.assertIn(hashlib.sha256(sig.encode("utf-8")).hexdigest(), digests)

    def test_sse_stream_with_wrapper_keeps_tool_arguments(self):
        frames = [
            {"response": {"candidates": [{"content": {"role": "model", "parts": [{"text": "hmm", "thought": True}]}}]}},
            {"response": {"candidates": [{"content": {"role": "model", "parts": [{"text": "Hi "}]}}]}},
            {"response": {"candidates": [{"content": {"role": "model", "parts": [{"text": "there"}]}}]}},
            {"response": {"candidates": [{"content": {"role": "model", "parts": [{"functionCall": {"name": "Read", "args": {"file_path": "a"}}}]}, "finishReason": "STOP"}]}},
        ]
        rec = _record("g2", _sse_data(frames), text="Hi there", stop="tool_use", thinking="hmm")
        counts, train, rejects = self._export([rec])
        self.assertEqual(counts["exported"], 1, rejects)
        target = self._target(train[0])
        self.assertEqual(target["content"], "Hi there")
        call = target["tool_calls"][0]
        self.assertEqual(json.loads(call["function"]["arguments"]), {"file_path": "a"})
        self.assertEqual(train[0]["metadata"]["tools_called"], ["Read"])

    def test_repeated_function_call_ids_are_made_distinct(self):
        part = {"functionCall": {"name": "Bash", "args": {"command": "ls"}}}
        raw = json.dumps({"response": {"candidates": [{"content": {"role": "model", "parts": [part, part]}, "finishReason": "STOP"}]}})
        counts, train, rejects = self._export([_record("g3", raw, stop="tool_use")])
        self.assertEqual(counts["exported"], 1, rejects)
        ids = [c["id"] for c in self._target(train[0])["tool_calls"]]
        self.assertEqual(len(ids), 2)
        self.assertEqual(len(set(ids)), 2)


def _gemini_wire(names):
    """Gemini wire body (wrapped request) offering the named tools with parametersJsonSchema."""
    decls = [{"name": n, "parametersJsonSchema": BASH_SCHEMA} for n in names]
    body = {"project": "p", "model": "m", "request": {"contents": [], "tools": [{"functionDeclarations": decls}]}, "userAgent": "antigravity", "requestType": "agent"}
    return json.dumps(body)


def _gemini_request(messages, names):
    return {"system": [], "messages": messages, "max_tokens": 100, "tools": list(names), "tools_count": len(names)}


GEMINI_CALL = json.dumps({"candidates": [{"content": {"role": "model", "parts": [{"functionCall": {"name": "Bash", "args": {"command": "echo hi"}}}]}, "finishReason": "STOP"}]})


class GeminiNativeTools(ExportTest):
    def test_wrapped_native_tool_declarations_are_accepted(self):
        req = _gemini_request([{"role": "user", "content": [{"type": "text", "text": "hi"}]}], ["Bash"])
        counts, train, rejects = self._export([_record("t1", GEMINI_CALL, stop="tool_use", request=req, wire=_gemini_wire(["Bash"]))])
        self.assertEqual(counts["exported"], 1, rejects)
        self.assertEqual(rejects, [])
        self.assertEqual(self._target(train[0])["tool_calls"][0]["id"], "Bash-1")

    def test_native_tool_name_mismatch_is_rejected(self):
        req = _gemini_request([{"role": "user", "content": [{"type": "text", "text": "hi"}]}], ["bash"])
        counts, train, rejects = self._export([_record("t2", GEMINI_CALL, stop="tool_use", request=req, wire=_gemini_wire(["Bash"]))])
        self.assertEqual(train, [])
        self.assertEqual(rejects[0]["reason"], "tool_schema_mismatch")

    def test_history_tool_calls_seed_generated_ids(self):
        history = [
            {"role": "user", "content": [{"type": "text", "text": "list"}]},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "Bash-1", "name": "Bash", "input": {"command": "ls"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "Bash-1", "content": [{"type": "text", "text": "a"}]}]},
            {"role": "assistant", "content": [{"type": "tool_use", "id": "Bash-2", "name": "Bash", "input": {"command": "pwd"}}]},
            {"role": "user", "content": [{"type": "tool_result", "tool_use_id": "Bash-2", "content": [{"type": "text", "text": "/x"}]}]},
        ]
        req = _gemini_request(history, ["Bash"])
        generated = _record("h1", GEMINI_CALL, stop="tool_use", request=req, wire=_gemini_wire(["Bash"]))
        explicit_raw = json.dumps({"candidates": [{"content": {"role": "model", "parts": [{"functionCall": {"id": "call_9", "name": "Bash", "args": {"command": "ls"}}}]}, "finishReason": "STOP"}]})
        explicit = _record("h2", explicit_raw, stop="tool_use", request=req, wire=_gemini_wire(["Bash"]))
        counts, train, rejects = self._export([generated, explicit])
        self.assertEqual(counts["exported"], 2, rejects)
        self.assertEqual(self._target(train[0])["tool_calls"][0]["id"], "Bash-3")
        self.assertEqual(self._target(train[1])["tool_calls"][0]["id"], "call_9")

    def test_unknown_gemini_part_key_is_archived_not_rejected(self):
        raw = json.dumps({"candidates": [{"content": {"role": "model", "parts": [{"text": "ok"}, {"inlineData": {"mimeType": "image/png", "data": "PAYLOAD"}}]}, "finishReason": "STOP"}]})
        counts, train, rejects = self._export([_record("x1", raw, text="ok", stop="end_turn")])
        self.assertEqual(counts["exported"], 1, rejects)
        unsupported = [b for b in self._sidecar() if b["kind"] == "unsupported"]
        self.assertEqual([b["field"] for b in unsupported], ["gemini.inlineData"])
        self.assertNotIn("PAYLOAD", json.dumps(train))
        self.assertNotIn("PAYLOAD", json.dumps(self._sidecar()))


class UnselectedReasoningArchive(ExportTest):
    def test_non_target_reasoning_field_is_archived_only(self):
        counts, train, rejects = self._export([_record("u1", ReasoningProvenance._chat({"content": "ok", "reasoning_content": "A", "reasoning": "UNSELECTED_TEXT"}), text="ok", thinking="A")])
        self.assertEqual(counts["exported"], 1, rejects)
        lines = [b for b in self._sidecar() if b["kind"] == "unselected"]
        self.assertEqual([(b["field"], b["text"]) for b in lines], [("openai.reasoning", "UNSELECTED_TEXT")])
        self.assertNotIn("UNSELECTED_TEXT", json.dumps(train))


class GeminiLlmrecFixture(ExportTest):
    def test_cli_exports_native_fixture_and_rejects_error_record(self):
        fixture = os.path.join(os.path.dirname(os.path.abspath(__file__)), "fixtures", "gemini_native_llmrec.jsonl")
        shutil.copy(fixture, os.path.join(self.raw, et.RECORDS_FILE))
        with open(os.devnull, "w", encoding="utf-8") as devnull, contextlib.redirect_stdout(devnull):
            self.assertEqual(et.main(["--raw-dir", self.raw, "--output-dir", self.out]), 0)
        train = _jsonl(os.path.join(self.out, et.TRAIN_FILE))
        rejects = _jsonl(os.path.join(self.raw, et.REJECTS_FILE))
        self.assertEqual([self._target(t)["tool_calls"][0]["id"] for t in train], ["Bash-3"])
        self.assertEqual([r["id"] for r in rejects], ["llm-native-2"])
        self.assertNotIn("SIG_C", json.dumps(train))


class SDKTraces(ExportTest):
    """Native SDK records: bridge body in raw_request, NDJSON stream in raw_response."""

    @staticmethod
    def _bridge(provider, messages=None):
        ctx = {
            "systemPrompt": "sys one",
            "messages": messages or [{"role": "user", "content": "hi", "timestamp": 1}],
            "tools": [{"name": "bash", "description": "Run a shell command", "parameters": BASH_SCHEMA}],
        }
        return json.dumps({"provider": provider, "model": "m", "context": ctx, "options": {}})

    @staticmethod
    def _stream(message, deltas=()):
        lines = [json.dumps({"type": "text_delta", "delta": d}) for d in deltas]
        lines.append(json.dumps({"type": "done", "reason": message["stopReason"], "message": message}))
        return "\n".join(lines) + "\n"

    def _sdk(self, rid, provider, message, text="", thinking=None, stop="tool_use", messages=None, deltas=()):
        return _record(rid, self._stream(message, deltas), text=text, stop=stop, thinking=thinking, wire=self._bridge(provider, messages))

    def test_claude_signed_thinking_and_tool_call(self):
        msg = {
            "stopReason": "toolUse",
            "content": [
                {"type": "thinking", "thinking": "Plan the call", "thinkingSignature": "SIG_CLAUDE_BYTES"},
                {"type": "text", "text": "Checking"},
                {"type": "toolCall", "id": "tu1", "name": "bash", "arguments": {"cmd": "ls"}},
            ],
        }
        rec = self._sdk("c1", "anthropic", msg, text="Checking", thinking="Plan the call", deltas=("Plan", " the call"))
        counts, train, rejects = self._export([rec])
        self.assertEqual(counts["exported"], 1, rejects)
        target = self._target(train[0])
        self.assertEqual(target["content"], "Checking")
        self.assertEqual(target["reasoning"], "Plan the call")
        self.assertEqual(target["tool_calls"][0]["id"], "tu1")
        self.assertEqual(json.loads(target["tool_calls"][0]["function"]["arguments"]), {"cmd": "ls"})
        self.assertEqual(train[0]["metadata"]["reasoning_kind"], "anthropic_thinking")
        self.assertEqual([b["text"] for b in self._sidecar() if b["kind"] == "anthropic_thinking"], ["Plan the call"])
        opaque = [(b["field"], b["bytes"], b["sha256"]) for b in self._sidecar() if b["kind"] == "opaque"]
        self.assertEqual(opaque, [("anthropic.thinkingSignature", len(b"SIG_CLAUDE_BYTES"), hashlib.sha256(b"SIG_CLAUDE_BYTES").hexdigest())])
        self.assertNotIn("SIG_CLAUDE_BYTES", json.dumps(train))

    def test_codex_summary_encrypted_state_and_tool_call(self):
        msg = {
            "stopReason": "toolUse",
            "content": [
                {"type": "thinking", "thinking": "Summary of reasoning", "summary": True, "thinkingSignature": "ENC_CODEX_BYTES", "itemId": "rs_1"},
                {"type": "toolCall", "id": "call_1|fc_1", "name": "bash", "arguments": {"cmd": "pwd"}},
            ],
        }
        rec = self._sdk("x1", "openai-codex", msg, thinking="Summary of reasoning")
        counts, train, rejects = self._export([rec])
        self.assertEqual(counts["exported"], 1, rejects)
        target = self._target(train[0])
        self.assertEqual(target["reasoning"], "Summary of reasoning")
        self.assertEqual(target["tool_calls"][0]["function"]["name"], "bash")
        self.assertEqual(train[0]["metadata"]["reasoning_kind"], "summary")
        kinds = [(b["kind"], b["field"]) for b in self._sidecar() if b["kind"] in ("summary", "opaque")]
        self.assertEqual(kinds, [("summary", "sdk.summary"), ("opaque", "openai-codex.thinkingSignature")])
        self.assertNotIn("ENC_CODEX_BYTES", json.dumps(train))

    def test_antigravity_thought_signature_with_tool_result_context(self):
        history = [
            {"role": "user", "content": "list files", "timestamp": 1},
            {
                "role": "assistant",
                "content": [{"type": "toolCall", "id": "c1", "name": "bash", "arguments": {"cmd": "ls"}, "thoughtSignature": "AG_THOUGHT_SIG"}],
                "stopReason": "toolUse",
                "timestamp": 2,
            },
            {"role": "toolResult", "toolCallId": "c1", "toolName": "bash", "content": [{"type": "text", "text": "file.txt"}], "isError": False, "timestamp": 3},
        ]
        msg = {"stopReason": "stop", "content": [{"type": "text", "text": "Done", "textSignature": "AG_TEXT_SIG"}]}
        rec = self._sdk("g1", "google-antigravity", msg, text="Done", stop="end_turn", messages=history)
        counts, train, rejects = self._export([rec])
        self.assertEqual(counts["exported"], 1, rejects)
        self.assertEqual(self._target(train[0])["content"], "Done")
        history_text = json.dumps(train[0]["messages"])
        self.assertIn("file.txt", history_text)
        self.assertIn("c1", history_text)
        self.assertNotIn("AG_THOUGHT_SIG", json.dumps(train))
        self.assertNotIn("AG_TEXT_SIG", json.dumps(train))

    def test_metadata_only_signature_yields_no_readable_reasoning(self):
        msg = {"stopReason": "stop", "content": [{"type": "thinking", "thinking": "", "thinkingSignature": "ONLY_SIG_BYTES"}, {"type": "text", "text": "ok"}]}
        counts, train, rejects = self._export([self._sdk("m1", "anthropic", msg, text="ok", stop="end_turn")])
        self.assertEqual(counts["exported"], 1, rejects)
        self.assertFalse(self._target(train[0]).get("reasoning"))
        self.assertEqual(train[0]["metadata"]["reasoning_source"], "none")
        self.assertTrue(train[0]["metadata"]["reasoning_opaque"])
        self.assertEqual([b["kind"] for b in self._sidecar() if b["kind"] in ("anthropic_thinking", "summary", "unclassified", "raw")], [])
        self.assertNotIn("ONLY_SIG_BYTES", json.dumps(train))

    def test_raw_record_is_unchanged_by_export(self):
        msg = {"stopReason": "stop", "content": [{"type": "thinking", "thinking": "Hidden", "thinkingSignature": "SIG_RAW_BYTES"}, {"type": "text", "text": "ok"}]}
        path = os.path.join(self.raw, et.RECORDS_FILE)
        with open(path, "w", encoding="utf-8") as f:
            f.write(json.dumps(self._sdk("r1", "anthropic", msg, text="ok", thinking="Hidden", stop="end_turn")) + "\n")
        with open(path, "rb") as f:
            before = f.read()
        counts = et.export(self.raw, self.out)
        self.assertEqual(counts["exported"], 1)
        with open(path, "rb") as f:
            self.assertEqual(f.read(), before)

    def test_terminal_failures_reject_with_distinct_reasons(self):
        ok_text = json.dumps({"type": "text_delta", "delta": "ok"})
        cases = {
            "eof": (ok_text + "\n", "sdk_stream_incomplete"),
            "error": (json.dumps({"type": "error", "reason": "aborted", "error": {"stopReason": "error"}}) + "\n", "sdk_error"),
            "bridge": (json.dumps({"type": "bridge_error", "code": "auth_required", "status": 401}) + "\n", "sdk_bridge_error"),
        }
        rows = [_record(rid, raw, text="ok", stop="end_turn", wire=self._bridge("anthropic")) for rid, (raw, _) in cases.items()]
        counts, train, rejects = self._export(rows)
        self.assertEqual(train, [])
        self.assertEqual({r["id"]: r["reason"] for r in rejects}, {rid: reason for rid, (_, reason) in cases.items()})
        self.assertNotIn("refused", counts["rejects_by_reason"])

    def test_refusal_rejects_as_refused_and_stays_archived(self):
        msg = {
            "stopReason": "stop",
            "stopDetails": {"type": "refusal"},
            "content": [{"type": "thinking", "thinking": "Weighing the request", "thinkingSignature": "SIG_REFUSED_BYTES"}],
        }
        counts, train, rejects = self._export([self._sdk("f1", "anthropic", msg, thinking="Weighing the request", stop="end_turn")])
        self.assertEqual(train, [])
        self.assertEqual([(r["id"], r["reason"]) for r in rejects], [("f1", "refused")])
        archived = [(b["kind"], b["text"]) for b in self._sidecar() if b.get("accepted") is False and b.get("text")]
        self.assertEqual(archived, [("anthropic_thinking", "Weighing the request")])
        self.assertNotIn("SIG_REFUSED_BYTES", json.dumps(self._sidecar()))



if __name__ == "__main__":
    unittest.main()
