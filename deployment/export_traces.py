#!/usr/bin/env python3
"""Export ARTEX llm_records snapshots to training JSONL.

Input: <raw-dir>/llm_records.jsonl, one JSON object per line with the
llm_records columns as stored by llmrec. request_body and response_body are
JSON strings. raw_request and raw_response are the verbatim provider bodies.
The snapshot is the source of truth and is not rewritten.

Optional <raw-dir>/provenance.json maps a profile_name to its model_backend and
provenance. Only provenance "open-weight-local" makes reasoning kind "raw". Without
a mapping, generic reasoning fields are "unclassified".

Outputs:
  <out-dir>/train.jsonl     REDACTED, one sample per accepted row
  <out-dir>/NOTICE.txt      provenance caveats
  <raw-dir>/rejects.jsonl   UNREDACTED, one line per rejected row:
                            line, id, reason, detail, original record verbatim
  <raw-dir>/reasoning.jsonl UNREDACTED, one line per reasoning block, opaque digest,
                            or unsupported field, for every row. Rewritten each run.

out-dir holds only train.jsonl and NOTICE.txt. Rejects stay beside the source
snapshot because they carry unredacted prompts and provider bodies. Raw bodies
are not copied out. They remain in the snapshot.

A sample is the prompt conversation followed by the recorded assistant turn as
the final message. Tool calls come from raw_response, because response_body
keeps only text, thinking, stop reason, and usage. A row is accepted only when
the text, thinking, and stop reason recovered from raw_response equal
response_body exactly. Otherwise the row is rejected, not guessed.

Tool schemas come from the wire body in raw_request, normalized to the OpenAI
function shape under the sample's top-level "tools". Names alone are never
turned into schemas. If raw_request carries no tools, the sample has no
"tools" key and metadata.tools_schema_source is "none".

History tool calls are associated by id. A tool_result must answer an open
tool_use from the immediately preceding assistant turn. Anything unmatched is
rejected.

Reasoning: explicit thinking text goes into target "reasoning". Each text block is
classified by metadata.reasoning_kind. Every kind keeps its text, so filter on that
field. Signatures, redacted blocks, and encrypted content are opaque: only a byte
count and SHA-256 are recorded, never the payload. Opaque-only reasoning sets
metadata.reasoning_opaque. Nothing is synthesized.

SDK records (raw_request is the bridge body with provider and context): the terminal line of raw_response decides the outcome. done, error, bridge_error, or EOF without a terminal line is the outcome. Only the terminal message is projected, so stream deltas are not read. error and bridge_error reject. A refusal (stop reason refusal or stopDetails type refusal) rejects as refused and stays in reasoning.jsonl. Native thinking with summary true is summary. Signatures are digests only.

Redaction runs on train.jsonl only, by heuristic pattern matching. It is not a
PII or secrets guarantee.

Caveats: guest root can modify or delete guest-side capture files, so exports
are not tamper-evident. HTTPS traffic in packet captures is encrypted. This
exporter reads application-level records, not packets.

Usage: python3 export_traces.py --raw-dir DIR --output-dir DIR
"""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import re
import sys
from typing import Any

RECORDS_FILE = "llm_records.jsonl"
TRAIN_FILE = "train.jsonl"
REJECTS_FILE = "rejects.jsonl"
NOTICE_FILE = "NOTICE.txt"
REASONING_FILE = "reasoning.jsonl"
PROVENANCE_FILE = "provenance.json"
RAW_PROVENANCE = "open-weight-local"  # the only provenance that makes reasoning "raw"

NOTICE = (
    "ARTEX trace export: provenance and limits\n"
    "- This directory holds only train.jsonl (redacted) and this NOTICE.txt.\n"
    "- Rejected rows are unredacted and live in the source snapshot as rejects.jsonl.\n"
    "- The source snapshot retains the verbatim wire bytes in llm_records.jsonl. This export does not copy raw bodies.\n"
    "- Each train.jsonl sample is one recorded LLM call.\n"
    "- Guest root can modify or delete guest-side capture files. Treat exports as untrusted unless the host copy is verified.\n"
    "- HTTPS traffic in packet captures is encrypted. This export reads application-level records, not packets.\n"
    "- train.jsonl redaction is heuristic pattern matching. It is not a PII or secrets guarantee.\n"
    "- No reasoning is synthesized. Reasoning appears only when the provider returned it as text.\n"
    "- reasoning.jsonl in the source snapshot is UNREDACTED. It holds reasoning text for every row and digests of opaque payloads.\n"
    "- metadata.reasoning_kind: raw only when provenance.json maps the profile to open-weight-local. unclassified for generic reasoning fields on other profiles. summary for Responses summaries and Anthropic thinking with display summarized. anthropic_thinking for other Anthropic thinking. Raw is never inferred from a field or model name.\n"
    "- Signatures, redacted_thinking data, and encrypted_content are opaque: a byte count and SHA-256 only, never the payload.\n"
    "- Reasoning-like keys this exporter does not read are flagged in reasoning.jsonl only. Known limit: a handled key name in an unhandled position is not flagged.\n"
    "- Per message or delta, the first non-empty of reasoning_content, reasoning, reasoning_text is the reasoning target, as norma reads it. Other non-empty fields are archived in reasoning.jsonl as kind unselected: unredacted text, never in train.jsonl.\n"
    "- reasoning_kind covers only the recorded target turn. Earlier assistant turns keep reasoning text with no kind.\n"
    "- reasoning_budget_exhausted is null unless the provider reported timings.reasoning_budget_exhausted.\n"
    "- Gemini thoughts (thought:true parts) are provider summaries (reasoning_kind summary), never raw. thoughtSignature values are opaque: byte count and SHA-256 only. Gemini functionCall ids that are empty or repeated become name-N, numbered after the tool calls already in request_body, as the Go provider assigns them.\n"
    "- SDK records: the terminal done or error line in raw_response decides the outcome. error, bridge_error, and EOF without a terminal line reject. Only the terminal message is read, so stream deltas are not scanned for reasoning. Native thinking with summary true is summary. Other Anthropic thinking is anthropic_thinking. Other provider thinking is unclassified. Refusals reject as refused and are archived.\n"
)


class Reject(Exception):
    """A record cannot become a sample without guessing."""

    def __init__(self, reason: str, detail: str = "") -> None:
        super().__init__(f"{reason}: {detail}" if detail else reason)
        self.reason = reason
        self.detail = detail


# ---------------------------------------------------------------- files


def _private_dir(path: str) -> None:
    os.makedirs(path, mode=0o700, exist_ok=True)
    os.chmod(path, 0o700)


def _open_private(path: str):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, "w", encoding="utf-8", newline="")


def _write_private(path: str, text: str) -> None:
    with _open_private(path) as f:
        f.write(text)


# ---------------------------------------------------------------- response decoding

_ATTEMPT_RE = re.compile(r"^===== attempt (\d+)/(\d+) \S+ HTTP (\d+) =====[ \t]*$", re.M)
_ANTHROPIC_EVENTS = {
    "message_start",
    "content_block_start",
    "content_block_delta",
    "content_block_stop",
    "message_delta",
    "message_stop",
    "ping",
}
_OPENAI_FINISH = {"tool_calls": "tool_use", "stop": "end_turn", "length": "max_tokens"}


def _map_openai_finish(reason: str) -> str:
    return _OPENAI_FINISH.get(reason, reason)


def _split_attempts(raw: str) -> list[tuple[int | None, str]]:
    matches = list(_ATTEMPT_RE.finditer(raw))
    if not matches:
        return [(None, raw)]
    if raw[: matches[0].start()].strip():
        raise Reject("unparseable_raw_response", "text before first attempt header")
    attempts = []
    for i, m in enumerate(matches):
        end = matches[i + 1].start() if i + 1 < len(matches) else len(raw)
        body = raw[m.end() : end]
        if body.startswith("\n"):
            body = body[1:]
        attempts.append((int(m.group(3)), body))
    return attempts


def _select_attempt(raw: str) -> str:
    ok = [body for status, body in _split_attempts(raw) if status is None or 200 <= status < 300]
    if not ok:
        raise Reject("no_successful_attempt", "every HTTP attempt failed")
    return ok[-1]


def _blocks(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if not isinstance(value, list) or not all(isinstance(b, dict) for b in value):
        raise Reject("unparseable_raw_response", "expected a list of objects")
    return value


class _Turn:
    """Mirrors norma's llm.Accumulator so tool inputs join the way the agent saw them."""

    def __init__(self) -> None:
        self.blocks: list[dict[str, Any]] = []
        self.text_buf: list[str] | None = None
        self.think_buf: list[str] | None = None
        self.think_label = ""
        self.last_tool: dict[str, Any] | None = None
        self.stop = ""
        self.opaque: dict[str, list[str]] = {}
        self.unsupported: list[dict[str, Any]] = []
        self.unselected: list[dict[str, Any]] = []
        self.budget: bool | None = None

    def _flush_text(self) -> None:
        if self.text_buf is not None:
            s = "".join(self.text_buf)
            if s:
                self.blocks.append({"type": "text", "text": s})
            self.text_buf = None

    def _flush_thinking(self) -> None:
        if self.think_buf is not None:
            s = "".join(self.think_buf)
            if s:
                self.blocks.append({"type": "thinking", "text": s, "label": self.think_label})
            self.think_buf = None

    def add(self, ev: tuple) -> None:
        kind = ev[0]
        if kind == "text":
            if self.text_buf is None:
                self._flush_thinking()
                self.text_buf = []
            self.text_buf.append(ev[1])
        elif kind == "thinking":
            if not ev[1]:
                return
            # one run per label: a summary and a reasoning_text never merge into one block
            if self.think_buf is None or ev[2] != self.think_label:
                self._flush_thinking()
                self._flush_text()
                self.think_buf = []
                self.think_label = ev[2]
            self.think_buf.append(ev[1])
        elif kind == "signature":
            self.opaque.setdefault(ev[2], []).append(ev[1])
        elif kind == "unsupported":
            self.unsupported.append({"field": ev[1], "bytes": ev[2]})
        elif kind == "unselected":
            self.unselected.append({"field": ev[2], "text": ev[1]})
        elif kind == "budget":
            self.budget = ev[1] if self.budget is None else (self.budget or ev[1])
        elif kind == "tool_start":
            self._flush_text()
            self._flush_thinking()
            self.last_tool = {"type": "tool", "id": ev[1], "name": ev[2], "parts": []}
            self.blocks.append(self.last_tool)
        elif kind == "tool_json":
            if self.last_tool is not None:
                self.last_tool["parts"].append(ev[1])
        elif kind == "stop":
            if ev[1]:
                self.stop = ev[1]

    def finish(self) -> dict[str, Any]:
        self._flush_text()
        self._flush_thinking()
        text = "".join(b["text"] for b in self.blocks if b["type"] == "text")
        runs = [b for b in self.blocks if b["type"] == "thinking"]
        thinking = "".join(b["text"] for b in runs)
        calls = [
            {"id": b["id"], "name": b["name"], "arguments": _valid_args(b["parts"])}
            for b in self.blocks
            if b["type"] == "tool"
        ]
        opaque = []
        for label in sorted(self.opaque):
            payload = "".join(self.opaque[label]).encode("utf-8")
            opaque.append({"field": label, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()})
        return {
            "text": text,
            "thinking": thinking,
            "tool_calls": calls,
            "stop_reason": self.stop,
            "opaque_reasoning": bool(self.opaque) and not thinking,
            "reasoning_blocks": [{"field": b["label"], "text": b["text"]} for b in runs],
            "opaque_blocks": opaque,
            "unsupported": self.unsupported,
            "unselected": self.unselected,
            "budget_exhausted": self.budget,
        }


def _valid_args(parts: list[str]) -> str:
    raw = "".join(parts).strip()
    if not raw:
        return "{}"  # provider sent no arguments at all
    try:
        json.loads(raw)
    except ValueError as e:
        raise Reject("malformed_tool_arguments", str(e)) from e
    return raw


# JSON (non-streaming) bodies -> normalized events


def _anthropic_json_events(obj: dict[str, Any]) -> list[tuple]:
    evs: list[tuple] = []
    for blk in _blocks(obj.get("content")):
        t = blk.get("type")
        if t == "text":
            evs.append(("text", blk.get("text") or ""))
        elif t == "thinking":
            evs.append(("thinking", blk.get("thinking") or "", "anthropic.thinking"))
            if blk.get("signature") is not None:
                evs.append(("signature", _as_text(blk["signature"]), "anthropic.signature"))
        elif t == "redacted_thinking":
            evs.append(("signature", _as_text(blk.get("data")), "anthropic.redacted_thinking"))
        elif t == "tool_use":
            evs.append(("tool_start", blk.get("id") or "", blk.get("name") or ""))
            inp = blk.get("input")
            evs.append(("tool_json", json.dumps(inp) if inp is not None else ""))
        else:
            raise Reject("unsupported_response_block", str(t))
    evs.append(("stop", obj.get("stop_reason") or ""))
    return evs


def _openai_json_events(obj: dict[str, Any]) -> list[tuple]:
    choices = _blocks(obj.get("choices"))
    if not choices:
        raise Reject("empty_response", "no choices")
    ch = choices[0]
    msg = ch.get("message") or {}
    evs: list[tuple] = []
    think, label = _openai_reasoning(msg)
    if think:
        evs.append(("thinking", think, label))
    evs += [("unselected", t, lbl) for lbl, t in _openai_unselected(msg)]
    if msg.get("content"):
        evs.append(("text", msg["content"]))
    elif msg.get("refusal"):
        evs.append(("text", msg["refusal"]))
    for tc in _blocks(msg.get("tool_calls")):
        fn = tc.get("function") or {}
        evs.append(("tool_start", tc.get("id") or "", fn.get("name") or ""))
        evs.append(("tool_json", fn.get("arguments") or ""))
    evs.append(("stop", _map_openai_finish(ch.get("finish_reason") or "")))
    return evs


def _responses_json_events(obj: dict[str, Any]) -> list[tuple]:
    evs: list[tuple] = []
    has_call = False
    for item in _blocks(obj.get("output")):
        t = item.get("type")
        if t == "message":
            for c in _blocks(item.get("content")):
                if c.get("type") == "output_text" and c.get("text"):
                    evs.append(("text", c["text"]))
        elif t == "reasoning":
            for s in _blocks(item.get("summary")):
                evs.append(("thinking", s.get("text") or "", "responses.summary"))
            for c in _blocks(item.get("content")):
                if c.get("type") == "reasoning_text":
                    evs.append(("thinking", c.get("text") or "", "responses.reasoning_text"))
            if item.get("encrypted_content") is not None:
                evs.append(("signature", _as_text(item["encrypted_content"]), "responses.encrypted_content"))
        elif t == "function_call":
            has_call = True
            evs.append(("tool_start", item.get("call_id") or "", item.get("name") or ""))
            evs.append(("tool_json", item.get("arguments") or ""))
        else:
            raise Reject("unsupported_response_block", str(t))
    stop = "tool_use" if has_call else "end_turn"
    if (obj.get("incomplete_details") or {}).get("reason") == "max_output_tokens":
        stop = "max_tokens"
    evs.append(("stop", stop))
    return evs


# SSE streams -> normalized events


_GEMINI_FINISH = {
    "STOP": "end_turn",
    "MAX_TOKENS": "max_tokens",
    "SAFETY": "refusal",
    "PROHIBITED_CONTENT": "refusal",
    "SPII": "refusal",
    "BLOCKLIST": "refusal",
}
_GEMINI_PART_KEYS = {"text", "thought", "thoughtSignature", "functionCall"}


def _gemini_body(obj: dict[str, Any]) -> bool:
    """True for a native Gemini body, with or without the response wrapper."""
    inner = obj.get("response") if isinstance(obj.get("response"), dict) else obj
    return isinstance(inner.get("candidates"), list)


_NO_HISTORY: tuple[int, frozenset[str]] = (0, frozenset())


def _history_tool_state(req: dict[str, Any]) -> tuple[int, frozenset[str]]:
    """Tool calls already in the request: count and ids. The Go provider seeds Gemini ids from these."""
    count = 0
    ids: set[str] = set()
    for msg in req.get("messages") or []:
        content = msg.get("content") if isinstance(msg, dict) else None
        for b in content if isinstance(content, list) else []:
            if isinstance(b, dict) and b.get("type") == "tool_use":
                count += 1
                ids.add(b.get("id") or "")
    return count, frozenset(ids)


class _GeminiCalls:
    """Call ids as the Go provider assigns them: numbering resumes after history; a missing or used id becomes name-N."""

    def __init__(self, history: tuple[int, frozenset[str]]) -> None:
        self.index, ids = history
        self.seen: set[str] = set(ids)
        self.any = False

    def new_id(self, call: dict[str, Any]) -> str:
        cid = str(call.get("id") or "")
        while cid == "" or cid in self.seen:
            self.index += 1
            cid = f"{call.get('name') or ''}-{self.index}"
        self.seen.add(cid)
        self.any = True
        return cid


def _gemini_part_events(part: dict[str, Any], calls: _GeminiCalls) -> list[tuple]:
    evs: list[tuple] = [("unsupported", f"gemini.{k}", len(json.dumps(part[k]).encode("utf-8"))) for k in sorted(set(part) - _GEMINI_PART_KEYS)]
    sig = _as_text(part.get("thoughtSignature"))
    call = part.get("functionCall")
    text = _as_text(part.get("text"))
    if call is not None:
        if not isinstance(call, dict):
            raise Reject("unsupported_response_block", "functionCall")
        evs.append(("tool_start", calls.new_id(call), str(call.get("name") or "")))
        evs.append(("tool_json", json.dumps(call.get("args"), ensure_ascii=False)))
        label = "gemini.functionCall"
    elif part.get("thought") is True:
        if text:
            evs.append(("thinking", text, "gemini.thought"))
        label = "gemini.thought"
    else:
        if text:
            evs.append(("text", text))
        label = "gemini.text"
    if sig:
        evs.append(("signature", sig, f"{label}.thoughtSignature"))
    return evs


def _gemini_events(obj: dict[str, Any], calls: _GeminiCalls) -> list[tuple]:
    inner = obj.get("response") if isinstance(obj.get("response"), dict) else obj
    evs: list[tuple] = []
    ended = False
    for cand in _blocks(inner.get("candidates")):
        content = cand.get("content") or {}
        if not isinstance(content, dict):
            raise Reject("unsupported_response_block", "candidate content")
        for part in _blocks(content.get("parts")):
            evs.extend(_gemini_part_events(part, calls))
        reason = cand.get("finishReason")
        if reason:
            stop = _GEMINI_FINISH.get(reason, reason)
            if stop == "end_turn" and calls.any:
                stop = "tool_use"
            evs.append(("stop", stop))
            ended = True
    block = (inner.get("promptFeedback") or {}).get("blockReason")
    if block and not ended:
        evs.append(("stop", "refusal"))
    return evs


def _sse_frames(body: str) -> list[tuple[str, dict[str, Any]]]:
    frames: list[tuple[str, dict[str, Any]]] = []
    name = ""
    data: list[str] = []

    def flush() -> None:
        nonlocal name, data
        if data:
            payload = "\n".join(data)
            if payload.strip() != "[DONE]":
                try:
                    obj = json.loads(payload)
                except ValueError:
                    obj = None  # keepalive or non-JSON comment; SDKs skip these too
                if isinstance(obj, dict):
                    frames.append((name, obj))
        name = ""
        data = []

    for line in body.splitlines():
        if not line:
            flush()
        elif line.startswith(":"):
            continue
        elif line.startswith("event:"):
            name = line[6:].strip()
        elif line.startswith("data:"):
            v = line[5:]
            data.append(v[1:] if v.startswith(" ") else v)
    flush()
    return frames


def _frame_provider(name: str, obj: dict[str, Any]) -> str | None:
    kind = name or str(obj.get("type", ""))
    if kind == "error" or obj.get("error"):
        raise Reject("stream_error", str(obj.get("error") or kind)[:200])
    if "choices" in obj:
        return "openai"
    if kind.startswith("response."):
        return "responses"
    if obj.get("type") in _ANTHROPIC_EVENTS:
        return "anthropic"
    if _gemini_body(obj):
        return "gemini"
    return None


class _AnthropicStream:
    provider = "anthropic"

    def frame(self, name: str, obj: dict[str, Any], evs: list[tuple]) -> None:
        t = obj.get("type")
        if t == "content_block_start":
            cb = obj.get("content_block") or {}
            ct = cb.get("type")
            if ct == "tool_use":
                evs.append(("tool_start", cb.get("id") or "", cb.get("name") or ""))
            elif ct == "redacted_thinking":
                evs.append(("signature", _as_text(cb.get("data")), "anthropic.redacted_thinking"))
            elif ct not in ("text", "thinking"):
                raise Reject("unsupported_response_block", str(ct))
        elif t == "content_block_delta":
            d = obj.get("delta") or {}
            dt = d.get("type")
            if dt == "text_delta":
                evs.append(("text", d.get("text") or ""))
            elif dt == "thinking_delta":
                evs.append(("thinking", d.get("thinking") or "", "anthropic.thinking"))
            elif dt == "signature_delta":
                evs.append(("signature", d.get("signature") or "", "anthropic.signature"))
            elif dt == "input_json_delta":
                evs.append(("tool_json", d.get("partial_json") or ""))
        elif t == "message_delta":
            evs.append(("stop", (obj.get("delta") or {}).get("stop_reason") or ""))


class _GeminiStream:
    provider = "gemini"

    def __init__(self, history: tuple[int, frozenset[str]]) -> None:
        self.calls = _GeminiCalls(history)

    def frame(self, name: str, obj: dict[str, Any], evs: list[tuple]) -> None:
        evs.extend(_gemini_events(obj, self.calls))


class _OpenAIStream:
    provider = "openai"

    def __init__(self) -> None:
        self.started: set[int] = set()
        self.last: int | None = None

    def frame(self, name: str, obj: dict[str, Any], evs: list[tuple]) -> None:
        choices = obj.get("choices") or []
        if not choices:
            return
        ch = choices[0] or {}
        d = ch.get("delta") or {}
        think, label = _openai_reasoning(d)
        if think:
            evs.append(("thinking", think, label))
        evs += [("unselected", t, lbl) for lbl, t in _openai_unselected(d)]
        if d.get("content"):
            evs.append(("text", d["content"]))
        if d.get("refusal"):
            evs.append(("text", d["refusal"]))
        for tc in d.get("tool_calls") or []:
            idx = tc.get("index", 0)
            fn = tc.get("function") or {}
            if idx not in self.started and (tc.get("id") or fn.get("name")):
                self.started.add(idx)
                self.last = idx
                evs.append(("tool_start", tc.get("id") or "", fn.get("name") or ""))
            args = fn.get("arguments") or ""
            if args:
                if idx != self.last:
                    raise Reject("ambiguous_tool_stream", f"argument fragment for tool index {idx}")
                evs.append(("tool_json", args))
        if ch.get("finish_reason"):
            evs.append(("stop", _map_openai_finish(ch["finish_reason"])))


class _ResponsesStream:
    provider = "responses"

    def __init__(self) -> None:
        self.tool_open = False
        self.tool_out: Any = None

    def frame(self, event: str, obj: dict[str, Any], evs: list[tuple]) -> None:
        kind = event or str(obj.get("type", ""))
        if kind == "response.output_item.added":
            item = obj.get("item") or {}
            it = item.get("type")
            if it == "function_call":
                self.tool_open = True
                self.tool_out = obj.get("output_index")
                evs.append(("tool_start", item.get("call_id") or "", item.get("name") or ""))
            elif it not in ("message", "reasoning"):
                raise Reject("unsupported_response_block", str(it))
        elif kind == "response.output_text.delta":
            if obj.get("delta"):
                evs.append(("text", obj["delta"]))
        elif kind == "response.reasoning_summary_text.delta":
            if obj.get("delta"):
                evs.append(("thinking", obj["delta"], "responses.summary"))
        elif kind == "response.reasoning_text.delta":
            if obj.get("delta"):
                evs.append(("thinking", obj["delta"], "responses.reasoning_text"))
        elif kind == "response.output_item.done":
            item = obj.get("item") or {}
            if item.get("type") == "reasoning" and item.get("encrypted_content") is not None:
                evs.append(("signature", _as_text(item["encrypted_content"]), "responses.encrypted_content"))
        elif kind == "response.function_call_arguments.delta":
            if not self.tool_open or obj.get("output_index") != self.tool_out:
                raise Reject("ambiguous_tool_stream", "argument delta for an unexpected output item")
            if obj.get("delta"):
                evs.append(("tool_json", obj["delta"]))
        elif kind in ("response.completed", "response.incomplete"):
            inc = (obj.get("response") or {}).get("incomplete_details") or {}
            evs.append(("stop", "max_tokens" if inc.get("reason") == "max_output_tokens" else "end_turn"))
        elif kind in ("response.failed", "error"):
            raise Reject("stream_error", kind)


_HANDLERS = {
    "anthropic": _AnthropicStream,
    "openai": _OpenAIStream,
    "responses": _ResponsesStream,
}


def _sse_events(body: str, history: tuple[int, frozenset[str]] = _NO_HISTORY) -> list[tuple]:
    handler = None
    evs: list[tuple] = []
    for i, (name, obj) in enumerate(_sse_frames(body)):
        evs.extend(_scan_events(obj, f"frame[{i}]"))
        provider = _frame_provider(name, obj)
        if provider is None:
            continue
        if handler is None:
            handler = _GeminiStream(history) if provider == "gemini" else _HANDLERS[provider]()
        elif handler.provider != provider:
            raise Reject("unknown_provider_format", "mixed stream formats")
        handler.frame(name, obj, evs)
    if handler is None:
        raise Reject("unknown_provider_format", "no recognized stream events")
    return evs


def _parse_completion(body: str, history: tuple[int, frozenset[str]] = _NO_HISTORY) -> dict[str, Any]:
    stripped = body.strip()
    if not stripped:
        raise Reject("unparseable_raw_response", "empty attempt body")
    if stripped.startswith("{"):
        try:
            obj = json.loads(stripped)
        except ValueError as e:
            raise Reject("unparseable_raw_response", str(e)) from e
        if not isinstance(obj, dict):
            raise Reject("unparseable_raw_response", "not a JSON object")
        if obj.get("error"):
            raise Reject("provider_error", str(obj["error"])[:200])
        if "choices" in obj:
            evs = _openai_json_events(obj)
        elif "output" in obj:
            evs = _responses_json_events(obj)
        elif _gemini_body(obj):
            evs = _gemini_events(obj, _GeminiCalls(history))
        elif obj.get("type") == "message" or "content" in obj:
            evs = _anthropic_json_events(obj)
        else:
            raise Reject("unknown_provider_format", "unrecognized JSON body")
        evs = _scan_events(obj, "body") + evs
    else:
        evs = _sse_events(stripped, history)
    turn = _Turn()
    for ev in evs:
        turn.add(ev)
    return turn.finish()


# ---------------------------------------------------------------- reasoning fields


# Reasoning-like keys this exporter does not read are flagged, never exported.
# Known limit: a handled key name in an unhandled position is not flagged.
_SKIP_KEYS = {
    "finish_reason",
    "stop_reason",
    "incomplete_details",
    "timings",
    "input",
    "finishReason",
    "blockReason",
}
_HANDLED_KEYS = {
    "reasoning_content",
    "reasoning",
    "reasoning_text",
    "summary",
    "thinking",
    "signature",
    "thoughtSignature",
    "encrypted_content",
    "redacted_thinking",
    "reasoning_budget_exhausted",
}
_REASONY = re.compile(r"reason|think|thought|summar|encrypt|signature|redact", re.I)

_SDK_PROVIDERS = {"anthropic", "openai-codex", "google-antigravity"}
_SDK_STOP = {"stop": "end_turn", "length": "max_tokens", "toolUse": "tool_use", "refusal": "refusal"}
_SDK_HANDLED = _HANDLED_KEYS | {"thinkingSignature", "textSignature", "stopReason"}
_SDK_TERMINALS = {"done", "error", "bridge_error"}


def _openai_reasoning(d: dict[str, Any]) -> tuple[str, str]:
    """norma reads only the first non-empty of these per message or delta."""
    for key in ("reasoning_content", "reasoning", "reasoning_text"):
        if d.get(key):
            return d[key], f"openai.{key}"
    return "", ""


def _openai_unselected(d: dict[str, Any]) -> list[tuple[str, str]]:
    """Non-empty reasoning fields norma does not read. Archived only, never in the target."""
    keys = [k for k in ("reasoning_content", "reasoning", "reasoning_text") if d.get(k)]
    return [(f"openai.{k}", d[k]) for k in keys[1:]]


def _unsupported_fields(value: Any, path: str, handled: set[str] = _HANDLED_KEYS) -> list[tuple[str, int]]:
    """(path, bytes) for reasoning-like values this exporter does not read."""
    found: list[tuple[str, int]] = []
    if isinstance(value, dict):
        for k, v in value.items():
            if k in _SKIP_KEYS:
                continue
            p = f"{path}.{k}"
            if _REASONY.search(k) and k not in handled and isinstance(v, (str, list, dict)) and v:
                found.append((p, len(json.dumps(v, ensure_ascii=False).encode("utf-8"))))
            else:
                found.extend(_unsupported_fields(v, p, handled))
    elif isinstance(value, list):
        for i, v in enumerate(value):
            found.extend(_unsupported_fields(v, f"{path}[{i}]", handled))
    return found


def _scan_events(obj: dict[str, Any], path: str) -> list[tuple]:
    evs: list[tuple] = [("unsupported", p, n) for p, n in _unsupported_fields(obj, path)]
    timings = obj.get("timings")
    if isinstance(timings, dict) and isinstance(timings.get("reasoning_budget_exhausted"), bool):
        evs.append(("budget", timings["reasoning_budget_exhausted"]))
    return evs


def _sdk_request(rec: dict[str, Any]) -> dict[str, Any] | None:
    """The bridge body the SDK provider sent, from raw_request. None for every other record."""
    try:
        body = json.loads(_as_text(rec.get("raw_request")))
    except ValueError:
        return None
    if isinstance(body, dict) and body.get("provider") in _SDK_PROVIDERS and isinstance(body.get("context"), dict):
        return body
    return None


def _sdk_str(value: Any) -> str:
    if value is None:
        return ""
    if not isinstance(value, str):
        raise Reject("unparseable_raw_response", "native text field is not a string")
    return value


def _sdk_sig(value: Any, label: str) -> list[tuple]:
    text = _sdk_str(value)
    return [("signature", text, label)] if text else []


def _sdk_terminal(raw: str) -> dict[str, Any]:
    """First done, error, or bridge_error line. Every line must be JSON; EOF without one is incomplete."""
    terminal = None
    for n, line in enumerate(raw.splitlines(), 1):
        if not line.strip():
            continue
        try:
            obj = json.loads(line)
        except ValueError as e:
            raise Reject("unparseable_raw_response", f"line {n}: {e}") from e
        if not isinstance(obj, dict):
            raise Reject("unparseable_raw_response", f"line {n} is not an object")
        if terminal is None and obj.get("type") in _SDK_TERMINALS:
            terminal = obj
    if terminal is None:
        raise Reject("sdk_stream_incomplete", "no done, error, or bridge_error line")
    return terminal


def _parse_sdk(raw: str, provider: str) -> dict[str, Any]:
    term = _sdk_terminal(raw)
    if term["type"] == "bridge_error":
        raise Reject("sdk_bridge_error", str(term.get("code") or "bridge error")[:200])
    if term["type"] == "error":
        raise Reject("sdk_error", str(term.get("reason") or "error")[:200])
    msg = term.get("message")
    if not isinstance(msg, dict):
        raise Reject("unparseable_raw_response", "done without a message object")
    native = msg.get("stopReason")
    if native not in _SDK_STOP or term.get("reason") != native:
        raise Reject("sdk_stop_mismatch", f"done reason {term.get('reason')!r}, message stopReason {native!r}")
    stop = _SDK_STOP[native]
    details = msg.get("stopDetails")
    if isinstance(details, dict) and details.get("type") == "refusal":
        stop = "refusal"
    evs: list[tuple] = [("unsupported", p, n) for p, n in _unsupported_fields(msg, "done.message", _SDK_HANDLED)]
    for i, b in enumerate(_blocks(msg.get("content"))):
        kind = b.get("type")
        if kind == "text":
            evs.append(("text", _sdk_str(b.get("text"))))
            evs += _sdk_sig(b.get("textSignature"), f"{provider}.textSignature")
        elif kind == "thinking":
            if b.get("summary") is True:
                label = "sdk.summary"
            elif provider == "anthropic":
                label = "anthropic.thinking"
            else:
                label = "sdk.thinking"
            evs.append(("thinking", _sdk_str(b.get("thinking")), label))
            evs += _sdk_sig(b.get("thinkingSignature"), f"{provider}.thinkingSignature")
        elif kind == "redactedThinking":
            evs += _sdk_sig(b.get("data"), f"{provider}.redactedThinking")
        elif kind == "toolCall":
            args = b.get("arguments")
            if not isinstance(args, dict):
                raise Reject("malformed_tool_arguments", f"content[{i}] arguments is not an object")
            evs.append(("tool_start", str(b.get("id") or ""), str(b.get("name") or "")))
            evs.append(("tool_json", json.dumps(args, ensure_ascii=False)))
            evs += _sdk_sig(b.get("thoughtSignature"), f"{provider}.thoughtSignature")
        else:
            raise Reject("unknown_sdk_block", f"content[{i}] type {kind!r}")
    evs.append(("stop", stop))
    turn = _Turn()
    for ev in evs:
        turn.add(ev)
    return turn.finish()


def _recover(rec: dict[str, Any], req: dict[str, Any]) -> dict[str, Any]:
    """Parsed assistant turn from raw_response: the SDK stream for SDK records, else the legacy formats."""
    raw = _select_attempt(_as_text(rec.get("raw_response")))
    bridge = _sdk_request(rec)
    if bridge is not None:
        return _parse_sdk(raw, bridge["provider"])
    return _parse_completion(raw, _history_tool_state(req))


def _sdk_content(value: Any) -> list[dict[str, Any]]:
    if value is None:
        return []
    if isinstance(value, str):
        return [{"type": "text", "text": value}]
    if not isinstance(value, list) or not all(isinstance(b, dict) for b in value):
        raise Reject("unsupported_message", "message content is not a block list")
    return value


def _sdk_assistant_block(b: dict[str, Any]) -> dict[str, Any]:
    kind = b.get("type")
    if kind == "text":
        return {"type": "text", "text": b.get("text") or "", "signature": b.get("textSignature") or ""}
    if kind == "thinking":
        return {"type": "thinking", "thinking": b.get("thinking") or "", "signature": b.get("thinkingSignature") or ""}
    if kind == "redactedThinking":
        return {"type": "redacted_thinking", "data": b.get("data") or ""}
    if kind == "toolCall":
        return {"type": "tool_use", "id": b.get("id") or "", "name": b.get("name") or "", "input": b.get("arguments"), "signature": b.get("thoughtSignature") or ""}
    raise Reject("unsupported_message", f"assistant block {kind!r}")


def _sdk_convert_history(ctx: dict[str, Any]) -> list[dict[str, Any]]:
    """pi-ai context as the legacy request shape, so one history converter checks both."""
    system = ctx.get("systemPrompt")
    if system is not None and not isinstance(system, str):
        raise Reject("unsupported_message", "systemPrompt is not a string")
    messages: list[dict[str, Any]] = []
    prev_result = False
    for m in _blocks(ctx.get("messages")):
        role = m.get("role")
        if role == "toolResult":
            block: dict[str, Any] = {"type": "tool_result", "tool_use_id": m.get("toolCallId") or "", "content": _sdk_content(m.get("content"))}
            if m.get("isError"):
                block["is_error"] = True
            if prev_result:
                messages[-1]["content"].append(block)
            else:
                messages.append({"role": "user", "content": [block]})
            prev_result = True
            continue
        prev_result = False
        if role == "user":
            messages.append({"role": "user", "content": _sdk_content(m.get("content"))})
        elif role == "assistant":
            messages.append({"role": "assistant", "content": [_sdk_assistant_block(b) for b in _blocks(m.get("content"))]})
        else:
            raise Reject("unsupported_message", f"role {role!r}")
    return _convert_history({"system": system or "", "messages": messages})


def _sdk_tools(bridge: dict[str, Any], req: dict[str, Any]) -> list[dict[str, Any]]:
    tools = bridge["context"].get("tools")
    if tools is None or tools == []:
        return []
    if not isinstance(tools, list):
        raise Reject("unknown_tool_schema_format", "context.tools is not a list")
    fns = [_tool_function({"type": "function", **t} if isinstance(t, dict) else t) for t in tools]
    return _checked_tools([{"type": "function", "function": f} for f in fns], req)


# ---------------------------------------------------------------- wire tool schemas


def _tool_function(t: Any) -> dict[str, Any]:
    """Normalize one wire tool to an OpenAI function object, or reject."""
    if not isinstance(t, dict):
        raise Reject("unknown_tool_schema_format", "tool is not an object")
    if t.get("type") == "function" and isinstance(t.get("function"), dict):
        fn = dict(t["function"])  # OpenAI chat completions shape
    elif t.get("type") == "function" and "name" in t:
        fn = {k: t[k] for k in ("name", "description", "parameters", "strict") if k in t}  # Responses shape
    elif t.get("type") in (None, "custom") and "input_schema" in t:
        fn = {"name": t.get("name")}  # Anthropic shape
        if t.get("description") is not None:
            fn["description"] = t["description"]
        fn["parameters"] = t["input_schema"]
    elif t.get("type") is None and "name" in t and ("parametersJsonSchema" in t or "parameters" in t):
        fn = {k: t[k] for k in ("name", "description") if k in t}  # Gemini functionDeclaration
        fn["parameters"] = t["parametersJsonSchema"] if "parametersJsonSchema" in t else t["parameters"]
    else:
        raise Reject("unknown_tool_schema_format", f"tool type {t.get('type')!r} has no known schema shape")
    name = fn.get("name")
    if not isinstance(name, str) or not name:
        raise Reject("unknown_tool_schema_format", "tool without a name")
    if "description" in fn and not isinstance(fn["description"], str):
        raise Reject("unknown_tool_schema_format", f"tool {name!r} description is not a string")
    if "parameters" in fn and not isinstance(fn["parameters"], dict):
        raise Reject("unknown_tool_schema_format", f"tool {name!r} parameters is not an object")
    return fn


def _checked_tools(out: list[dict[str, Any]], req: dict[str, Any]) -> list[dict[str, Any]]:
    """Normalized tools must have unique names equal to request_body's tool names."""
    names = [f["function"]["name"] for f in out]
    if len(set(names)) != len(names):
        raise Reject("ambiguous_tool_schema", "duplicate tool names")
    declared = req.get("tools") or []
    if not isinstance(declared, list) or not all(isinstance(x, str) for x in declared) or sorted(declared) != sorted(names):
        raise Reject("tool_schema_mismatch", "tool names differ from request_body tools")
    return out



def _wire_tools(raw_request: str, req: dict[str, Any]) -> list[dict[str, Any]]:
    """Tool schemas from the actual wire body. Empty when the wire body has none."""
    if not raw_request.strip():
        return []
    try:
        wire = json.loads(raw_request)
    except ValueError as e:
        raise Reject("unparseable_raw_request", str(e)) from e
    if not isinstance(wire, dict):
        raise Reject("unparseable_raw_request", "not a JSON object")
    body = wire["request"] if isinstance(wire.get("request"), dict) else wire  # Gemini wraps the request
    tools = body.get("tools")
    if tools is None or tools == []:
        return []
    if not isinstance(tools, list):
        raise Reject("unknown_tool_schema_format", "tools is not a list")
    decls: list[Any] = []
    for t in tools:
        if isinstance(t, dict) and "functionDeclarations" in t:
            decls += _blocks(t["functionDeclarations"])  # Gemini tool groups
        else:
            decls.append(t)
    return _checked_tools([{"type": "function", "function": _tool_function(t)} for t in decls], req)


# ---------------------------------------------------------------- request history


def _flatten(blocks: list[dict[str, Any]]) -> str:
    parts = []
    for b in blocks:
        if b.get("type") != "text":
            raise Reject("unsupported_message", f"tool_result block {b.get('type')!r}")
        parts.append(b.get("text") or "")
    return "".join(parts)


def _args(value: Any) -> str:
    return json.dumps(value if value is not None else {}, ensure_ascii=False)


def _history_assistant(blocks: list[dict[str, Any]]) -> dict[str, Any]:
    texts: list[str] = []
    thoughts: list[str] = []
    calls: list[dict[str, Any]] = []
    opaque = False
    for b in blocks:
        t = b.get("type")
        if t == "text":
            texts.append(b.get("text") or "")
            opaque = opaque or bool(b.get("signature"))
        elif t == "thinking":
            if b.get("thinking"):
                thoughts.append(b["thinking"])
            elif b.get("signature"):
                opaque = True
        elif t == "redacted_thinking":
            opaque = True
        elif t == "tool_use":
            calls.append(
                {
                    "id": b.get("id") or "",
                    "type": "function",
                    "function": {"name": b.get("name") or "", "arguments": _args(b.get("input"))},
                }
            )
            opaque = opaque or bool(b.get("signature"))
        else:
            raise Reject("unsupported_message", f"assistant block {t!r}")
    msg: dict[str, Any] = {"role": "assistant", "content": "".join(texts)}
    if thoughts:
        msg["reasoning"] = "".join(thoughts)
    if opaque:
        msg["reasoning_opaque"] = True
    if calls:
        msg["tool_calls"] = calls
    return msg


def _convert_history(req: dict[str, Any]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    system = req.get("system") or []
    if isinstance(system, str):
        system = [system]
    if not isinstance(system, list) or not all(isinstance(s, str) for s in system):
        raise Reject("unsupported_message", "system is not a list of strings")
    sys_text = "\n\n".join(s for s in system if s)
    if sys_text:
        out.append({"role": "system", "content": sys_text})
    messages = req.get("messages")
    if not isinstance(messages, list):
        raise Reject("unsupported_message", "messages missing")

    pending: set[str] = set()  # tool_use ids awaiting a tool_result
    issued: set[str] = set()  # every tool_use id seen in history
    for msg in messages:
        if not isinstance(msg, dict):
            raise Reject("unsupported_message", "message is not an object")
        role = msg.get("role")
        blocks = _blocks(msg.get("content"))
        if role == "user":
            texts: list[str] = []
            results: list[dict[str, Any]] = []
            for b in blocks:
                t = b.get("type")
                if t == "text":
                    texts.append(b.get("text") or "")
                elif t == "tool_result":
                    results.append(b)
                else:
                    raise Reject("unsupported_message", f"user block {t!r}")
            for r in results:
                tid = r.get("tool_use_id") or ""
                if tid not in pending:
                    raise Reject("unmatched_tool_result", f"tool_use_id {tid!r} answers no open tool call")
                pending.discard(tid)
                entry: dict[str, Any] = {
                    "role": "tool",
                    "tool_call_id": tid,
                    "content": _flatten(_blocks(r.get("content"))),
                }
                if r.get("is_error"):
                    entry["is_error"] = True
                out.append(entry)
            if pending:
                raise Reject("unmatched_tool_call", f"no tool_result for {sorted(pending)}")
            text = "".join(texts)
            if text:
                out.append({"role": "user", "content": text})
        elif role == "assistant":
            if pending:
                raise Reject("unmatched_tool_call", f"no tool_result for {sorted(pending)}")
            converted = _history_assistant(blocks)
            for call in converted.get("tool_calls", []):
                cid = call["id"]
                if not cid or cid in issued:
                    raise Reject("ambiguous_tool_call", f"tool_use id {cid!r} is missing or reused")
                issued.add(cid)
                pending.add(cid)
            out.append(converted)
        else:
            raise Reject("unsupported_message", f"role {role!r}")
    if pending:
        raise Reject("unmatched_tool_call", f"no tool_result for {sorted(pending)}")
    return out


# ---------------------------------------------------------------- records


def _json_object(rec: dict[str, Any], key: str) -> dict[str, Any]:
    value = rec.get(key)
    if value is None or value == "":
        raise Reject(f"missing_{key}")
    if isinstance(value, str):
        try:
            value = json.loads(value)
        except ValueError as e:
            raise Reject(f"unparseable_{key}", str(e)) from e
    if not isinstance(value, dict):
        raise Reject(f"unparseable_{key}", "not a JSON object")
    return value


def _as_text(value: Any) -> str:
    if value is None:
        return ""
    if isinstance(value, str):
        return value
    return json.dumps(value, ensure_ascii=False)


# ---------------------------------------------------------------- reasoning kinds


def _load_provenance(raw_dir: str) -> dict[str, tuple[str, str]]:
    """profile_name -> (model_backend, provenance). An absent or blank file maps nothing."""
    path = os.path.join(raw_dir, PROVENANCE_FILE)
    if not os.path.isfile(path):
        return {}
    with open(path, encoding="utf-8") as f:
        text = f.read()
    if not text.strip():
        return {}
    try:
        doc = json.loads(text)
    except ValueError as e:
        raise ValueError(f"{path}: {e}") from e
    profiles = doc.get("reasoning_profiles") if isinstance(doc, dict) else None
    if not isinstance(profiles, dict):
        raise ValueError(f"{path}: expected an object with a reasoning_profiles object")
    out: dict[str, tuple[str, str]] = {}
    for name, entry in profiles.items():
        entry = entry if isinstance(entry, dict) else {}
        backend, prov = entry.get("model_backend"), entry.get("provenance")
        if not (isinstance(backend, str) and backend and isinstance(prov, str) and prov):
            raise ValueError(f"{path}: profile {name!r} needs non-empty model_backend and provenance strings")
        out[name] = (backend, prov)
    return out


def _provenance_for(mapping: dict[str, tuple[str, str]], profile_name: Any) -> tuple[str, str]:
    if isinstance(profile_name, str) and profile_name in mapping:
        return mapping[profile_name]
    return "unknown", "unknown"


def _kind_for(label: str, verified: bool, summarized: bool) -> str:
    if label in ("responses.summary", "gemini.thought", "sdk.summary"):
        return "summary"
    if label == "anthropic.thinking":
        return "summary" if summarized else "anthropic_thinking"
    return "raw" if verified else "unclassified"


def _display_summarized(raw_request: str) -> bool:
    """True only when the captured wire body itself asks for summarized thinking."""
    try:
        wire = json.loads(raw_request)
    except ValueError:
        return False
    thinking = wire.get("thinking") if isinstance(wire, dict) else None
    return isinstance(thinking, dict) and thinking.get("display") == "summarized"


def _reasoning_view(rec: dict[str, Any], mapping: dict[str, tuple[str, str]], parsed: dict[str, Any]) -> dict[str, Any]:
    backend, prov = _provenance_for(mapping, rec.get("profile_name"))
    verified = prov == RAW_PROVENANCE
    summarized = _display_summarized(_as_text(rec.get("raw_request")))
    blocks = [
        {"kind": _kind_for(b["field"], verified, summarized), "field": b["field"], "text": b["text"]}
        for b in parsed["reasoning_blocks"]
    ]
    opaque = parsed["opaque_blocks"]
    kinds = {b["kind"] for b in blocks}
    if len(kinds) > 1:
        kind = "mixed"
    elif kinds:
        kind = kinds.pop()
    elif opaque:
        kind = "opaque"
    else:
        kind = "none"
    return {
        "model_backend": backend,
        "provenance": prov,
        "kind": kind,
        "fields": sorted({b["field"] for b in blocks} | {o["field"] for o in opaque}),
        "blocks": blocks,
        "opaque": opaque,
        "unsupported": parsed["unsupported"],
        "unselected": parsed["unselected"],
        "budget_exhausted": parsed["budget_exhausted"],
    }


def _build_sample(rec: dict[str, Any], mapping: dict[str, tuple[str, str]]) -> dict[str, Any]:
    if rec.get("status") == "refused":
        raise Reject("refused", str(rec.get("error") or "provider refused"))
    if rec.get("status") != "ok":
        raise Reject("status_error", str(rec.get("error") or rec.get("status") or "no status"))
    req = _json_object(rec, "request_body")
    resp = _json_object(rec, "response_body")
    raw = _as_text(rec.get("raw_response"))
    if not raw.strip():
        raise Reject("missing_raw_response", "tool calls are only recoverable from raw_response")
    bridge = _sdk_request(rec)
    parsed = _recover(rec, req)
    if parsed["stop_reason"] == "refusal":
        raise Reject("refused", "provider reported a refusal")

    if parsed["text"] != (resp.get("text") or ""):
        raise Reject("response_mismatch", "text differs from response_body")
    if parsed["thinking"] != (resp.get("thinking") or ""):
        raise Reject("response_mismatch", "thinking differs from response_body")
    stop = parsed["stop_reason"]
    if stop != (resp.get("stop_reason") or ""):
        raise Reject("response_mismatch", f"stop_reason {stop!r} differs from response_body")
    if not stop:
        raise Reject("missing_stop_reason")
    if stop == "max_tokens":
        raise Reject("truncated_max_tokens", "response was cut off")

    view = _reasoning_view(rec, mapping, parsed)
    tools = _sdk_tools(bridge, req) if bridge is not None else _wire_tools(_as_text(rec.get("raw_request")), req)
    history = _sdk_convert_history(bridge["context"]) if bridge is not None else _convert_history(req)
    target: dict[str, Any] = {"role": "assistant", "content": parsed["text"]}
    if parsed["thinking"]:
        target["reasoning"] = parsed["thinking"]
    calls = []
    for c in parsed["tool_calls"]:
        if not c["id"] or not c["name"]:
            raise Reject("ambiguous_tool_call", "tool call without id or name")
        calls.append({"id": c["id"], "type": "function", "function": {"name": c["name"], "arguments": c["arguments"]}})
    if calls:
        target["tool_calls"] = calls

    sample: dict[str, Any] = {"id": rec.get("id"), "messages": history + [target]}
    if tools:
        sample["tools"] = tools
    sample["metadata"] = {
        "session_id": rec.get("session_id"),
        "task_id": rec.get("task_id"),
        "worker": rec.get("worker"),
        "model": rec.get("model"),
        "profile_name": rec.get("profile_name"),
        "ts": rec.get("ts"),
        "latency_ms": rec.get("latency_ms"),
        "status": "ok",
        "stop_reason": stop,
        "usage": {
            "input_tokens": rec.get("input_tokens"),
            "output_tokens": rec.get("output_tokens"),
            "cache_read": rec.get("cache_read"),
            "cache_write": rec.get("cache_write"),
        },
        "tools_offered": req.get("tools") or [],
        "tools_called": [c["name"] for c in parsed["tool_calls"]],
        "tools_schema_source": ("sdk_context" if bridge is not None else "raw_request") if tools else "none",
        "thinking_config": req.get("thinking") if bridge is None else bridge.get("options"),
        "reasoning_source": "explicit" if parsed["thinking"] else "none",
        "reasoning_opaque": parsed["opaque_reasoning"],
        "model_backend": view["model_backend"],
        "provenance": view["provenance"],
        "reasoning_kind": view["kind"],
        "reasoning_fields": view["fields"],
        "reasoning_budget_exhausted": view["budget_exhausted"],
    }
    return sample


# ---------------------------------------------------------------- redaction

# Heuristic only. Matches common secret shapes, not every secret.
_SECRET_KEY = re.compile(
    r"(^|[_.-])(api[_-]?key|apikey|authorization|x-api-key|password|passwd|secret|token|access[_-]?token|refresh[_-]?token|cookie)$",
    re.I,
)
_SECRET_PATTERNS = (
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{8,}"), "Bearer [REDACTED]"),
    (
        re.compile(r"(?i)\b(authorization|x-api-key|api[_-]?key|password|passwd|secret|token)(['\"]?\s*[:=]\s*['\"]?)[^\s'\"\\,}&]{6,}"),
        r"\1\2[REDACTED]",
    ),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}"), "[REDACTED]"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "[REDACTED]"),
    (re.compile(r"\bgh[pousr]_[A-Za-z0-9]{20,}\b"), "[REDACTED]"),
)


def _redact(value: Any, key: str = "") -> Any:
    if isinstance(value, dict):
        return {k: _redact(v, str(k)) for k, v in value.items()}
    if isinstance(value, list):
        return [_redact(v, key) for v in value]
    if isinstance(value, str):
        if value and key and _SECRET_KEY.search(key):
            return "[REDACTED]"
        # arguments is JSON text: redact the values inside and re-serialize so escapes survive
        if key == "arguments":
            try:
                parsed = json.loads(value)
            except ValueError:
                parsed = None  # not JSON: plain-text patterns below
            if isinstance(parsed, (dict, list)):
                return json.dumps(_redact(parsed), ensure_ascii=False)
        for pat, repl in _SECRET_PATTERNS:
            value = pat.sub(repl, value)
        return value
    return value


# ---------------------------------------------------------------- export


def _reject(out, counts: dict[str, Any], lineno: int, rec: dict[str, Any] | None, err: Reject, record: Any) -> None:
    counts["rejected"] += 1
    by = counts["rejects_by_reason"]
    by[err.reason] = by.get(err.reason, 0) + 1
    entry = {
        "line": lineno,
        "id": rec.get("id") if rec else None,
        "reason": err.reason,
        "detail": err.detail,
        "record": record,
    }
    out.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _parse_record(text: str) -> dict[str, Any]:
    try:
        rec = json.loads(text)
    except ValueError as e:
        raise Reject("malformed_record", str(e)) from e
    if not isinstance(rec, dict):
        raise Reject("malformed_record", "not a JSON object")
    return rec


_SIDECAR_META = ("id", "ts", "model", "profile_name", "session_id", "task_id", "status")


def _write_lines(out, lines: list[dict[str, Any]]) -> None:
    for entry in lines:
        out.write(json.dumps(entry, ensure_ascii=False) + "\n")


def _reasoning_lines(lineno: int, rec: dict[str, Any] | None, mapping: dict[str, tuple[str, str]], reject: str) -> list[dict[str, Any]]:
    """Sidecar lines for one source line. Opaque payloads are digests only, never text."""
    meta = {k: rec.get(k) for k in _SIDECAR_META} if rec is not None else dict.fromkeys(_SIDECAR_META)
    base = {"line": lineno, **meta, "accepted": reject == "", "reject": reject}
    view = None
    if rec is not None:
        try:
            parsed = _recover(rec, _json_object(rec, "request_body"))
            view = _reasoning_view(rec, mapping, parsed)
        except (Reject, AttributeError, TypeError, KeyError, IndexError, ValueError):
            pass  # unparseable: a single not_recovered line below
    if view is None:
        backend, prov = _provenance_for(mapping, meta["profile_name"])
        return [{**base, "model_backend": backend, "provenance": prov, "budget_exhausted": None, "kind": "not_recovered", "field": ""}]
    head = {**base, "model_backend": view["model_backend"], "provenance": view["provenance"], "budget_exhausted": view["budget_exhausted"]}
    lines = [{**head, "kind": b["kind"], "field": b["field"], "text": b["text"]} for b in view["blocks"]]
    lines += [{**head, "kind": "opaque", "field": o["field"], "bytes": o["bytes"], "sha256": o["sha256"]} for o in view["opaque"]]
    lines += [{**head, "kind": "unsupported", "field": u["field"], "bytes": u["bytes"]} for u in view["unsupported"]]
    lines += [{**head, "kind": "unselected", "field": u["field"], "text": u["text"]} for u in view["unselected"]]
    return lines



def export(raw_dir: str, out_dir: str) -> dict[str, Any]:
    """Export raw_dir/llm_records.jsonl. Writes redacted train.jsonl and NOTICE.txt to
    out_dir, and unredacted rejects.jsonl and reasoning.jsonl to raw_dir. Returns counts."""
    records_path = os.path.join(raw_dir, RECORDS_FILE)
    if not os.path.isfile(records_path):
        raise FileNotFoundError(f"{records_path} not found")
    mapping = _load_provenance(raw_dir)
    _private_dir(out_dir)
    train_path = os.path.join(out_dir, TRAIN_FILE)
    rejects_path = os.path.join(raw_dir, REJECTS_FILE)
    reasoning_path = os.path.join(raw_dir, REASONING_FILE)
    counts: dict[str, Any] = {"records": 0, "exported": 0, "rejected": 0, "rejects_by_reason": {}}

    with contextlib.ExitStack() as stack, open(records_path, encoding="utf-8") as src:
        train = stack.enter_context(_open_private(train_path))
        rejects = stack.enter_context(_open_private(rejects_path))
        sidecar = stack.enter_context(_open_private(reasoning_path))
        for lineno, line in enumerate(src, 1):
            text = line.strip()
            if not text:
                continue
            counts["records"] += 1
            try:
                rec = _parse_record(text)
            except Reject as r:
                _reject(rejects, counts, lineno, None, r, text)
                _write_lines(sidecar, _reasoning_lines(lineno, None, mapping, r.reason))
                continue
            reject = ""
            try:
                sample = _build_sample(rec, mapping)
            except Reject as r:
                _reject(rejects, counts, lineno, rec, r, rec)
                reject = r.reason
            except (AttributeError, TypeError, KeyError, IndexError, ValueError) as e:
                # malformed provider shape: keep the record verbatim and keep going
                r = Reject("malformed_provider_record", f"{type(e).__name__}: {e}")
                _reject(rejects, counts, lineno, rec, r, rec)
                reject = r.reason
            else:
                train.write(json.dumps(_redact(sample), ensure_ascii=False) + "\n")
                counts["exported"] += 1
            _write_lines(sidecar, _reasoning_lines(lineno, rec, mapping, reject))

    _write_private(os.path.join(out_dir, NOTICE_FILE), NOTICE)
    counts["train_file"] = train_path
    counts["rejects_file"] = rejects_path
    return counts


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(
        description="Export ARTEX llm_records to redacted training JSONL. Rejects and reasoning.jsonl go to <raw-dir>.",
    )
    p.add_argument("--raw-dir", required=True, help="snapshot dir containing llm_records.jsonl")
    p.add_argument("--output-dir", required=True, help="training dir for train.jsonl and NOTICE.txt (created 0700)")
    a = p.parse_args(argv)
    counts = export(a.raw_dir, a.output_dir)
    print(json.dumps(counts, indent=2, sort_keys=True))
    return 0


if __name__ == "__main__":
    sys.exit(main())
