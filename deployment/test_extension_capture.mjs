import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const source = readFileSync(new URL("../m1nervac0nsole/extension/background.js", import.meta.url), "utf8");

function captureHarness(bodies) {
  const handlers = {};
  const sent = [];
  const chrome = {
    storage: {
      local: { get: async () => ({ serverUrl: "http://fixture.invalid///", token: "fixture-token" }), set: async () => {} },
      session: { set: async () => {} },
    },
    tabs: { query: async () => [{ id: 7 }] },
    action: { setBadgeText() {}, setBadgeBackgroundColor() {} },
    debugger: {
      attach: async () => {}, detach: async () => {},
      onEvent: { addListener(fn) { handlers.event = fn; } },
      onDetach: { addListener(fn) { handlers.detach = fn; } },
      async sendCommand(_target, method, params) {
        if (method !== "Network.getResponseBody") return {};
        const body = bodies[params.requestId];
        if (body instanceof Error) throw body;
        assert.notEqual(body, undefined, `body must not be read for ${params.requestId}`);
        return { body, base64Encoded: false };
      },
    },
    runtime: { onMessage: { addListener(fn) { handlers.message = fn; } } },
  };
  const context = {
    chrome,
    // the worker loads its queue helpers with importScripts; run them in the same context
    importScripts(file) {
      vm.runInContext(readFileSync(new URL(`../m1nervac0nsole/extension/${file}`, import.meta.url), "utf8"), context);
    },
    async fetch(url, options) {
      const payload = JSON.parse(options.body);
      sent.push({ url, method: options.method, headers: { ...options.headers }, payload });
      return { ok: true, json: async () => ({ ingested: payload.exchanges.length, failed: 0 }) };
    },
  };
  // probe the real module-scoped session so a leak in the pending-request map is observable
  vm.runInNewContext(`${source}\nglobalThis.__pendingRequests = () => session.requests.size;`, context, {
    filename: "extension/background.js",
  });
  return {
    sent,
    pendingRequests() {
      return context.__pendingRequests();
    },
    message(type) {
      return new Promise((resolve) => handlers.message({ type }, null, resolve));
    },
    async exchange(requestId, response, tabId = 7) {
      const emit = (method, params) => handlers.event({ tabId }, method, { requestId, ...params });
      emit("Network.requestWillBeSent", { request: {
        method: "POST", url: `https://target.invalid/${requestId}`,
        headers: { "Content-Type": "application/json" }, postData: '{"task":"fixture"}',
      } });
      emit("Network.responseReceived", { response });
      emit("Network.loadingFinished", {});
      await new Promise(setImmediate);
    },
    async failed(requestId, errorText, tabId = 7) {
      const emit = (method, params) => handlers.event({ tabId }, method, { requestId, ...params });
      emit("Network.requestWillBeSent", { request: {
        method: "GET", url: `https://target.invalid/${requestId}`, headers: { "X-Probe": "1" },
      } });
      emit("Network.loadingFailed", { errorText });
      await new Promise(setImmediate);
    },
  };
}

test("CDP header objects yield normalized headers and captured bodies in the authenticated batch", async () => {
  const capture = captureHarness({ text: '{"result":"captured"}' });
  await capture.message("start");
  await capture.exchange("text", { status: 201, headers: {
    "Content-Type": "application/json; charset=utf-8", "X-Mixed-Case": "value", "Content-Length": 21,
  } });
  const state = await capture.message("flushNow");
  assert.deepEqual(capture.sent, [{
    url: "http://fixture.invalid/api/traffic/ingest", method: "POST",
    headers: { Authorization: "Bearer fixture-token", "Content-Type": "application/json" },
    payload: { exchanges: [{
      method: "POST", url: "https://target.invalid/text", status: 201,
      // failed=false: a response arrived, so the server must not treat status 0 as a failure
      failed: false,
      requestHeaders: { "Content-Type": "application/json" }, requestBody: '{"task":"fixture"}',
      responseHeaders: {
        "content-type": "application/json; charset=utf-8", "x-mixed-case": "value", "content-length": "21",
      },
      responseBody: '{"result":"captured"}',
    }] },
  }]);
  assert.equal(state.lastError, "");
  assert.equal(state.queued, 0);
});

test("headerless and discarded bodies still capture metadata; skipped MIME and other tabs do not leak bodies", async () => {
  const capture = captureHarness({ headerless: "plain response", discarded: new Error("body discarded") });
  await capture.message("start");
  await capture.exchange("headerless", { status: 200 });
  await capture.exchange("image", { status: 200, headers: { "Content-Type": "IMAGE/PNG" } });
  await capture.exchange("discarded", { status: 410, headers: { "X-Result": "gone" } });
  await capture.exchange("other-tab", { status: 200, headers: {} }, 8);
  const state = await capture.message("flushNow");
  assert.deepEqual(capture.sent.flatMap(({ payload }) => payload.exchanges).map((exchange) => ({
    url: exchange.url, status: exchange.status, headers: exchange.responseHeaders, body: exchange.responseBody,
  })), [
    { url: "https://target.invalid/headerless", status: 200, headers: {}, body: "plain response" },
    { url: "https://target.invalid/image", status: 200, headers: { "content-type": "IMAGE/PNG" }, body: "" },
    { url: "https://target.invalid/discarded", status: 410, headers: { "x-result": "gone" }, body: "" },
  ]);
  assert.equal(state.lastError, "");
});

test("a blocked or aborted request is captured as evidence and frees its pending slot", async () => {
  const capture = captureHarness({});
  await capture.message("start");
  await capture.failed("waf", "net::ERR_BLOCKED_BY_CLIENT");
  await capture.failed("aborted", "net::ERR_ABORTED");
  const state = await capture.message("flushNow");

  // A failed request never reaches responseReceived, so before this fix it was
  // dropped entirely: a WAF block or auth failure left no trace in the capture.
  assert.deepEqual(
    capture.sent.flatMap(({ payload }) => payload.exchanges).map((e) => ({
      url: e.url, status: e.status, failed: e.failed, err: e.responseHeaders["x-capture-error"],
    })),
    [
      { url: "https://target.invalid/waf", status: 0, failed: true, err: "net::ERR_BLOCKED_BY_CLIENT" },
      { url: "https://target.invalid/aborted", status: 0, failed: true, err: "net::ERR_ABORTED" },
    ],
  );
  assert.equal(state.lastError, "");
  assert.equal(capture.pendingRequests(), 0, "the partial request entry outlived the request");
});
