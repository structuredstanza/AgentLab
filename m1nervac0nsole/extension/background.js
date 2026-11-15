// m1nervac0nsole Traffic Capture — background service worker.
//
// Captures the network activity of one tab through the chrome.debugger API
// (Network domain) and pushes text request/response pairs to the m1nervac0nsole
// ingest endpoint in batches. Counters live in chrome.storage.session so the
// popup and the (short-lived) service worker share one view; the pending queue
// and the ids the server already accepted live in chrome.storage.local, so a
// restart or a worker recycle neither drops a capture nor resends one.

importScripts("queue.js"); // pure queue helpers, kept out of this file to be testable

const { QUEUE_CAP, SENT_CAP, newId, cap, pending, takeBatch, rememberSent } = CaptureQueue;

const FLUSH_AT = 10; // entries per batch
const MAX_BODY = 256 * 1024; // matches the server-side ingest cap
const SKIP_MIME = ["image/", "font/", "audio/", "video/", "application/octet-stream"];

let session = {
  capturing: false,
  tabId: null,
  queue: [], // pending ExternalExchange objects, persisted in storage.local
  sentIds: [], // ids the server already accepted, persisted alongside the queue
  requests: new Map(), // debugger requestId -> partial request info
  ingested: 0,
  failed: 0,
  lastError: "",
};

async function saveState() {
  await chrome.storage.session.set({
    capturing: session.capturing,
    tabId: session.tabId,
    ingested: session.ingested,
    failed: session.failed,
    lastError: session.lastError,
    queued: session.queue.length,
  });
}

// Queue and accepted-ids are written together, so a restart can never restore a
// queue whose entries the server already has without the ids that suppress them.
async function saveQueue() {
  for (;;) {
    try {
      await chrome.storage.local.set({ pendingQueue: session.queue, sentIds: session.sentIds });
      return;
    } catch (e) {
      // storage.local is capped (~10 MB): shed the oldest half rather than lose
      // the whole queue to one oversized capture
      if (session.queue.length <= 1) throw e;
      session.queue = session.queue.slice(Math.ceil(session.queue.length / 2));
    }
  }
}

let restored = null;

// The service worker is recycled freely, so the queue is reloaded on first use.
function restoreQueue() {
  if (!restored) {
    restored = (async () => {
      const { pendingQueue = [], sentIds = [] } = await chrome.storage.local.get(["pendingQueue", "sentIds"]);
      session.sentIds = sentIds;
      session.queue = cap(pending(session.queue.concat(pendingQueue), sentIds), QUEUE_CAP);
    })().catch(() => {
      // no readable queue: start empty, live captures still flush
    });
  }
  return restored;
}

async function getConfig() {
  const { serverUrl = "", token = "" } = await chrome.storage.local.get(["serverUrl", "token"]);
  return { serverUrl: serverUrl.replace(/\/+$/, ""), token };
}

async function getActiveTabId() {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  return tab ? tab.id : null;
}

async function start() {
  if (session.capturing) return { ok: true };
  await restoreQueue();
  const { serverUrl, token } = await getConfig();
  if (!serverUrl || !token) {
    return { ok: false, error: "Set the console URL and token first." };
  }
  const tabId = await getActiveTabId();
  if (tabId == null) return { ok: false, error: "No active tab." };
  try {
    await chrome.debugger.attach({ tabId }, "1.3");
  } catch (e) {
    return { ok: false, error: `attach failed: ${e.message}` };
  }
  await chrome.debugger.sendCommand({ tabId }, "Network.enable", {});
  // queue and sentIds survive: unsent captures from a previous session are
  // flushed rather than discarded when a new capture starts
  session = { ...session, capturing: true, tabId, requests: new Map(), ingested: 0, failed: 0, lastError: "" };
  chrome.action.setBadgeText({ text: "REC" });
  chrome.action.setBadgeBackgroundColor({ color: "#c2410c" });
  await saveState();
  await flush();
  return { ok: true };
}

async function stop() {
  if (session.capturing && session.tabId != null) {
    await flush();
    try {
      await chrome.debugger.sendCommand({ tabId: session.tabId }, "Network.disable", {});
      await chrome.debugger.detach({ tabId: session.tabId });
    } catch (_) {
      // tab may already be gone; nothing to do
    }
  }
  session.capturing = false;
  session.tabId = null;
  chrome.action.setBadgeText({ text: "" });
  await saveState();
  return { ok: true };
}

function skipBody(mimeType) {
  const mt = (mimeType || "").toLowerCase();
  return SKIP_MIME.some((p) => mt.startsWith(p));
}

function truncate(s) {
  if (s.length <= MAX_BODY) return s;
  return s.slice(0, MAX_BODY) + "\n... [truncated by extension]";
}

async function queueExchange(info, response) {
  const respHeaders = {};
  for (const [name, value] of Object.entries(response.headers || {})) {
    respHeaders[name.toLowerCase()] = String(value);
  }
  const mime = respHeaders["content-type"] || "";

  let reqBody = truncate(info.postData || "");
  let respBody = "";
  if (info.error) {
    // no response to read; record why it failed so the capture stays evidence
    respHeaders["x-capture-error"] = info.error;
  } else if (!skipBody(mime)) {
    try {
      const body = await chrome.debugger.sendCommand(
        { tabId: session.tabId },
        "Network.getResponseBody",
        { requestId: info.requestId }
      );
      if (body && !body.base64Encoded) {
        reqBody = truncate(reqBody);
        respBody = truncate(body.body || "");
      }
    } catch (_) {
      // body already discarded by the browser; capture the pair without bodies
    }
  }

  session.queue = cap(session.queue.concat([{
    id: newId(),
    method: info.method,
    url: info.url,
    status: response.status || 0,
    // the server records status 0 as success unless it knows no response arrived
    failed: !!info.error,
    requestHeaders: info.headers || {},
    requestBody: reqBody,
    responseHeaders: respHeaders,
    responseBody: respBody,
  }]), QUEUE_CAP);
  if (session.queue.length >= FLUSH_AT) await flush();
  else await saveQueue();
}

async function flush() {
  await restoreQueue();
  // drop whatever the server already accepted before the last restart
  session.queue = pending(session.queue, session.sentIds);
  if (session.queue.length === 0) {
    await saveQueue();
    return;
  }
  const { serverUrl, token } = await getConfig();
  if (!serverUrl || !token) {
    session.lastError = "missing server URL or token";
    await saveState();
    return;
  }
  const { batch, rest } = takeBatch(session.queue, FLUSH_AT);
  session.queue = rest;
  try {
    const res = await fetch(`${serverUrl}/api/traffic/ingest`, {
      method: "POST",
      headers: { "Authorization": `Bearer ${token}`, "Content-Type": "application/json" },
      // the id is local bookkeeping; the ingest payload stays as it was
      body: JSON.stringify({ exchanges: batch.map(({ id, ...exchange }) => exchange) }),
    });
    if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 200)}`);
    const out = await res.json();
    session.ingested += out.ingested || 0;
    session.failed += out.failed || 0;
    // recorded before the queue write, so a restart cannot resend this batch
    session.sentIds = rememberSent(session.sentIds, batch.map((e) => e.id), SENT_CAP);
    session.lastError = out.failed ? `${out.failed} entries rejected by the server` : "";
  } catch (e) {
    // put the batch back (oldest first) but cap the queue so a dead server
    // cannot grow it unbounded; the cap drops the oldest entries
    session.queue = cap(batch.concat(session.queue), QUEUE_CAP);
    session.lastError = e.message;
  }
  await saveQueue();
  await saveState();
}

chrome.debugger.onEvent.addListener((source, method, params) => {
  if (!session.capturing || !source.tabId || source.tabId !== session.tabId) return;
  if (method === "Network.requestWillBeSent") {
    session.requests.set(params.requestId, {
      requestId: params.requestId,
      method: params.request.method,
      url: params.request.url,
      headers: params.request.headers,
      postData: params.request.postData || "",
    });
  } else if (method === "Network.responseReceived") {
    const info = session.requests.get(params.requestId);
    if (info) info.response = params.response;
  } else if (method === "Network.loadingFinished") {
    const info = session.requests.get(params.requestId);
    session.requests.delete(params.requestId);
    if (!info || !info.response) return;
    queueExchange(info, info.response).catch((e) => {
      session.lastError = e.message;
      saveState();
    });
  } else if (method === "Network.loadingFailed") {
    // A blocked, aborted or failed request never reaches responseReceived, so it
    // used to be dropped from the capture entirely and its partial entry stayed
    // in the map for the rest of the session. A WAF block or an auth failure is
    // exactly the evidence a capture session exists to collect.
    const info = session.requests.get(params.requestId);
    session.requests.delete(params.requestId);
    if (!info) return;
    queueExchange({ ...info, error: params.errorText || "request failed" }, { status: 0, headers: {} }).catch((e) => {
      session.lastError = e.message;
      saveState();
    });
  }
});

chrome.debugger.onDetach.addListener((source) => {
  if (session.capturing && source.tabId === session.tabId) {
    // DevTools opened, or the tab navigated somewhere undebaggable: stop
    // cleanly instead of silently dropping events.
    session.capturing = false;
    session.tabId = null;
    session.lastError = "debugger detached (DevTools opened?)";
    chrome.action.setBadgeText({ text: "" });
    saveState();
  }
});

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    // a recycled worker answers getState before anything else touches the queue
    await restoreQueue();
    switch (msg?.type) {
      case "getState": {
        sendResponse({
          capturing: session.capturing,
          tabId: session.tabId,
          ingested: session.ingested,
          failed: session.failed,
          queued: session.queue.length,
          lastError: session.lastError,
          configured: !!(await getConfig()).serverUrl,
        });
        return;
      }
      case "start":
        sendResponse(await start());
        return;
      case "stop":
        sendResponse(await stop());
        return;
      case "flushNow":
        await flush();
        sendResponse(await stateSnapshot());
        return;
      default:
        sendResponse({ ok: false, error: "unknown message" });
    }
  })();
  return true; // async sendResponse
});

async function stateSnapshot() {
  return {
    capturing: session.capturing,
    tabId: session.tabId,
    ingested: session.ingested,
    failed: session.failed,
    queued: session.queue.length,
    lastError: session.lastError,
  };
}
