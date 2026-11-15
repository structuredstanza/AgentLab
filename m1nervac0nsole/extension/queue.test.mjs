// Self-check for the capture queue. Run with: node --test (from extension/)
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import vm from "node:vm";

// loaded exactly as the service worker loads it: a plain script, no module
const context = vm.createContext({});
vm.runInContext(readFileSync(new URL("./queue.js", import.meta.url), "utf8"), context);
const { QUEUE_CAP, SENT_CAP, newId, cap, pending, takeBatch, rememberSent } = context.CaptureQueue;

// What chrome.storage.local does to a value: JSON round-trip.
const stored = (v) => JSON.parse(JSON.stringify(v));

const entry = (n) => ({ id: newId(), method: "GET", url: `https://x.example/${n}` });

test("queued captures survive a restart", () => {
  const queue = [entry(1), entry(2), entry(3)];
  const restored = stored(queue);
  assert.equal(restored.length, 3);
  assert.deepEqual(
    pending(restored, []).map((e) => e.url),
    ["https://x.example/1", "https://x.example/2", "https://x.example/3"]
  );
});

test("a flush after restart sends no duplicate", () => {
  const queue = [entry(1), entry(2), entry(3)];
  // first flush lands entry 1 and records its id
  const { batch, rest } = takeBatch(queue, 1);
  assert.equal(batch.length, 1);
  const sentIds = rememberSent([], batch.map((e) => e.id));
  // restart: the queue write is stale and still holds entry 1
  const restored = stored([batch[0], ...rest]);
  const toSend = pending(restored, stored(sentIds));
  assert.deepEqual(
    toSend.map((e) => e.url),
    ["https://x.example/2", "https://x.example/3"]
  );
  assert.equal(toSend.filter((e) => e.id === batch[0].id).length, 0);
});

test("the cap drops the oldest entries, not the newest", () => {
  let queue = [];
  for (let i = 1; i <= QUEUE_CAP + 5; i++) queue = cap(queue.concat([entry(i)]), QUEUE_CAP);
  assert.equal(queue.length, QUEUE_CAP);
  assert.equal(queue[queue.length - 1].url, `https://x.example/${QUEUE_CAP + 5}`);
  assert.equal(queue[0].url, "https://x.example/6");
});

test("takeBatch splits oldest-first and leaves the rest", () => {
  const queue = [entry(1), entry(2), entry(3)];
  const { batch, rest } = takeBatch(queue, 2);
  assert.deepEqual(batch.map((e) => e.url), ["https://x.example/1", "https://x.example/2"]);
  assert.deepEqual(rest.map((e) => e.url), ["https://x.example/3"]);
});

test("sent ids are bounded and ignore entries without an id", () => {
  let sentIds = [];
  for (let i = 0; i < SENT_CAP + 3; i++) sentIds = rememberSent(sentIds, [newId()]);
  assert.equal(sentIds.length, SENT_CAP);
  assert.equal(rememberSent(sentIds, [undefined, null]).length, SENT_CAP);
});
