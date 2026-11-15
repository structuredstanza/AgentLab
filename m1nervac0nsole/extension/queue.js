// Pending-capture queue for the background service worker.
//
// A classic script loaded with importScripts rather than a module, so the same
// file runs unchanged in the deployment harness's vm context. Every function is
// pure over plain arrays; the caller owns storage.

globalThis.CaptureQueue = (() => {
  const QUEUE_CAP = 200; // pending entries kept across a restart
  const SENT_CAP = 500; // ids remembered so a restart cannot resend

  let seq = 0;

  // Stable per-entry id, assigned once at capture time and persisted with the
  // entry, so a restored queue keeps the identity the server already accepted.
  // Not crypto.randomUUID: the vm harness has no WebCrypto.
  function newId() {
    seq += 1;
    return `${Date.now().toString(36)}-${seq.toString(36)}-${Math.random().toString(36).slice(2, 10)}`;
  }

  // Oldest entries go first: the newest capture is the one being inspected.
  function cap(list, limit = QUEUE_CAP) {
    return list.length > limit ? list.slice(list.length - limit) : list;
  }

  // Entries the server has not acknowledged yet.
  function pending(queue, sentIds) {
    const sent = new Set(sentIds);
    return queue.filter((e) => e && !sent.has(e.id));
  }

  function takeBatch(queue, size) {
    return { batch: queue.slice(0, size), rest: queue.slice(size) };
  }

  function rememberSent(sentIds, ids, limit = SENT_CAP) {
    return cap(sentIds.concat(ids.filter(Boolean)), limit);
  }

  return { QUEUE_CAP, SENT_CAP, newId, cap, pending, takeBatch, rememberSent };
})();
