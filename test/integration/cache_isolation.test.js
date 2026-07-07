// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/integration/cache_isolation.test.js
// Integration tests for cache safety fixes:
//   1. RFC 8484 SS.4.1: wire GET queries have their DNS transaction ID zeroed
//      before responses are built and cached, so one client's ID never leaks
//      to another client through a shared cache entry.
//   2. ?cd=1 JSON queries are cached separately from cd=0 queries, so
//      responses obtained with DNSSEC validation disabled cannot poison the
//      cache entry served to validating clients.

import { describe, it, expect, vi, afterEach } from "vitest";
import { handleRequest } from "../../src/handler.js";
import { buildDnsQuery, buildDnsQueryWithDo, buildDnsResponse } from "../../src/dns.js";

function makeFakeCache() {
  const store = new Map();
  return {
    store,
    async match(req) {
      return store.get(typeof req === "string" ? req : req.url) || null;
    },
    async put(req, resp) {
      store.set(typeof req === "string" ? req : req.url, resp.clone());
    },
  };
}

async function dispatchWithEnv(request, env, fakeCache) {
  const cache = fakeCache || makeFakeCache();
  const waitUntilTasks = [];
  const ctx = { waitUntil: (p) => waitUntilTasks.push(p) };
  const origCaches = globalThis.caches;
  globalThis.caches = { default: cache };
  try {
    const response = await handleRequest(request, env || {}, ctx);
    await Promise.allSettled(waitUntilTasks);
    return { response, cache };
  } finally {
    globalThis.caches = origCaches;
  }
}

function toBase64url(buf) {
  let b = "";
  for (let i = 0; i < buf.length; i++) b += String.fromCharCode(buf[i]);
  return btoa(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

function fromBase64url(b64) {
  const padded = b64.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - b64.length % 4) % 4);
  const bin = atob(padded);
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

afterEach(() => { vi.restoreAllMocks(); });

// ---------------------------------------------------------------------------
// Wire GET: client DNS ID must never reach the cache
// ---------------------------------------------------------------------------

describe("Wire GET - DNS transaction ID is zeroed in cached responses", () => {
  // A delayed blocked upstream response forces the phase-2 path (past the
  // MIN_WAIT_MS race), which is the path that writes blocked responses to the
  // edge cache.
  function makeDelayedBlockedFetch(delayMs) {
    const body = buildDnsResponse("blocked.example.com.", "0.0.0.0", 0);
    return vi.fn(
      (url) =>
        new Promise((resolve) =>
          setTimeout(
            () =>
              resolve(
                new Response(body, {
                  headers: { "Content-Type": "application/dns-message" },
                })
              ),
            delayMs
          )
        )
    );
  }

  it("caches the blocked response with ID=0 and restores the client ID on the reply", async () => {
    globalThis.fetch = makeDelayedBlockedFetch(100);

    const query = buildDnsQuery("blocked.example.com", 1, 0x1234);
    const req = new Request(`https://w.example.com/dns-query?dns=${toBase64url(query)}`);
    const { response, cache } = await dispatchWithEnv(req, { MIN_WAIT_MS: "10" });

    // Direct reply carries the client's original transaction ID
    const replyBuf = new Uint8Array(await response.arrayBuffer());
    expect((replyBuf[0] << 8) | replyBuf[1]).toBe(0x1234);
    expect(response.headers.get("x-blocked")).toBe("true");

    // The cached copy must have ID=0 (RFC 8484 SS.4.1)
    expect(cache.store.size).toBe(1);
    const cachedResp = [...cache.store.values()][0];
    const cachedBuf = new Uint8Array(await cachedResp.clone().arrayBuffer());
    expect(cachedBuf[0]).toBe(0);
    expect(cachedBuf[1]).toBe(0);
  });

  it("a second client with ID=0 does not receive the first client's ID from cache", async () => {
    globalThis.fetch = makeDelayedBlockedFetch(100);
    const cache = makeFakeCache();

    // Client 1: non-zero transaction ID, populates the cache
    const q1 = buildDnsQuery("blocked.example.com", 1, 0x1234);
    const req1 = new Request(`https://w.example.com/dns-query?dns=${toBase64url(q1)}`);
    await dispatchWithEnv(req1, { MIN_WAIT_MS: "10" }, cache);
    expect(cache.store.size).toBe(1);

    // Client 2: ID=0 with DO=1 - the cache hit fast path returns the cached
    // bytes unmodified, so any leaked ID would surface here.
    const q2 = buildDnsQueryWithDo("blocked.example.com", 1, 0, true);
    const req2 = new Request(`https://w.example.com/dns-query?dns=${toBase64url(q2)}`);
    const { response } = await dispatchWithEnv(req2, { MIN_WAIT_MS: "10" }, cache);

    const buf = new Uint8Array(await response.arrayBuffer());
    expect(buf[0]).toBe(0);
    expect(buf[1]).toBe(0);
  });

  it("forwards the wire GET query upstream with a zeroed DNS ID", async () => {
    const fetchMock = makeDelayedBlockedFetch(100);
    globalThis.fetch = fetchMock;

    const query = buildDnsQuery("blocked.example.com", 1, 0xbeef);
    const req = new Request(`https://w.example.com/dns-query?dns=${toBase64url(query)}`);
    await dispatchWithEnv(req, { MIN_WAIT_MS: "10" });

    expect(fetchMock).toHaveBeenCalled();
    for (const call of fetchMock.mock.calls) {
      const target = new URL(call[0]);
      const forwarded = fromBase64url(target.searchParams.get("dns"));
      expect(forwarded[0]).toBe(0);
      expect(forwarded[1]).toBe(0);
    }
  });
});

// ---------------------------------------------------------------------------
// JSON GET: cd=1 and cd=0 must not share a cache entry
// ---------------------------------------------------------------------------

describe("JSON GET - ?cd=1 responses are cached separately from cd=0", () => {
  const jsonOkBody = {
    Status: 0,
    TC: false, RD: true, RA: true, AD: false, CD: false,
    Question: [{ name: "example.com.", type: 1 }],
    Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "93.184.216.34" }],
  };

  function makeJsonFetch() {
    return vi.fn(async () =>
      new Response(JSON.stringify(jsonOkBody), {
        headers: { "Content-Type": "application/dns-json" },
      })
    );
  }

  it("a cd=1 query does not populate the cache entry used by cd=0 queries", async () => {
    const fetchMock = makeJsonFetch();
    globalThis.fetch = fetchMock;
    const cache = makeFakeCache();

    // Request 1: cd=1 (upstream validation disabled)
    const req1 = new Request("https://w.example.com/dns-query?name=example.com&type=A&cd=1");
    await dispatchWithEnv(req1, {}, cache);
    const callsAfterFirst = fetchMock.mock.calls.length;
    expect(callsAfterFirst).toBeGreaterThan(0);
    expect(cache.store.size).toBe(1);

    // Request 2: same name/type without cd - must MISS and query upstream again
    const req2 = new Request("https://w.example.com/dns-query?name=example.com&type=A");
    await dispatchWithEnv(req2, {}, cache);
    expect(fetchMock.mock.calls.length).toBeGreaterThan(callsAfterFirst);
    expect(cache.store.size).toBe(2);
  });

  it("repeat cd=0 queries still share a single cache entry", async () => {
    const fetchMock = makeJsonFetch();
    globalThis.fetch = fetchMock;
    const cache = makeFakeCache();

    const req1 = new Request("https://w.example.com/dns-query?name=example.com&type=A");
    await dispatchWithEnv(req1, {}, cache);
    const callsAfterFirst = fetchMock.mock.calls.length;

    const req2 = new Request("https://w.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatchWithEnv(req2, {}, cache);

    expect(fetchMock.mock.calls.length).toBe(callsAfterFirst); // served from cache
    expect(cache.store.size).toBe(1);
    expect(response.status).toBe(200);
  });
});
