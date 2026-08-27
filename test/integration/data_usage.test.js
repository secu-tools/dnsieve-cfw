// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/integration/data_usage.test.js
// End-to-end guards against client and upstream data amplification.
//
// Covered scenarios:
//   - A blocked answer reaches the client with a cacheable TTL, not TTL=0
//   - A short upstream TTL is raised to the TTL the worker advertises
//   - The body TTL always matches Cache-Control on both fresh and cached paths
//   - Concurrent hits inside the renewal window start exactly one background
//     refresh rather than one per request

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { INFLIGHT_REFRESH } from "../../src/handler.js";
import { makeFakeCache, dispatch } from "../helpers/worker.js";
import { buildDnsQuery, buildDnsResponse, extractMinTtlWire } from "../../src/dns.js";

function wirePost(name, { qtype = 1, id = 0 } = {}) {
  return new Request("https://worker.example.com/dns-query", {
    method: "POST",
    headers: { "Content-Type": "application/dns-message" },
    body: buildDnsQuery(name, qtype, id),
  });
}

// Two upstreams both answering with the same wire response.
function wireUpstreams(body) {
  return vi.fn(async () => new Response(body, {
    status: 200,
    headers: { "Content-Type": "application/dns-message" },
  }));
}

const TWO_UPSTREAMS = JSON.stringify([
  "https://up1.example.com/dns-query",
  "https://up2.example.com/dns-query",
]);

const BASE_ENV = { UPSTREAM_SERVERS: TWO_UPSTREAMS, MIN_CACHE_TTL_FLOOR: "60" };

const RENEW_ENV = {
  UPSTREAM_SERVERS: TWO_UPSTREAMS,
  WORKER_CACHE_TTL_SECONDS: "100",
  CACHE_RENEW_PERCENT: "90", // renew once >10s of the 100s TTL has elapsed
  MIN_CACHE_TTL_FLOOR: "60",
};

// Rewinds a cached entry's insertion timestamp so it looks `seconds` old.
async function ageCacheEntry(cache, seconds) {
  const key = [...cache.store.keys()][0];
  const stored = cache.store.get(key);
  const body = await stored.arrayBuffer();
  const headers = new Headers(stored.headers);
  headers.set("x-cache-inserted-at", String(Math.floor(Date.now() / 1000) - seconds));
  cache.store.set(key, new Response(body, { status: 200, headers }));
}

let originalFetch;
beforeEach(() => {
  originalFetch = globalThis.fetch;
  INFLIGHT_REFRESH.clear();
});
afterEach(() => {
  globalThis.fetch = originalFetch;
  vi.restoreAllMocks();
  INFLIGHT_REFRESH.clear();
});

describe("blocked answers are cacheable by the client", () => {
  // Blocked domains are queried constantly; TTL=0 makes an OS resolver repeat
  // the lookup over the network every time.
  it("returns a non-zero TTL for a blocked domain", async () => {
    // 0.0.0.0 from upstream is the block signal.
    globalThis.fetch = wireUpstreams(buildDnsResponse("ads.example.com", "0.0.0.0", 60));

    const { response } = await dispatch(wirePost("ads.example.com"), {
      env: { UPSTREAM_SERVERS: TWO_UPSTREAMS, BLOCKING_MODE: "null" },
    });

    expect(response.headers.get("X-Blocked")).toBe("true");

    const buf = new Uint8Array(await response.arrayBuffer());
    const ttl = extractMinTtlWire(buf);
    expect(ttl).not.toBe(0);
    expect(ttl).toBeGreaterThanOrEqual(60);
  });

  it("advertises the blocked TTL consistently in body and header", async () => {
    globalThis.fetch = wireUpstreams(buildDnsResponse("ads.example.com", "0.0.0.0", 60));

    const { response } = await dispatch(wirePost("ads.example.com"), {
      env: {
        UPSTREAM_SERVERS: TWO_UPSTREAMS,
        BLOCKING_MODE: "null",
        CLIENT_BLOCKED_CACHE_TTL_SECONDS: "86400",
      },
    });

    const advertised = Number(response.headers.get("X-Client-Cache-TTL"));
    const buf = new Uint8Array(await response.arrayBuffer());
    expect(extractMinTtlWire(buf)).toBe(advertised);
    expect(advertised).toBeGreaterThan(0);
  });
});

describe("short upstream TTLs are raised to the advertised client TTL", () => {
  it("raises a 5 second TTL to the configured floor", async () => {
    globalThis.fetch = wireUpstreams(buildDnsResponse("cdn.example.com", "1.2.3.4", 5));

    const { response } = await dispatch(wirePost("cdn.example.com"), {
      env: BASE_ENV,
    });

    const buf = new Uint8Array(await response.arrayBuffer());
    expect(extractMinTtlWire(buf)).toBe(60);
    expect(response.headers.get("Cache-Control")).toBe("public, max-age=60");
  });

  it("keeps the body TTL and Cache-Control in agreement on a cache hit", async () => {
    globalThis.fetch = wireUpstreams(buildDnsResponse("cdn.example.com", "1.2.3.4", 5));
    const cache = makeFakeCache();

    await dispatch(wirePost("cdn.example.com"), { cache, env: BASE_ENV });

    // Second request must be served from cache without touching upstream.
    const callsAfterFirst = globalThis.fetch.mock.calls.length;
    const second = await dispatch(wirePost("cdn.example.com"), { cache, env: BASE_ENV });
    expect(globalThis.fetch.mock.calls.length).toBe(callsAfterFirst);

    // putCache stores the worker-side Cache-Control; a cache hit must
    // re-derive the client value rather than leak the edge lifetime.
    const buf = new Uint8Array(await second.response.arrayBuffer());
    const bodyTtl = extractMinTtlWire(buf);
    expect(second.response.headers.get("Cache-Control")).toBe(`public, max-age=${bodyTtl}`);
    expect(bodyTtl).toBe(60);
  });
});

describe("cached answers decay as they age", () => {
  // Serving a full-length TTL from a nearly expired entry would let total
  // staleness reach worker TTL + client TTL, roughly double the maximum.
  it("subtracts the entry age from the served TTL", async () => {
    globalThis.fetch = wireUpstreams(buildDnsResponse("aged.example.com", "1.2.3.4", 1800));
    const cache = makeFakeCache();
    const env = { UPSTREAM_SERVERS: TWO_UPSTREAMS, MIN_CACHE_TTL_FLOOR: "60", CLIENT_CACHE_TTL_SECONDS: "1800" };

    const fresh = await dispatch(wirePost("aged.example.com"), { cache, env });
    const freshTtl = extractMinTtlWire(new Uint8Array(await fresh.response.arrayBuffer()));
    expect(freshTtl).toBe(1800);

    await ageCacheEntry(cache, 600);

    const hit = await dispatch(wirePost("aged.example.com"), { cache, env });
    const agedTtl = extractMinTtlWire(new Uint8Array(await hit.response.arrayBuffer()));
    expect(agedTtl).toBe(1200);
    expect(hit.response.headers.get("Cache-Control")).toBe("public, max-age=1200");
  });

  it("never lets a client hold an answer past the configured budget", async () => {
    // For every age, served TTL + age must stay within budget + floor.
    globalThis.fetch = wireUpstreams(buildDnsResponse("aged.example.com", "1.2.3.4", 1800));
    const env = { UPSTREAM_SERVERS: TWO_UPSTREAMS, MIN_CACHE_TTL_FLOOR: "60", CLIENT_CACHE_TTL_SECONDS: "1800" };

    for (const age of [0, 300, 900, 1700, 1799]) {
      const cache = makeFakeCache();
      await dispatch(wirePost("aged.example.com"), { cache, env });
      await ageCacheEntry(cache, age);
      const hit = await dispatch(wirePost("aged.example.com"), { cache, env });
      const served = extractMinTtlWire(new Uint8Array(await hit.response.arrayBuffer()));
      expect(served + age).toBeLessThanOrEqual(1800 + 60);
      expect(served).toBeGreaterThanOrEqual(60);
    }
  });

  it("floors an almost-expired entry rather than serving zero", async () => {
    globalThis.fetch = wireUpstreams(buildDnsResponse("aged.example.com", "1.2.3.4", 1800));
    const cache = makeFakeCache();
    const env = { UPSTREAM_SERVERS: TWO_UPSTREAMS, MIN_CACHE_TTL_FLOOR: "60", CLIENT_CACHE_TTL_SECONDS: "1800" };

    await dispatch(wirePost("aged.example.com"), { cache, env });
    await ageCacheEntry(cache, 1795);

    const hit = await dispatch(wirePost("aged.example.com"), { cache, env });
    const served = extractMinTtlWire(new Uint8Array(await hit.response.arrayBuffer()));
    expect(served).toBe(60);
  });
});

describe("background refresh is deduplicated", () => {
  // Without in-flight tracking every cache hit in the renewal window starts its
  // own fan-out to all upstreams.
  it("starts one refresh for many concurrent hits in the renewal window", async () => {
    const cache = makeFakeCache();
    const env = RENEW_ENV;

    globalThis.fetch = wireUpstreams(buildDnsResponse("hot.example.com", "1.2.3.4", 300));

    // Populate the cache.
    await dispatch(wirePost("hot.example.com"), { cache, env });

    // Age the entry into the renewal window.
    await ageCacheEntry(cache, 50);

    // Never resolve upstream, so the refresh stays in flight for the duration.
    let pendingResolve;
    const pending = new Promise(r => { pendingResolve = r; });
    globalThis.fetch = vi.fn(async () => {
      await pending;
      return new Response(buildDnsResponse("hot.example.com", "1.2.3.4", 300), {
        status: 200, headers: { "Content-Type": "application/dns-message" },
      });
    });

    // Fire several concurrent cache hits inside the renewal window.
    const tasks = [];
    for (let i = 0; i < 5; i++) {
      tasks.push(dispatch(wirePost("hot.example.com"), { cache, env, awaitBackground: false }));
    }
    const settled = await Promise.all(tasks);

    // Exactly one refresh should be in flight, hence one fan-out.
    expect(INFLIGHT_REFRESH.size).toBe(1);
    expect(globalThis.fetch.mock.calls.length).toBe(2); // one per upstream, once

    pendingResolve();
    await Promise.allSettled(settled.flatMap(s => s.waitUntilTasks));
  });

  it("allows a new refresh once the previous one completes", async () => {
    const cache = makeFakeCache();
    const env = RENEW_ENV;
    globalThis.fetch = wireUpstreams(buildDnsResponse("hot.example.com", "1.2.3.4", 300));

    await dispatch(wirePost("hot.example.com"), { cache, env });

    await ageCacheEntry(cache, 50);
    await dispatch(wirePost("hot.example.com"), { cache, env });
    expect(INFLIGHT_REFRESH.size).toBe(0); // completed and cleaned up

    await ageCacheEntry(cache, 50);
    const before = globalThis.fetch.mock.calls.length;
    await dispatch(wirePost("hot.example.com"), { cache, env });
    expect(globalThis.fetch.mock.calls.length).toBeGreaterThan(before);
  });

  it("clears in-flight tracking even when the refresh fails", async () => {
    const cache = makeFakeCache();
    const env = RENEW_ENV;
    globalThis.fetch = wireUpstreams(buildDnsResponse("hot.example.com", "1.2.3.4", 300));
    await dispatch(wirePost("hot.example.com"), { cache, env });

    await ageCacheEntry(cache, 50);

    globalThis.fetch = vi.fn(async () => { throw new Error("upstream down"); });
    await dispatch(wirePost("hot.example.com"), { cache, env });

    expect(INFLIGHT_REFRESH.size).toBe(0);
  });
});

describe("early-block verdicts get the full blocked TTL", () => {
  // The early-block path returns as soon as one upstream reports a block. That
  // verdict is not tentative -- Phase 2 applies the identical rule -- and the
  // entry is left uncached only because the worker requires all upstreams to
  // have responded. Any upstream answering inside MIN_WAIT_MS takes this path,
  // so downgrading the TTL here would gut the fix.
  it("serves the configured blocked TTL when one upstream blocks first", async () => {
    let call = 0;
    globalThis.fetch = vi.fn(async () => {
      if (call++ === 0) {
        return new Response(buildDnsResponse("ads.example.com", "0.0.0.0", 60), {
          status: 200, headers: { "Content-Type": "application/dns-message" },
        });
      }
      await new Promise(() => {}); // second upstream never settles
    });

    const { response } = await dispatch(wirePost("ads.example.com"), {
      env: {
        UPSTREAM_SERVERS: TWO_UPSTREAMS,
        BLOCKING_MODE: "null",
        CLIENT_BLOCKED_CACHE_TTL_SECONDS: "86400",
        MIN_CACHE_TTL_FLOOR: "60",
      },
      awaitBackground: false,
    });

    expect(response.headers.get("X-Blocked")).toBe("true");
    expect(extractMinTtlWire(new Uint8Array(await response.arrayBuffer()))).toBe(86400);
  });

  it("serves the same TTL when every upstream blocks", async () => {
    globalThis.fetch = wireUpstreams(buildDnsResponse("ads.example.com", "0.0.0.0", 60));

    const { response } = await dispatch(wirePost("ads.example.com"), {
      env: {
        UPSTREAM_SERVERS: TWO_UPSTREAMS,
        BLOCKING_MODE: "null",
        CLIENT_BLOCKED_CACHE_TTL_SECONDS: "86400",
        MIN_CACHE_TTL_FLOOR: "60",
      },
    });

    expect(extractMinTtlWire(new Uint8Array(await response.arrayBuffer()))).toBe(86400);
  });
});

describe("edge-cache bookkeeping never reaches the client", () => {
  // The edge cache is shared per profile, so an insertion timestamp reveals
  // when somebody else first looked up that domain.
  it("strips cache bookkeeping headers on a cache hit", async () => {
    globalThis.fetch = wireUpstreams(buildDnsResponse("priv.example.com", "1.2.3.4", 300));
    const cache = makeFakeCache();

    await dispatch(wirePost("priv.example.com"), { cache, env: BASE_ENV });
    const hit = await dispatch(wirePost("priv.example.com"), { cache, env: BASE_ENV });

    expect(hit.response.headers.get("X-Cache-Inserted-At")).toBe(null);
    expect(hit.response.headers.get("X-Worker-Cache-TTL")).toBe(null);
    // The stored entry still carries them; only the client copy is scrubbed.
    const stored = cache.store.get([...cache.store.keys()][0]);
    expect(stored.headers.get("X-Cache-Inserted-At")).not.toBe(null);
  });

  it("does not leak the edge lifetime through Cache-Control on a hit", async () => {
    globalThis.fetch = wireUpstreams(buildDnsResponse("priv.example.com", "1.2.3.4", 300));
    const cache = makeFakeCache();
    const env = { ...BASE_ENV, WORKER_CACHE_TTL_SECONDS: "1800", CLIENT_CACHE_TTL_SECONDS: "300" };

    await dispatch(wirePost("priv.example.com"), { cache, env });
    const hit = await dispatch(wirePost("priv.example.com"), { cache, env });

    expect(hit.response.headers.get("Cache-Control")).not.toContain("1800");
  });
});

describe("blocked verdicts reach the edge cache", () => {
  // A resolver block is among the fastest answers an upstream produces, so
  // nearly every block takes the early-return path. If that path skipped the
  // cache write, WORKER_BLOCKED_CACHE_TTL_SECONDS would never apply and every
  // repeat query for a blocked domain would re-run the full fan-out.
  it("caches a block once every upstream has answered", async () => {
    globalThis.fetch = wireUpstreams(buildDnsResponse("ads.example.com", "0.0.0.0", 60));
    const cache = makeFakeCache();
    const env = { UPSTREAM_SERVERS: TWO_UPSTREAMS, BLOCKING_MODE: "null" };

    const { response } = await dispatch(wirePost("ads.example.com"), { cache, env });
    expect(response.headers.get("X-Blocked")).toBe("true");
    expect(cache.store.size).toBe(1);

    // The second request must be served from cache without any fan-out.
    const before = globalThis.fetch.mock.calls.length;
    const second = await dispatch(wirePost("ads.example.com"), { cache, env });
    expect(globalThis.fetch.mock.calls.length).toBe(before);
    expect(second.response.headers.get("X-Blocked")).toBe("true");
  });

  it("does not cache when an upstream failed to answer", async () => {
    // Preserves the phase-2 rule: only cache when every upstream responded.
    let call = 0;
    globalThis.fetch = vi.fn(async () => {
      if (call++ === 0) {
        return new Response(buildDnsResponse("ads.example.com", "0.0.0.0", 60), {
          status: 200, headers: { "Content-Type": "application/dns-message" },
        });
      }
      throw new Error("upstream down");
    });
    const cache = makeFakeCache();

    const { response } = await dispatch(wirePost("ads.example.com"), {
      cache, env: { UPSTREAM_SERVERS: TWO_UPSTREAMS, BLOCKING_MODE: "null" },
    });

    expect(response.headers.get("X-Blocked")).toBe("true");
    expect(cache.store.size).toBe(0);
  });
});
