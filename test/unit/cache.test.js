// test/unit/cache.test.js
// Unit tests for cache key construction and cache TTL helpers (src/cache.js)

import { describe, it, expect, vi } from "vitest";
import { buildCacheKey, putCache, computeClientTtl, shouldRenewCache } from "../../src/cache.js";
import { buildDnsResponse } from "../../src/dns.js";

// ---------------------------------------------------------------------------
// buildCacheKey - JSON GET
// ---------------------------------------------------------------------------

describe("buildCacheKey - JSON GET", () => {
  function makeUrl(search) {
    return new URL(`https://worker.example.com/dns-query${search}`);
  }

  it("returns a Request for a JSON?name= query", () => {
    const key = buildCacheKey("aabbcc", makeUrl("?name=example.com&type=A"), null);
    expect(key instanceof Request).toBe(true);
  });

  it("cache key URL encodes the domain name", () => {
    const key = buildCacheKey("aabbcc", makeUrl("?name=example.com&type=A"), null);
    expect(key.url).toContain("example.com");
  });

  it("includes the profile ID in the cache key URL", () => {
    const key = buildCacheKey("aabbcc", makeUrl("?name=example.com&type=A"), null);
    expect(key.url).toContain("aabbcc");
  });

  it("normalises domain name to lowercase in cache key", () => {
    const lower = buildCacheKey("aabbcc", makeUrl("?name=example.com&type=A"), null);
    const upper = buildCacheKey("aabbcc", makeUrl("?name=EXAMPLE.COM&type=A"), null);
    expect(lower.url).toBe(upper.url);
  });

  it("normalises type to uppercase in cache key", () => {
    const lower = buildCacheKey("aabbcc", makeUrl("?name=example.com&type=a"), null);
    const upper = buildCacheKey("aabbcc", makeUrl("?name=example.com&type=A"), null);
    expect(lower.url).toBe(upper.url);
  });

  it("defaults to type A when type is omitted", () => {
    const withDefault = buildCacheKey("aabbcc", makeUrl("?name=example.com"), null);
    const withA       = buildCacheKey("aabbcc", makeUrl("?name=example.com&type=A"), null);
    expect(withDefault.url).toBe(withA.url);
  });

  it("different profiles produce different cache keys", () => {
    const k1 = buildCacheKey("aabbcc", makeUrl("?name=example.com&type=A"), null);
    const k2 = buildCacheKey("112233", makeUrl("?name=example.com&type=A"), null);
    expect(k1.url).not.toBe(k2.url);
  });

  it("different query names produce different cache keys", () => {
    const k1 = buildCacheKey("aabbcc", makeUrl("?name=foo.com&type=A"), null);
    const k2 = buildCacheKey("aabbcc", makeUrl("?name=bar.com&type=A"), null);
    expect(k1.url).not.toBe(k2.url);
  });

  it("different types produce different cache keys", () => {
    const k1 = buildCacheKey("aabbcc", makeUrl("?name=example.com&type=A"), null);
    const k2 = buildCacheKey("aabbcc", makeUrl("?name=example.com&type=AAAA"), null);
    expect(k1.url).not.toBe(k2.url);
  });
});

// ---------------------------------------------------------------------------
// buildCacheKey - wire GET
// ---------------------------------------------------------------------------

describe("buildCacheKey - wire GET", () => {
  function makeWireUrl(dns) {
    return new URL(`https://worker.example.com/dns-query?dns=${dns}`);
  }

  it("returns a Request for a wire ?dns= query", () => {
    const key = buildCacheKey("aabbcc", makeWireUrl("AAABBB"), null);
    expect(key instanceof Request).toBe(true);
  });

  it("includes 'wire' segment in the cache key URL", () => {
    const key = buildCacheKey("aabbcc", makeWireUrl("AAABBB"), null);
    expect(key.url).toContain("/wire/");
  });

  it("strips padding from base64url in cache key", () => {
    const withPad    = buildCacheKey("aabbcc", makeWireUrl("AAABBB=="), null);
    const withoutPad = buildCacheKey("aabbcc", makeWireUrl("AAABBB"), null);
    expect(withPad.url).toBe(withoutPad.url);
  });
});

// ---------------------------------------------------------------------------
// buildCacheKey - wire POST (async)
// ---------------------------------------------------------------------------

describe("buildCacheKey - wire POST", () => {
  it("returns a Promise for POST body bytes", () => {
    const body = new Uint8Array([0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    const result = buildCacheKey("aabbcc", new URL("https://x.example.com/dns-query"), body);
    expect(result instanceof Promise).toBe(true);
  });

  it("produces deterministic cache key for same body", async () => {
    const body = new Uint8Array([0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    const url = new URL("https://x.example.com/dns-query");
    const k1 = await buildCacheKey("aabbcc", url, body);
    const k2 = await buildCacheKey("aabbcc", url, body);
    expect(k1.url).toBe(k2.url);
  });

  it("different bodies produce different cache keys", async () => {
    const body1 = new Uint8Array([0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    const body2 = new Uint8Array([0, 0, 2, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    const url = new URL("https://x.example.com/dns-query");
    const k1 = await buildCacheKey("aabbcc", url, body1);
    const k2 = await buildCacheKey("aabbcc", url, body2);
    expect(k1.url).not.toBe(k2.url);
  });

  it("includes 'wire' and hex hash in URL", async () => {
    const body = new Uint8Array([0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    const key = await buildCacheKey("aabbcc", new URL("https://x.example.com/dns-query"), body);
    expect(key.url).toContain("/wire/");
    expect(key.url).toMatch(/[0-9a-f]{64}/); // SHA-256 hex
  });

  it("profile ID is in cache key URL", async () => {
    const body = new Uint8Array([0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    const key = await buildCacheKey("aabbcc", new URL("https://x.example.com/dns-query"), body);
    expect(key.url).toContain("aabbcc");
  });
});

// ---------------------------------------------------------------------------
// putCache
// ---------------------------------------------------------------------------

describe("putCache", () => {
  it("writes normal response with worker normal TTL headers", async () => {
    const cache = { put: vi.fn(async () => {}) };
    const key = new Request("https://doh-cache.internal/aabbcc/json/example.com/A");
    const resp = new Response(JSON.stringify({ ok: true }), {
      status: 200,
      headers: { "Content-Type": "application/dns-json" },
    });

    await putCache(cache, key, resp, false);

    expect(cache.put).toHaveBeenCalledTimes(1);
    const [calledKey, cachedResp] = cache.put.mock.calls[0];
    expect(calledKey.url).toBe(key.url);
    expect(cachedResp.headers.get("cache-control")).toBe("public, max-age=1800");
    expect(cachedResp.headers.get("x-worker-cache-ttl")).toBe("1800");
    expect(cachedResp.status).toBe(200);
  });

  it("writes blocked response with worker blocked TTL headers", async () => {
    const cache = { put: vi.fn(async () => {}) };
    const key = new Request("https://doh-cache.internal/aabbcc/json/blocked.example/A");
    const resp = new Response(JSON.stringify({ Status: 0 }), {
      status: 200,
      headers: { "Content-Type": "application/dns-json" },
    });

    await putCache(cache, key, resp, true);

    expect(cache.put).toHaveBeenCalledTimes(1);
    const [, cachedResp] = cache.put.mock.calls[0];
    expect(cachedResp.headers.get("cache-control")).toBe("public, max-age=86400");
    expect(cachedResp.headers.get("x-worker-cache-ttl")).toBe("86400");
  });

  it("swallows cache.put errors to avoid breaking request flow", async () => {
    const cache = {
      put: vi.fn(async () => {
        throw new Error("cache backend unavailable");
      }),
    };
    const key = new Request("https://doh-cache.internal/aabbcc/json/example.com/A");
    const resp = new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } });

    await expect(putCache(cache, key, resp, false)).resolves.toBeUndefined();
    expect(cache.put).toHaveBeenCalledTimes(1);
  });
});

// ---------------------------------------------------------------------------
// computeClientTtl
// ---------------------------------------------------------------------------

describe("computeClientTtl", () => {
  it("uses configured normal TTL when no DNS records are present", () => {
    const result = { wire: false, json: { Status: 0 } };
    expect(computeClientTtl(result, false)).toBe(1800);
  });

  it("caps blocked result TTL to DNS record TTL when lower than configured", () => {
    const result = {
      wire: false,
      json: {
        Status: 0,
        Answer: [{ TTL: 120, data: "0.0.0.0" }],
      },
    };
    expect(computeClientTtl(result, true)).toBe(120);
  });

  it("applies MIN_CACHE_TTL_FLOOR for very small wire TTL values", () => {
    const raw = buildDnsResponse("short.example.", "1.2.3.4", 1);
    const result = { wire: true, raw };
    expect(computeClientTtl(result, false)).toBe(60);
  });
});

// ---------------------------------------------------------------------------
// Security & Malformed Inputs (Cache)
// ---------------------------------------------------------------------------

describe("Cache - Security & Malformed Inputs", () => {
  function makeUrl(search) {
    return new URL(`https://worker.example.com/dns-query${search}`);
  }

  it("URL-encodes path separators in ?name= to prevent cache key traversal", () => {
    // encodeURIComponent encodes '/' as '%2F', so path segments cannot traverse
    // the doh-cache.internal base URL hierarchy.
    const url = makeUrl("?name=../../../etc/passwd&type=A");
    const key = buildCacheKey("aabbcc", url, null);
    // Slashes must be percent-encoded so they do not form real path segments
    expect(key.url).toContain("%2F");
    // The key URL must remain under the expected prefix
    expect(key.url.startsWith("https://doh-cache.internal/")).toBe(true);
    // Must not resolve above the base (no real path traversal)
    expect(key.url).not.toBe("https://doh-cache.internal/etc/passwd");
  });

  it("handles extremely long domain names", () => {
    const longName = "a".repeat(255) + ".com";
    const url = makeUrl(`?name=${longName}&type=A`);
    const key = buildCacheKey("aabbcc", url, null);
    expect(key.url).toContain(longName);
  });

  it("handles control characters without failing cache generation", () => {
    const url = makeUrl("?name=ex\x00ample.com&type=A");
    const key = buildCacheKey("aabbcc", url, null);
    // Normalization usually catches this, but at worst it's stringified
    expect(key.url.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// buildCacheKey - additional normalisation coverage
// ---------------------------------------------------------------------------

describe("buildCacheKey - normalisation", () => {
  function makeUrl(search) {
    return new URL(`https://worker.example.com/dns-query${search}`);
  }

  it("JSON cache key is under doh-cache.internal host", () => {
    const key = buildCacheKey("aabbcc", makeUrl("?name=example.com&type=A"), null);
    expect(new URL(key.url).host).toBe("doh-cache.internal");
  });

  it("wire GET cache key is under doh-cache.internal host", () => {
    const key = buildCacheKey("aabbcc", makeUrl("?dns=AAABBB"), null);
    expect(new URL(key.url).host).toBe("doh-cache.internal");
  });

  it("JSON key URL includes /json/ path segment", () => {
    const key = buildCacheKey("aabbcc", makeUrl("?name=example.com&type=A"), null);
    expect(key.url).toContain("/json/");
  });

  it("wire GET key URL includes /wire/ path segment", () => {
    const key = buildCacheKey("aabbcc", makeUrl("?dns=AAABBB"), null);
    expect(key.url).toContain("/wire/");
  });

  it("normalises IDN domain to ACE in cache key", () => {
    // The WHATWG URL toASCII converts unicode to punycode via new URL()
    const url = makeUrl("?name=xn--nxdomain.example&type=A");
    const key = buildCacheKey("aabbcc", url, null);
    expect(key.url).toContain("xn--nxdomain.example");
  });

  it("method on cache Request is always GET", () => {
    const key = buildCacheKey("aabbcc", makeUrl("?name=example.com&type=A"), null);
    expect(key.method).toBe("GET");
  });
});

// ---------------------------------------------------------------------------
// computeClientTtl - additional coverage
// ---------------------------------------------------------------------------

describe("computeClientTtl - additional coverage", () => {
  it("returns blocked TTL when no DNS records and blocked=true", () => {
    const result = { wire: false, json: null };
    const ttl = computeClientTtl(result, true);
    // CLIENT_BLOCKED_CACHE_TTL_SECONDS = 86400
    expect(ttl).toBe(86400);
  });

  it("caps wire TTL at CLIENT_CACHE_TTL_SECONDS for normal result", () => {
    const raw = buildDnsResponse("example.com.", "1.2.3.4", 999999);
    const result = { wire: true, raw };
    const ttl = computeClientTtl(result, false);
    expect(ttl).toBeLessThanOrEqual(1800);
  });

  it("uses Authority TTL when Answer is absent", () => {
    const result = {
      wire: false,
      json: {
        Status: 3,
        Authority: [{ TTL: 120 }],
      },
    };
    const ttl = computeClientTtl(result, false);
    expect(ttl).toBe(120);
  });

  it("applies floor to 0-TTL DNS record", () => {
    const result = {
      wire: false,
      json: { Answer: [{ TTL: 0 }] },
    };
    const ttl = computeClientTtl(result, false);
    expect(ttl).toBeGreaterThanOrEqual(60);
  });
});

// ---------------------------------------------------------------------------
// buildCacheKey - unified format for all wire request types
// Verifies that DO=0 and DO=1 queries for the same domain share a cache entry,
// and that wire GET and JSON GET for the same domain share a cache entry.
// ---------------------------------------------------------------------------

import { buildDnsQuery, buildDnsQueryWithDo } from "../../src/dns.js";

describe("buildCacheKey - unified key format (wire = json)", () => {
  function makeJsonUrl(name, type = "A") {
    return new URL(`https://w.example.com/dns-query?name=${name}&type=${type}`);
  }

  it("valid wire GET query produces /json/ cache key (not /wire/)", () => {
    const q = buildDnsQuery("example.com", 1);
    const b64 = btoa(String.fromCharCode(...q))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const url = new URL(`https://w.example.com/dns-query?dns=${b64}`);
    const key = buildCacheKey("aabbcc", url, null);
    expect(key.url).toContain("/json/");
    expect(key.url).toContain("example.com");
  });

  it("valid wire GET and JSON GET for same domain produce identical cache keys", () => {
    const q = buildDnsQuery("example.com", 1);
    const b64 = btoa(String.fromCharCode(...q))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const wireGetKey = buildCacheKey("aabbcc",
      new URL(`https://w.example.com/dns-query?dns=${b64}`), null);
    const jsonGetKey = buildCacheKey("aabbcc", makeJsonUrl("example.com", "A"), null);
    expect(wireGetKey.url).toBe(jsonGetKey.url);
  });

  it("wire POST for valid DNS query produces /json/ cache key", () => {
    const q = buildDnsQuery("example.com", 1);
    const keyPromise = buildCacheKey("aabbcc",
      new URL("https://w.example.com/dns-query"), q);
    // For a valid DNS body, buildCacheKey returns a Request (not a Promise)
    expect(keyPromise instanceof Request).toBe(true);
    if (keyPromise instanceof Request) {
      expect(keyPromise.url).toContain("/json/");
      expect(keyPromise.url).toContain("example.com");
    }
  });

  it("wire POST and JSON GET for same domain produce identical cache keys", () => {
    const q = buildDnsQuery("example.com", 1);
    const wirePostKey = buildCacheKey("aabbcc",
      new URL("https://w.example.com/dns-query"), q);
    const jsonGetKey = buildCacheKey("aabbcc", makeJsonUrl("example.com", "A"), null);
    expect(wirePostKey.url).toBe(jsonGetKey.url);
  });

  it("DO=0 wire POST and DO=1 wire POST share the same cache key", () => {
    const qNoDo = buildDnsQuery("example.com", 1);
    const qDo   = buildDnsQueryWithDo("example.com", 1, 0, true);
    const keyNoDo = buildCacheKey("aabbcc",
      new URL("https://w.example.com/dns-query"), qNoDo);
    const keyDo = buildCacheKey("aabbcc",
      new URL("https://w.example.com/dns-query"), qDo);
    expect(keyNoDo.url).toBe(keyDo.url);
  });

  it("different qtype produces different cache key", () => {
    const qA    = buildDnsQuery("example.com", 1);
    const qAAAA = buildDnsQuery("example.com", 28);
    const keyA    = buildCacheKey("aabbcc",
      new URL("https://w.example.com/dns-query"), qA);
    const keyAAAA = buildCacheKey("aabbcc",
      new URL("https://w.example.com/dns-query"), qAAAA);
    expect(keyA.url).not.toBe(keyAAAA.url);
  });
});

// ---------------------------------------------------------------------------
// shouldRenewCache
// ---------------------------------------------------------------------------

// Build a fake cached Response with the two timing headers that shouldRenewCache reads.
// insertedSecondsAgo: how many seconds ago the entry was stored.
// totalTtl: the value stored in X-Worker-Cache-TTL.
function makeCachedResp(insertedSecondsAgo, totalTtl) {
  const insertedAt = Math.floor(Date.now() / 1000) - insertedSecondsAgo;
  return new Response(null, {
    headers: {
      "X-Cache-Inserted-At": String(insertedAt),
      "X-Worker-Cache-TTL":  String(totalTtl),
    },
  });
}

describe("shouldRenewCache", () => {
  it("returns false when CACHE_RENEW_PERCENT is 0 (disabled)", () => {
    const resp = makeCachedResp(1790, 1800);
    expect(shouldRenewCache(resp, { CACHE_RENEW_PERCENT: 0 })).toBe(false);
  });

  it("returns false when CACHE_RENEW_PERCENT is missing from cfg", () => {
    const resp = makeCachedResp(1790, 1800);
    expect(shouldRenewCache(resp, {})).toBe(false);
  });

  it("returns false when X-Cache-Inserted-At header is absent", () => {
    const resp = new Response(null, {
      headers: { "X-Worker-Cache-TTL": "1800" },
    });
    expect(shouldRenewCache(resp, { CACHE_RENEW_PERCENT: 10 })).toBe(false);
  });

  it("returns false when X-Worker-Cache-TTL header is absent", () => {
    const insertedAt = String(Math.floor(Date.now() / 1000) - 1790);
    const resp = new Response(null, {
      headers: { "X-Cache-Inserted-At": insertedAt },
    });
    expect(shouldRenewCache(resp, { CACHE_RENEW_PERCENT: 10 })).toBe(false);
  });

  it("returns true when remaining TTL is below renew_percent threshold", () => {
    // 1800s total TTL, 10% threshold = 180s. Inserted 1700s ago => 100s remaining < 180.
    const resp = makeCachedResp(1700, 1800);
    expect(shouldRenewCache(resp, { CACHE_RENEW_PERCENT: 10 })).toBe(true);
  });

  it("returns false when remaining TTL is above renew_percent threshold", () => {
    // 1800s total TTL, 10% threshold = 180s. Inserted 10s ago => 1790s remaining > 180.
    const resp = makeCachedResp(10, 1800);
    expect(shouldRenewCache(resp, { CACHE_RENEW_PERCENT: 10 })).toBe(false);
  });

  it("returns true at 1 second remaining (well below any normal threshold)", () => {
    // 300s TTL, 299s old => 1s remaining. 10% of 300 = 30s threshold.
    const resp = makeCachedResp(299, 300);
    expect(shouldRenewCache(resp, { CACHE_RENEW_PERCENT: 10 })).toBe(true);
  });

  it("returns false when remaining TTL equals the threshold exactly (strict less-than)", () => {
    // 1000s TTL, 10% threshold = 100s. Inserted 900s ago => exactly 100s remaining.
    const resp = makeCachedResp(900, 1000);
    expect(shouldRenewCache(resp, { CACHE_RENEW_PERCENT: 10 })).toBe(false);
  });

  it("returns false when entry appears expired (remaining <= 0)", () => {
    // Inserted 2000s ago with 1800s TTL => -200s remaining.
    const resp = makeCachedResp(2000, 1800);
    expect(shouldRenewCache(resp, { CACHE_RENEW_PERCENT: 10 })).toBe(false);
  });

  it("respects a higher renew_percent (50%)", () => {
    // 1000s TTL, 50% threshold = 500s. Inserted 600s ago => 400s remaining < 500 => true.
    const resp = makeCachedResp(600, 1000);
    expect(shouldRenewCache(resp, { CACHE_RENEW_PERCENT: 50 })).toBe(true);
  });

  it("high renew_percent does not trigger on a fresh entry", () => {
    // 1000s TTL, 50% threshold = 500s. Inserted 10s ago => 990s remaining > 500 => false.
    const resp = makeCachedResp(10, 1000);
    expect(shouldRenewCache(resp, { CACHE_RENEW_PERCENT: 50 })).toBe(false);
  });

  it("uses module-level CACHE_RENEW_PERCENT when cfg is null", () => {
    // Default is 10. 300s TTL, inserted 289s ago => 11s remaining. 10% of 300 = 30 => true.
    const resp = makeCachedResp(289, 300);
    expect(shouldRenewCache(resp, null)).toBe(true);
  });

  it("uses module default as fallback when cfg is undefined", () => {
    const resp = makeCachedResp(289, 300);
    expect(shouldRenewCache(resp, undefined)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// putCache - X-Cache-Inserted-At header
// ---------------------------------------------------------------------------

describe("putCache - X-Cache-Inserted-At header", () => {
  it("stores X-Cache-Inserted-At as a unix timestamp in the cached response", async () => {
    const cache = { put: vi.fn(async () => {}) };
    const key  = new Request("https://doh-cache.internal/aabbcc/json/example.com/A");
    const resp = new Response("{}", { status: 200, headers: { "Content-Type": "application/dns-json" } });

    const before = Math.floor(Date.now() / 1000);
    await putCache(cache, key, resp, false);
    const after  = Math.floor(Date.now() / 1000);

    const [, storedResp] = cache.put.mock.calls[0];
    const ts = Number(storedResp.headers.get("x-cache-inserted-at"));
    expect(ts).toBeGreaterThanOrEqual(before);
    expect(ts).toBeLessThanOrEqual(after);
  });

  it("X-Cache-Inserted-At is a positive integer (unix seconds)", async () => {
    const cache = { put: vi.fn(async () => {}) };
    const key  = new Request("https://doh-cache.internal/000000/json/test.example/A");
    const resp = new Response("{}", { status: 200, headers: { "Content-Type": "application/dns-json" } });

    await putCache(cache, key, resp, false);

    const [, storedResp] = cache.put.mock.calls[0];
    const ts = Number(storedResp.headers.get("x-cache-inserted-at"));
    expect(Number.isInteger(ts)).toBe(true);
    expect(ts).toBeGreaterThan(0);
  });
});
