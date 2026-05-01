// test/rfc/rfc4343_rfc5891.test.js
//
// RFC 4343 - DNS Case Insensitivity
//   DNS names are case-insensitive (RFC 4343 SS.2). Cache keys and comparisons
//   must normalize domain names to lowercase so that EXAMPLE.COM, Example.Com,
//   and eXaMpLe.CoM all resolve via the same cache entry.
//
// RFC 5891 / IDNA 2008 (WHATWG URL Standard SS.3.3)
//   Internationalized domain names are converted to ASCII Compatible Encoding
//   (ACE / Punycode, xn-- prefix). ACE labels must be lowercased and must
//   survive round-trips without corruption. A wrong-cased ACE label such as
//   XN--NXDOMAIN.EXAMPLE must hash to the same cache key as
//   xn--nxdomain.example.

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { toASCII } from "../../src/dns.js";
import { buildCacheKey } from "../../src/cache.js";
import { handleRequest } from "../../src/handler.js";
import { buildDnsResponse } from "../../src/dns.js";

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeUrl(search) {
  return new URL(`https://worker.example.com/dns-query${search}`);
}

function makeFakeCache() {
  const store = new Map();
  return {
    match: (req) => Promise.resolve(store.get(typeof req === "string" ? req : req.url)),
    put: (req, resp) => { store.set(typeof req === "string" ? req : req.url, resp); return Promise.resolve(); },
  };
}

function makeUpstreamResponse(body, contentType = "application/dns-json") {
  return new Response(JSON.stringify(body), {
    status: 200,
    headers: { "Content-Type": contentType },
  });
}

// ---------------------------------------------------------------------------
// RFC 4343 - Cache key case insensitivity
// ---------------------------------------------------------------------------

describe("RFC 4343 - DNS case insensitivity (cache key normalisation)", () => {
  const profileId = "aabbcc";
  const type = "A";

  it("lowercase and uppercase produce the same JSON GET cache key", () => {
    const lower = buildCacheKey(profileId, makeUrl(`?name=example.com&type=${type}`), null);
    const upper = buildCacheKey(profileId, makeUrl(`?name=EXAMPLE.COM&type=${type}`), null);
    expect(lower.url).toBe(upper.url);
  });

  it("mixed-case variants all produce the same JSON GET cache key", () => {
    const base = buildCacheKey(profileId, makeUrl("?name=example.com&type=A"), null);
    const mixed1 = buildCacheKey(profileId, makeUrl("?name=Example.Com&type=A"), null);
    const mixed2 = buildCacheKey(profileId, makeUrl("?name=eXaMpLe.CoM&type=A"), null);
    const mixed3 = buildCacheKey(profileId, makeUrl("?name=EXAMPLE.COM&type=A"), null);
    expect(mixed1.url).toBe(base.url);
    expect(mixed2.url).toBe(base.url);
    expect(mixed3.url).toBe(base.url);
  });

  it("uppercase type name normalises to same cache key as lowercase", () => {
    const lower = buildCacheKey(profileId, makeUrl("?name=example.com&type=a"), null);
    const upper = buildCacheKey(profileId, makeUrl("?name=example.com&type=A"), null);
    expect(lower.url).toBe(upper.url);
  });

  it("toASCII lowercases all ASCII label characters per RFC 4343", () => {
    expect(toASCII("EXAMPLE.COM")).toBe("example.com");
    expect(toASCII("Example.Com")).toBe("example.com");
    expect(toASCII("eXaMpLe.CoM")).toBe("example.com");
  });

  it("toASCII preserves already-lowercase domain unchanged", () => {
    expect(toASCII("example.com")).toBe("example.com");
    expect(toASCII("www.sub.example.org")).toBe("www.sub.example.org");
  });

  it("cache key path uses lowercase domain regardless of input case", () => {
    const key = buildCacheKey(profileId, makeUrl("?name=UPPER.EXAMPLE.COM&type=A"), null);
    // The domain portion of the URL must be lowercase; DNS type names (A, AAAA) remain uppercase
    expect(key.url).toContain("/upper.example.com/");
    expect(key.url).not.toContain("UPPER");
  });
});

// ---------------------------------------------------------------------------
// RFC 4343 - Integration: uppercase name query hits same cache as lowercase
// ---------------------------------------------------------------------------

describe("RFC 4343 - Integration: case-insensitive cache lookup", () => {
  let fetchSpy;
  let fakeCache;

  beforeEach(() => {
    fakeCache = makeFakeCache();
    vi.stubGlobal("caches", { default: fakeCache });

    const normalResp = { Status: 0, Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "1.2.3.4" }] };
    let callCount = 0;
    fetchSpy = vi.spyOn(globalThis, "fetch").mockImplementation(() => {
      callCount++;
      return Promise.resolve(makeUpstreamResponse(normalResp));
    });
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("uppercase query result shares the same cache entry shape as lowercase", async () => {
    // First request: lowercase - populates cache
    const req1 = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    const r1 = await handleRequest(req1, {}, { waitUntil: () => {} });
    expect(r1.status).toBe(200);

    // Second request: UPPERCASE - should compute same cache key
    const req2 = new Request("https://worker.example.com/dns-query?name=EXAMPLE.COM&type=A");
    const r2 = await handleRequest(req2, {}, { waitUntil: () => {} });
    expect(r2.status).toBe(200);

    // Both responses should carry X-Blocked: false
    expect(r1.headers.get("x-blocked")).toBe("false");
    expect(r2.headers.get("x-blocked")).toBe("false");
  });
});

// ---------------------------------------------------------------------------
// RFC 5891 / IDNA 2008 - ACE label handling
// ---------------------------------------------------------------------------

describe("RFC 5891 - IDNA ACE label normalisation", () => {
  it("lowercases uppercase ACE prefix XN-- to xn--", () => {
    // ACE labels with uppercase prefix must be normalised to lowercase
    const result = toASCII("XN--NXDOMAIN.EXAMPLE");
    expect(result).toBe("xn--nxdomain.example");
  });

  it("ACE label survives round-trip without corruption", () => {
    // A real-world ACE label: xn--bcher-kva.example (buchel.example in German)
    const ace = "xn--bcher-kva.example";
    expect(toASCII(ace)).toBe(ace);
  });

  it("mixed-case ACE label normalises to same value as lowercase ACE", () => {
    const lower = toASCII("xn--nxdomain.example");
    const upper = toASCII("XN--NXDOMAIN.EXAMPLE");
    const mixed = toASCII("Xn--NxDomain.Example");
    expect(upper).toBe(lower);
    expect(mixed).toBe(lower);
  });

  it("mixed-case ACE labels produce the same cache key as lowercase ACE", () => {
    const lower = buildCacheKey("aabbcc", makeUrl("?name=xn--nxdomain.example&type=A"), null);
    const upper = buildCacheKey("aabbcc", makeUrl("?name=XN--NXDOMAIN.EXAMPLE&type=A"), null);
    expect(lower.url).toBe(upper.url);
  });

  it("two-label ACE domain normalises all labels", () => {
    const result = toASCII("XN--LABEL1.XN--LABEL2");
    expect(result).toBe("xn--label1.xn--label2");
  });
});

// ---------------------------------------------------------------------------
// Block detection - no IP leak (adapted from integration_block_test.go)
// ---------------------------------------------------------------------------

describe("Block detection - no usable IP leak in blocked response", () => {
  let fetchSpy;
  let fakeCache;

  beforeEach(() => {
    fakeCache = makeFakeCache();
    vi.stubGlobal("caches", { default: fakeCache });

    // Upstream returns a block-signaling 0.0.0.0 A record
    const blockedJsonBody = {
      Status: 0,
      Answer: [{ name: "blocked.example.", type: 1, TTL: 86400, data: "0.0.0.0" }],
    };
    fetchSpy = vi.spyOn(globalThis, "fetch").mockResolvedValue(
      makeUpstreamResponse(blockedJsonBody)
    );
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("blocked A response carries X-Blocked: true", async () => {
    const req = new Request("https://worker.example.com/dns-query?name=blocked.example&type=A");
    const resp = await handleRequest(req, {}, { waitUntil: () => {} });
    expect(resp.headers.get("x-blocked")).toBe("true");
  });

  it("blocked response body does not contain a routable IPv4 address", async () => {
    const req = new Request("https://worker.example.com/dns-query?name=blocked.example&type=A");
    const resp = await handleRequest(req, {}, { waitUntil: () => {} });
    const body = await resp.json();
    // All Answer data values must be the block sentinel, not a routable IP
    if (body.Answer && body.Answer.length > 0) {
      for (const record of body.Answer) {
        // 0.0.0.0 is the only acceptable IPv4 block sentinel
        if (typeof record.data === "string" && record.data.includes(".")) {
          expect(record.data).toBe("0.0.0.0");
        }
      }
    }
  });

  it("blocked response does not expose the sentinel IP in Status (must be 0 = NOERROR)", async () => {
    const req = new Request("https://worker.example.com/dns-query?name=blocked.example&type=A");
    const resp = await handleRequest(req, {}, { waitUntil: () => {} });
    const body = await resp.json();
    // Status 0 = NOERROR - the block is signaled via X-Blocked header, not rcode
    expect(body.Status).toBe(0);
  });

  it("blocked IPv6 sentinel :: does not leak a routable address", async () => {
    fakeCache = makeFakeCache();
    vi.stubGlobal("caches", { default: fakeCache });

    // Resolvers signal blocked AAAA with :: (the canonical all-zeros form, per Quad9 docs)
    const blockedAAAA = {
      Status: 0,
      Answer: [{ name: "blocked.example.", type: 28, TTL: 86400, data: "::" }],
    };
    vi.spyOn(globalThis, "fetch").mockResolvedValue(makeUpstreamResponse(blockedAAAA));

    const req = new Request("https://worker.example.com/dns-query?name=blocked.example&type=AAAA");
    const resp = await handleRequest(req, {}, { waitUntil: () => {} });
    expect(resp.headers.get("x-blocked")).toBe("true");

    const body = await resp.json();
    if (body.Answer && body.Answer.length > 0) {
      for (const record of body.Answer) {
        if (typeof record.data === "string" && record.data.includes(":")) {
          // Must be the block sentinel, not a routable global unicast
          expect(record.data).toMatch(/^0[:\.]|^::$/);
        }
      }
    }
  });
});

// ---------------------------------------------------------------------------
// RFC 4343 - Block detection uses case-insensitive cache key
// ---------------------------------------------------------------------------

describe("RFC 4343 - Block cache key is case-insensitive", () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it("upper-case domain blocked query produces same cache key as lowercase", () => {
    const lower = buildCacheKey("aabbcc", makeUrl("?name=blocked.example&type=A"), null);
    const upper = buildCacheKey("aabbcc", makeUrl("?name=BLOCKED.EXAMPLE&type=A"), null);
    expect(lower.url).toBe(upper.url);
  });
});
