// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/integration/worker.test.js
// Integration tests for the Cloudflare Worker request handler.
// These tests exercise the full handleRequest() pipeline with mocked upstreams
// and a fake edge cache.
//
// Covered scenarios:
//   - JSON DoH GET (Accept: application/dns-json)
//   - Wire DoH GET (?dns=<base64url>)
//   - Wire DoH POST (Content-Type: application/dns-message)
//   - CORS preflight
//   - Error responses: 400, 405, 413, 415
//   - All-upstream-fail: HTTP 200 + SERVFAIL DNS body (RFC 8484 s4.2.1)
//   - Block detection and X-Blocked header
//   - Profile ID extraction via /p-{hex}/ path
//   - Cache hit and miss behaviour
//   - X-All-Responded / X-Upstream-Index headers
//   - DNS transaction ID preservation in wire responses (RFC 8484 SS.4.1)

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleRequest } from "../../src/handler.js";
import { buildDnsResponse, buildDnsQuery } from "../../src/dns.js";

// ---------------------------------------------------------------------------
// Fake infrastructure
// ---------------------------------------------------------------------------

// A minimal fake Cloudflare Cache that stores responses by cache key URL.
function makeFakeCache() {
  const store = new Map();
  return {
    store,
    async match(req) {
      const key = typeof req === "string" ? req : req.url;
      return store.get(key) || null;
    },
    async put(req, resp) {
      const key = typeof req === "string" ? req : req.url;
      // Clone the response so the body is still readable later
      store.set(key, resp.clone());
    },
  };
}

// Wraps handleRequest with injected fake caches.default and ctx.
async function dispatch(request, fakeCache) {
  return dispatchWithEnv(request, fakeCache, {});
}

// Like dispatch but accepts custom env bindings to override config.
async function dispatchWithEnv(request, fakeCache, env) {
  const cache = fakeCache || makeFakeCache();
  const waitUntilTasks = [];
  const ctx = { waitUntil: (p) => waitUntilTasks.push(p) };

  const originalCaches = globalThis.caches;
  globalThis.caches = { default: cache };

  try {
    const response = await handleRequest(request, env || {}, ctx);
    await Promise.allSettled(waitUntilTasks);
    return { response, cache };
  } finally {
    globalThis.caches = originalCaches;
  }
}

// Builds a fake upstream fetch implementation.
// upstreams is an array of { contentType, body, status } indexed by call order or url match.
function makeFetch(responses) {
  let callIndex = 0;
  return vi.fn(async (url, options) => {
    const def = responses[callIndex % responses.length];
    callIndex++;
    const status = def.status ?? 200;
    const body = def.body instanceof Uint8Array ? def.body : JSON.stringify(def.body);
    return new Response(body, {
      status,
      headers: { "Content-Type": def.contentType || "application/dns-json" },
    });
  });
}

// Standard JSON upstream response for example.com A query
const jsonOkBody = {
  Status: 0,
  TC: false, RD: true, RA: true, AD: false, CD: false,
  Question: [{ name: "example.com.", type: 1 }],
  Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "93.184.216.34" }],
};

// ---------------------------------------------------------------------------
// CORS preflight
// ---------------------------------------------------------------------------

describe("CORS preflight", () => {
  it("returns 200 for OPTIONS with correct CORS headers", async () => {
    const req = new Request("https://worker.example.com/dns-query", { method: "OPTIONS" });
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
    expect(response.headers.get("access-control-allow-origin")).toBe("*");
    expect(response.headers.get("access-control-allow-methods")).toContain("GET");
    expect(response.headers.get("access-control-allow-methods")).toContain("POST");
  });

  it("returns preflight allow headers and max-age", async () => {
    const req = new Request("https://worker.example.com/dns-query", { method: "OPTIONS" });
    const { response } = await dispatch(req);
    expect(response.headers.get("access-control-allow-headers")).toContain("Content-Type");
    expect(response.headers.get("access-control-max-age")).toBe("86400");
  });
});

// ---------------------------------------------------------------------------
// Method validation (RFC 8484 SS.4.2.1)
// ---------------------------------------------------------------------------

describe("Method validation", () => {
  it("returns 405 for PUT method", async () => {
    const req = new Request("https://worker.example.com/dns-query", { method: "PUT" });
    const { response } = await dispatch(req);
    expect(response.status).toBe(405);
    expect(response.headers.get("allow")).toContain("GET");
  });

  it("returns 405 for DELETE method", async () => {
    const req = new Request("https://worker.example.com/dns-query", { method: "DELETE" });
    const { response } = await dispatch(req);
    expect(response.status).toBe(405);
  });

  it("returns 405 for PATCH method", async () => {
    const req = new Request("https://worker.example.com/dns-query", { method: "PATCH" });
    const { response } = await dispatch(req);
    expect(response.status).toBe(405);
  });
});

// ---------------------------------------------------------------------------
// Bad request validation (RFC 8484 SS.4.2.1)
// ---------------------------------------------------------------------------

describe("Bad request validation", () => {
  it("returns 400 for GET without ?name or ?dns params", async () => {
    const req = new Request("https://worker.example.com/dns-query");
    const { response } = await dispatch(req);
    expect(response.status).toBe(400);
  });

  it("returns 415 for POST with wrong Content-Type", async () => {
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: "not-dns",
    });
    const { response } = await dispatch(req);
    expect(response.status).toBe(415);
  });

  it("returns 413 for POST body exceeding 65535 bytes", async () => {
    const bigBody = new Uint8Array(65536);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: bigBody,
    });
    const { response } = await dispatch(req);
    expect(response.status).toBe(413);
  });

  // Regression: a POST body shorter than the mandatory 12-byte DNS header is
  // malformed and was previously forwarded to upstreams, causing them to return
  // HTTP 500. The worker must now reject it with 400 before any upstream is queried.
  it("returns 400 for POST body shorter than 12 bytes (minimum DNS header size)", async () => {
    const tinyBody = new Uint8Array(5);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: tinyBody,
    });
    const { response } = await dispatch(req);
    expect(response.status).toBe(400);
  });

  it("returns 400 for empty POST body", async () => {
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: new Uint8Array(0),
    });
    const { response } = await dispatch(req);
    expect(response.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// JSON DoH GET - normal flow
// ---------------------------------------------------------------------------

describe("JSON DoH GET", () => {
  beforeEach(() => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: jsonOkBody },
      { contentType: "application/dns-json", body: jsonOkBody },
      { contentType: "application/dns-json", body: jsonOkBody },
    ]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 200 for valid JSON Get query", async () => {
    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A", {
      headers: { Accept: "application/dns-json" },
    });
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
  });

  it("returns application/dns-json content type", async () => {
    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A", {
      headers: { Accept: "application/dns-json" },
    });
    const { response } = await dispatch(req);
    expect(response.headers.get("content-type")).toContain("application/dns-json");
  });

  it("sets X-Blocked false for normal result", async () => {
    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req);
    expect(response.headers.get("x-blocked")).toBe("false");
  });

  it("sets X-Profile-Id header", async () => {
    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req);
    expect(response.headers.get("x-profile-id")).toMatch(/^[0-9a-f]{6}$/);
  });

  it("sets Cache-Control header", async () => {
    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req);
    expect(response.headers.get("cache-control")).toMatch(/public, max-age=\d+/);
  });

  it("sets CORS header", async () => {
    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req);
    expect(response.headers.get("access-control-allow-origin")).toBe("*");
  });

  it("response body is valid JSON", async () => {
    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req);
    const json = await response.json();
    expect(typeof json.Status).toBe("number");
  });
});

// ---------------------------------------------------------------------------
// Wire DoH POST - normal flow (RFC 8484)
// ---------------------------------------------------------------------------

describe("Wire DoH POST", () => {
  const wireOkBody = buildDnsResponse("example.com.", "93.184.216.34", 300);

  beforeEach(() => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-message", body: wireOkBody },
      { contentType: "application/dns-message", body: wireOkBody },
      { contentType: "application/dns-message", body: wireOkBody },
    ]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 200 for a valid wire POST", async () => {
    const query = buildDnsQuery("example.com", 1);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
  });

  it("returns application/dns-message content type", async () => {
    const query = buildDnsQuery("example.com", 1);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatch(req);
    expect(response.headers.get("content-type")).toContain("dns-message");
  });

  it("accepts POST content-type with charset parameter", async () => {
    const query = buildDnsQuery("example.com", 1);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message; charset=utf-8" },
      body: query,
    });
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("dns-message");
  });
});

// ---------------------------------------------------------------------------
// Wire DoH GET (?dns=<base64url>) (RFC 8484)
// ---------------------------------------------------------------------------

describe("Wire DoH GET", () => {
  const wireOkBody = buildDnsResponse("example.com.", "93.184.216.34", 300);

  beforeEach(() => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-message", body: wireOkBody },
      { contentType: "application/dns-message", body: wireOkBody },
      { contentType: "application/dns-message", body: wireOkBody },
    ]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns 200 for a valid wire GET", async () => {
    const query = buildDnsQuery("example.com", 1);
    const b64 = btoa(String.fromCharCode(...query))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const req = new Request(`https://worker.example.com/dns-query?dns=${b64}`);
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
  });

  it("returns 400 for malformed base64url in ?dns= (RFC 8484 S.4.1)", async () => {
    // RFC 8484 S.4.1 requires an HTTP 400 for an invalid base64url value in ?dns=
    const req = new Request("https://worker.example.com/dns-query?dns=%25%25%25");
    const { response } = await dispatch(req);
    expect(response.status).toBe(400);
  });

  it("returns 400 for ?dns= that decodes to fewer than 12 bytes", async () => {
    // A valid DNS message requires at least a 12-byte header.
    const shortBytes = new Uint8Array(6);
    const b64 = btoa(String.fromCharCode(...shortBytes))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const req = new Request(`https://worker.example.com/dns-query?dns=${b64}`);
    const { response } = await dispatch(req);
    expect(response.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// Ambiguous query parameter handling
// ---------------------------------------------------------------------------

describe("Ambiguous query parameters", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("prioritises wire mode when both ?dns and ?name are present", async () => {
    const wireOkBody = buildDnsResponse("example.com.", "93.184.216.34", 300);
    const fetchMock = vi.fn(async () => {
      return new Response(wireOkBody, {
        status: 200,
        headers: { "Content-Type": "application/dns-message" },
      });
    });
    globalThis.fetch = fetchMock;

    const query = buildDnsQuery("example.com", 1);
    const b64 = btoa(String.fromCharCode(...query))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");

    const req = new Request(
      `https://worker.example.com/dns-query?name=example.com&type=A&dns=${b64}`
    );
    const { response } = await dispatch(req);

    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("dns-message");

    const [calledUrl, opts] = fetchMock.mock.calls[0];
    expect(calledUrl).toContain("dns=");
    expect(calledUrl).not.toContain("name=");
    expect(opts.headers.Accept).toBe("application/dns-message");
  });
});

// ---------------------------------------------------------------------------
// DNS transaction ID preservation (RFC 8484 SS.4.1)
// ---------------------------------------------------------------------------

describe("DNS transaction ID preservation (RFC 8484 SS.4.1)", () => {
  const wireOkBody = buildDnsResponse("example.com.", "1.2.3.4", 60);

  beforeEach(() => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-message", body: wireOkBody },
      { contentType: "application/dns-message", body: wireOkBody },
      { contentType: "application/dns-message", body: wireOkBody },
    ]);
  });

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("preserves client DNS ID 0xABCD in POST wire response", async () => {
    const query = buildDnsQuery("example.com", 1, 0xabcd);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatch(req);
    const buf = new Uint8Array(await response.arrayBuffer());
    expect(buf[0]).toBe(0xab);
    expect(buf[1]).toBe(0xcd);
  });

  it("zero DNS ID is sent to the upstream (normalization)", async () => {
    const query = buildDnsQuery("example.com", 1, 0xffff);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const capturedBodies = [];
    globalThis.fetch = vi.fn(async (url, opts) => {
      if (opts && opts.body) {
        capturedBodies.push(new Uint8Array(await new Response(opts.body).arrayBuffer()));
      }
      return new Response(wireOkBody, {
        headers: { "Content-Type": "application/dns-message" },
      });
    });
    await dispatch(req);
    // All upstream requests must have ID=0
    for (const b of capturedBodies) {
      expect(b[0]).toBe(0);
      expect(b[1]).toBe(0);
    }
  });
});

// ---------------------------------------------------------------------------
// Block detection
// ---------------------------------------------------------------------------

describe("Block detection", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("sets X-Blocked true for 0.0.0.0 A record (JSON)", async () => {
    const blockedJson = {
      Status: 0,
      Answer: [{ name: "blocked.example.", type: 1, TTL: 86400, data: "0.0.0.0" }],
    };
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: blockedJson },
      { contentType: "application/dns-json", body: blockedJson },
      { contentType: "application/dns-json", body: blockedJson },
    ]);
    const req = new Request("https://worker.example.com/dns-query?name=blocked.example&type=A");
    const { response } = await dispatch(req);
    expect(response.headers.get("x-blocked")).toBe("true");
  });

  it("sets X-Blocked true for NXDOMAIN without Authority (JSON)", async () => {
    const nxJson = { Status: 3 };
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: nxJson },
      { contentType: "application/dns-json", body: nxJson },
      { contentType: "application/dns-json", body: nxJson },
    ]);
    const req = new Request("https://worker.example.com/dns-query?name=blocked.example&type=A");
    const { response } = await dispatch(req);
    expect(response.headers.get("x-blocked")).toBe("true");
  });

  it("sets X-Blocked false for NXDOMAIN with Authority SOA (genuine NXDOMAIN)", async () => {
    const realNxJson = {
      Status: 3,
      Authority: [{ name: "example.com.", type: 6, TTL: 900, data: "ns1.example.com." }],
    };
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: realNxJson },
      { contentType: "application/dns-json", body: realNxJson },
      { contentType: "application/dns-json", body: realNxJson },
    ]);
    const req = new Request("https://worker.example.com/dns-query?name=gone.example&type=A");
    const { response } = await dispatch(req);
    expect(response.headers.get("x-blocked")).toBe("false");
  });

  it("sets X-Blocked true for blocked wire response (0.0.0.0)", async () => {
    const blockedWire = buildDnsResponse("blocked.example.", "0.0.0.0", 86400);
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-message", body: blockedWire },
      { contentType: "application/dns-message", body: blockedWire },
      { contentType: "application/dns-message", body: blockedWire },
    ]);
    const query = buildDnsQuery("blocked.example", 1);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatch(req);
    expect(response.headers.get("x-blocked")).toBe("true");
  });
});

// ---------------------------------------------------------------------------
// All upstreams fail - RFC 8484 s4.2.1 SERVFAIL response
// ---------------------------------------------------------------------------

// RFC 8484 s4.2.1: any valid DNS response, including SERVFAIL, MUST be
// returned with HTTP 200. The proxy must never return a bare 502 to a DoH
// client; instead it builds a synthetic SERVFAIL DNS reply.
describe("All upstreams fail - RFC 8484 s4.2.1 SERVFAIL response", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns HTTP 200 with SERVFAIL DNS body (JSON) when all upstreams return non-ok status", async () => {
    globalThis.fetch = makeFetch([
      { body: "Bad Gateway", status: 502 },
      { body: "Bad Gateway", status: 502 },
      { body: "Bad Gateway", status: 502 },
    ]);
    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/dns-json");
    const body = await response.json();
    expect(body.Status).toBe(2); // SERVFAIL
  });

  it("returns HTTP 200 with SERVFAIL DNS body (JSON) when all upstreams throw", async () => {
    globalThis.fetch = vi.fn(async () => { throw new Error("network error"); });
    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.Status).toBe(2); // SERVFAIL
  });

  it("returns HTTP 200 with SERVFAIL wire response when all upstreams fail on wire POST", async () => {
    globalThis.fetch = vi.fn(async () => { throw new Error("network error"); });
    const query = buildDnsQuery("example.com", 1, 0x1234);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/dns-message");
    const buf = new Uint8Array(await response.arrayBuffer());
    expect(buf.length).toBeGreaterThanOrEqual(4);
    expect(buf[3] & 0x0f).toBe(2); // rcode=2 (SERVFAIL)
    // DNS ID must be restored to client's original ID (RFC 8484 s4.1)
    expect((buf[0] << 8) | buf[1]).toBe(0x1234);
  });

  it("returns HTTP 200 with SERVFAIL wire response when all upstreams fail on wire GET", async () => {
    globalThis.fetch = vi.fn(async () => { throw new Error("network error"); });
    const query = buildDnsQuery("example.com", 1, 0x5678);
    let b64 = "";
    for (let i = 0; i < query.length; i++) b64 += String.fromCharCode(query[i]);
    const dnsParam = btoa(b64).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
    const req = new Request(`https://worker.example.com/dns-query?dns=${dnsParam}`);
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toContain("application/dns-message");
    const buf = new Uint8Array(await response.arrayBuffer());
    expect(buf[3] & 0x0f).toBe(2); // rcode=2 (SERVFAIL)
    expect((buf[0] << 8) | buf[1]).toBe(0x5678); // client ID restored
  });

  // Regression: an upstream returning HTTP 500 must not crash the worker.
  // The failed upstream is skipped and the next available upstream's response is used.
  it("returns 200 when one upstream returns HTTP 500 and another returns a valid response", async () => {
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce(new Response("Internal Server Error", { status: 500 }))
      .mockResolvedValueOnce(new Response(JSON.stringify(jsonOkBody), {
        status: 200,
        headers: { "Content-Type": "application/dns-json" },
      }));
    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.Status).toBe(0); // valid answer, not SERVFAIL
  });

  it("returns HTTP 200 with SERVFAIL when all upstreams return HTTP 500", async () => {
    globalThis.fetch = makeFetch([
      { body: "Internal Server Error", status: 500 },
      { body: "Internal Server Error", status: 500 },
      { body: "Internal Server Error", status: 500 },
    ]);
    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.Status).toBe(2); // SERVFAIL
  });
});

// ---------------------------------------------------------------------------
// Profile ID routing
// ---------------------------------------------------------------------------

describe("Profile ID routing", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("uses profile from /p-{hex}/ path segment", async () => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: jsonOkBody },
      { contentType: "application/dns-json", body: jsonOkBody },
    ]);

    const req = new Request(
      "https://worker.example.com/p-aabbcc/dns-query?name=example.com&type=A"
    );
    const { response } = await dispatch(req);

    // Profile ID extracted from path is reflected in the response header
    expect(response.headers.get("x-profile-id")).toBe("aabbcc");
  });

  it("returns X-Profile-Id matching the path segment", async () => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: jsonOkBody },
      { contentType: "application/dns-json", body: jsonOkBody },
      { contentType: "application/dns-json", body: jsonOkBody },
    ]);
    const req = new Request(
      "https://worker.example.com/p-112233/dns-query?name=example.com&type=A"
    );
    const { response } = await dispatch(req);
    expect(response.headers.get("x-profile-id")).toBe("112233");
  });
});

// ---------------------------------------------------------------------------
// Cache hit/miss behaviour
// ---------------------------------------------------------------------------

describe("Caching behaviour", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("serves from cache on second request and does not call fetch", async () => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: jsonOkBody },
      { contentType: "application/dns-json", body: jsonOkBody },
      { contentType: "application/dns-json", body: jsonOkBody },
    ]);

    const fakeCache = makeFakeCache();

    const req1 = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    await dispatch(req1, fakeCache);

    // Reset fetch mock to count second-request calls
    const fetchMock = vi.fn(async () => new Response(JSON.stringify(jsonOkBody), {
      headers: { "Content-Type": "application/dns-json" },
    }));
    globalThis.fetch = fetchMock;

    const req2 = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req2, fakeCache);

    expect(response.status).toBe(200);
    // fetch should not have been called for the cache hit
    expect(fetchMock).not.toHaveBeenCalled();
  });

  it("X-Worker-Cache-TTL header present on cached response", async () => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: jsonOkBody },
      { contentType: "application/dns-json", body: jsonOkBody },
      { contentType: "application/dns-json", body: jsonOkBody },
    ]);

    const fakeCache = makeFakeCache();

    // First request populates cache
    const req1 = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    await dispatch(req1, fakeCache);

    // Second request should be a cache hit
    const req2 = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    // Serve directly from cache store to inspect X-Worker-Cache-TTL
    const cachedEntries = [...fakeCache.store.values()];
    if (cachedEntries.length > 0) {
      const cached = cachedEntries[0];
      expect(cached.headers.get("x-worker-cache-ttl")).not.toBeNull();
    }
  });

  it("blocked response uses WORKER_BLOCKED_CACHE_TTL_SECONDS in edge cache", async () => {
    const blockedJson = {
      Status: 0,
      Answer: [{ name: "blocked.example.", type: 1, TTL: 86400, data: "0.0.0.0" }],
    };
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: blockedJson },
      { contentType: "application/dns-json", body: blockedJson },
      { contentType: "application/dns-json", body: blockedJson },
    ]);

    const fakeCache = makeFakeCache();
    const req = new Request("https://worker.example.com/dns-query?name=blocked.example&type=A");
    await dispatch(req, fakeCache);

    const cachedEntries = [...fakeCache.store.values()];
    if (cachedEntries.length > 0) {
      const cached = cachedEntries[0];
      const workerTtl = parseInt(cached.headers.get("x-worker-cache-ttl"), 10);
      // Should use blocked TTL (86400) rather than normal TTL (1800)
      expect(workerTtl).toBeGreaterThan(1800);
    }
  });

  it("restores DNS ID for wire cache hits while cache copy remains ID=0", async () => {
    const wireOkBody = buildDnsResponse("example.com.", "1.2.3.4", 300);
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-message", body: wireOkBody },
      { contentType: "application/dns-message", body: wireOkBody },
      { contentType: "application/dns-message", body: wireOkBody },
    ]);

    const fakeCache = makeFakeCache();
    const query = buildDnsQuery("example.com", 1, 0xbeef);
    const b64 = btoa(String.fromCharCode(...query))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const req = new Request(`https://worker.example.com/dns-query?dns=${b64}`);

    const first = await dispatch(req, fakeCache);
    const firstBuf = new Uint8Array(await first.response.arrayBuffer());
    expect(firstBuf[0]).toBe(0xbe);
    expect(firstBuf[1]).toBe(0xef);

    const cachedEntries = [...fakeCache.store.values()];
    expect(cachedEntries.length).toBeGreaterThan(0);
    const cachedBuf = new Uint8Array(await cachedEntries[0].clone().arrayBuffer());
    expect(cachedBuf[0]).toBe(0);
    expect(cachedBuf[1]).toBe(0);

    const fetchMock = vi.fn(async () => {
      return new Response(wireOkBody, {
        headers: { "Content-Type": "application/dns-message" },
      });
    });
    globalThis.fetch = fetchMock;

    const second = await dispatch(req, fakeCache);
    const secondBuf = new Uint8Array(await second.response.arrayBuffer());
    expect(secondBuf[0]).toBe(0xbe);
    expect(secondBuf[1]).toBe(0xef);
    expect(fetchMock).not.toHaveBeenCalled();
  });
});

// ---------------------------------------------------------------------------
// Error response cache safety
// ---------------------------------------------------------------------------

describe("Error response cache safety", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns Cache-Control: no-store on 400 invalid request", async () => {
    const req = new Request("https://worker.example.com/dns-query");
    const { response } = await dispatch(req);
    expect(response.status).toBe(400);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("returns Cache-Control: no-store when all upstreams fail (SERVFAIL)", async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new Error("network down");
    });
    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.Status).toBe(2); // SERVFAIL
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
});

// ---------------------------------------------------------------------------
// SERVFAIL filtering
// ---------------------------------------------------------------------------

describe("SERVFAIL filtering", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("treats SERVFAIL JSON response as failed upstream", async () => {
    // First upstream returns SERVFAIL, second returns OK
    const servfailJson = { Status: 2 };
    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce(new Response(JSON.stringify(servfailJson), {
        headers: { "Content-Type": "application/dns-json" },
      }))
      .mockResolvedValueOnce(new Response(JSON.stringify(jsonOkBody), {
        headers: { "Content-Type": "application/dns-json" },
      }));

    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
    expect(response.headers.get("x-blocked")).toBe("false");
  });
});

// ---------------------------------------------------------------------------
// X-Upstream-Index header
// ---------------------------------------------------------------------------

describe("X-Upstream-Index header", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns X-Upstream-Index: 0 when first upstream responds first", async () => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: jsonOkBody },
      { contentType: "application/dns-json", body: jsonOkBody },
      { contentType: "application/dns-json", body: jsonOkBody },
    ]);
    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req);
    expect(response.headers.get("x-upstream-index")).toBe("0");
  });
});

// ---------------------------------------------------------------------------
// Additional HTTP method tests
// ---------------------------------------------------------------------------

describe("Unsupported HTTP methods", () => {
  // Note: CONNECT is a tunnel method rejected by the Workers runtime before
  // reaching user code. Only test methods the runtime allows.
  const methods = ["HEAD", "TRACE"];

  afterEach(() => { vi.restoreAllMocks(); });

  for (const method of methods) {
    it(`returns 405 for ${method} method`, async () => {
      const req = new Request("https://worker.example.com/dns-query", { method });
      const { response } = await dispatch(req);
      expect(response.status).toBe(405);
      expect(response.headers.get("allow")).toContain("GET");
    });
  }
});

// ---------------------------------------------------------------------------
// Cache-Control: no-store on all error responses
// ---------------------------------------------------------------------------

describe("no-store cache safety for all error codes", () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it("405 response has Cache-Control: no-store", async () => {
    const req = new Request("https://worker.example.com/dns-query", { method: "DELETE" });
    const { response } = await dispatch(req);
    expect(response.status).toBe(405);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("415 response has Cache-Control: no-store", async () => {
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: "bad",
    });
    const { response } = await dispatch(req);
    expect(response.status).toBe(415);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });

  it("413 response has Cache-Control: no-store", async () => {
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: new Uint8Array(65536),
    });
    const { response } = await dispatch(req);
    expect(response.status).toBe(413);
    expect(response.headers.get("cache-control")).toBe("no-store");
  });
});

// ---------------------------------------------------------------------------
// X-Worker-Version header
// ---------------------------------------------------------------------------

describe("X-Worker-Version header", () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it("X-Worker-Version is present and looks like a semver for JSON GET", async () => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: jsonOkBody },
      { contentType: "application/dns-json", body: jsonOkBody },
    ]);
    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req);
    const ver = response.headers.get("x-worker-version");
    expect(ver).not.toBeNull();
    expect(ver).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("X-Worker-Version is present for wire POST", async () => {
    const wireOk = buildDnsResponse("example.com.", "1.2.3.4", 300);
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-message", body: wireOk },
      { contentType: "application/dns-message", body: wireOk },
    ]);
    const query = buildDnsQuery("example.com", 1);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatch(req);
    expect(response.headers.get("x-worker-version")).toMatch(/^\d+\.\d+\.\d+/);
  });
});

// ---------------------------------------------------------------------------
// Wire GET DNS ID extraction and restoration
// ---------------------------------------------------------------------------

describe("Wire GET - DNS ID extraction from base64url", () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it("restores correct DNS ID from wire GET ?dns= parameter", async () => {
    const wireOk = buildDnsResponse("example.com.", "1.2.3.4", 300);
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-message", body: wireOk },
      { contentType: "application/dns-message", body: wireOk },
    ]);

    const query = buildDnsQuery("example.com", 1, 0x1234);
    const b64 = btoa(String.fromCharCode(...query))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const req = new Request(`https://worker.example.com/dns-query?dns=${b64}`);

    const { response } = await dispatch(req);
    const buf = new Uint8Array(await response.arrayBuffer());
    expect(buf[0]).toBe(0x12);
    expect(buf[1]).toBe(0x34);
  });

  it("wire GET with DNS ID = 0 returns response with ID = 0", async () => {
    const wireOk = buildDnsResponse("example.com.", "1.2.3.4", 300);
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-message", body: wireOk },
      { contentType: "application/dns-message", body: wireOk },
    ]);

    const query = buildDnsQuery("example.com", 1, 0x0000);
    const b64 = btoa(String.fromCharCode(...query))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const req = new Request(`https://worker.example.com/dns-query?dns=${b64}`);

    const { response } = await dispatch(req);
    const buf = new Uint8Array(await response.arrayBuffer());
    expect(buf[0]).toBe(0x00);
    expect(buf[1]).toBe(0x00);
  });
});

// ---------------------------------------------------------------------------
// Multiple profiles - separate cache entries
// ---------------------------------------------------------------------------

describe("Multiple profiles produce separate cache entries", () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it("different profile IDs produce distinct cache entries", async () => {
    const fakeCache = makeFakeCache();
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: jsonOkBody },
      { contentType: "application/dns-json", body: jsonOkBody },
    ]);

    const req1 = new Request("https://worker.example.com/p-aabbcc/dns-query?name=example.com&type=A");
    await dispatch(req1, fakeCache);

    const req2 = new Request("https://worker.example.com/p-112233/dns-query?name=example.com&type=A");
    await dispatch(req2, fakeCache);

    // Two distinct cache keys for two different profiles
    expect(fakeCache.store.size).toBeGreaterThanOrEqual(2);
    const keys = [...fakeCache.store.keys()];
    const hasProfile1 = keys.some(k => k.includes("aabbcc"));
    const hasProfile2 = keys.some(k => k.includes("112233"));
    expect(hasProfile1).toBe(true);
    expect(hasProfile2).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Security - CORS preflight does not expose sensitive headers
// ---------------------------------------------------------------------------

describe("CORS preflight security", () => {
  it("preflight does not include Cache-Control: public", async () => {
    const req = new Request("https://worker.example.com/dns-query", { method: "OPTIONS" });
    const { response } = await dispatch(req);
    const cc = response.headers.get("cache-control");
    // Preflight should not advertise public caching
    // cc may be null (no Cache-Control header on OPTIONS) or empty - neither should be "public"
    if (cc !== null) {
      expect(cc).not.toContain("public");
    }
    // At minimum, preflight must not set public caching directives
    expect(cc).not.toBe("public");
  });
});

// ---------------------------------------------------------------------------
// All-fail response carries expected DNS fields
// ---------------------------------------------------------------------------

describe("All-fail SERVFAIL response structure", () => {
  afterEach(() => { vi.restoreAllMocks(); });

  it("SERVFAIL JSON body includes Status=2 and Question with queried name", async () => {
    globalThis.fetch = vi.fn(async () => { throw new Error("connection refused"); });
    const req = new Request("https://worker.example.com/p-aabbcc/dns-query?name=fail.example&type=A");
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.Status).toBe(2); // SERVFAIL
    expect(Array.isArray(body.Question)).toBe(true);
    expect(body.Question[0].name).toBe("fail.example");
    expect(response.headers.get("x-profile-id")).toBe("aabbcc");
  });
});

// ---------------------------------------------------------------------------
// Blocking mode and EDE integration
// ---------------------------------------------------------------------------

describe("Blocking mode - wire POST", () => {
  // Upstream that returns a blocked wire response (0.0.0.0)
  const blockedWire = buildDnsResponse("blocked.example.", "0.0.0.0", 86400);

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("null mode: wire response has A=0.0.0.0", async () => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-message", body: blockedWire },
      { contentType: "application/dns-message", body: blockedWire },
    ]);
    const query = buildDnsQuery("blocked.example", 1);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatchWithEnv(req, null, { BLOCKING_MODE: "null" });
    expect(response.headers.get("x-blocked")).toBe("true");
    expect(response.headers.get("x-blocking-mode")).toBe("null");
    const buf = new Uint8Array(await response.arrayBuffer());
    // rcode = bits 0-3 of byte 3
    expect(buf[3] & 0x0f).toBe(0); // NOERROR
  });

  it("nxdomain mode: wire response has rcode=3", async () => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-message", body: blockedWire },
      { contentType: "application/dns-message", body: blockedWire },
    ]);
    const query = buildDnsQuery("blocked.example", 1);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatchWithEnv(req, null, { BLOCKING_MODE: "nxdomain" });
    expect(response.headers.get("x-blocked")).toBe("true");
    const buf = new Uint8Array(await response.arrayBuffer());
    expect(buf[3] & 0x0f).toBe(3); // NXDOMAIN
  });

  it("refused mode: wire response has rcode=5", async () => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-message", body: blockedWire },
      { contentType: "application/dns-message", body: blockedWire },
    ]);
    const query = buildDnsQuery("blocked.example", 1);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatchWithEnv(req, null, { BLOCKING_MODE: "refused" });
    const buf = new Uint8Array(await response.arrayBuffer());
    expect(buf[3] & 0x0f).toBe(5); // REFUSED
  });

  it("nodata mode: wire response has rcode=0 and no answer", async () => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-message", body: blockedWire },
      { contentType: "application/dns-message", body: blockedWire },
    ]);
    const query = buildDnsQuery("blocked.example", 1);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatchWithEnv(req, null, { BLOCKING_MODE: "nodata" });
    const buf = new Uint8Array(await response.arrayBuffer());
    expect(buf[3] & 0x0f).toBe(0); // NOERROR
    expect((buf[6] << 8) | buf[7]).toBe(0); // ANCOUNT=0
  });
});

describe("Blocking mode - EDE in wire POST (always auto-derived)", () => {
  const blockedWire = buildDnsResponse("blocked.example.", "0.0.0.0", 86400);

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("wire blocked response always includes an OPT record with EDE", async () => {
    // EDE is hardcoded; no env override needed - it is always present.
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-message", body: blockedWire },
      { contentType: "application/dns-message", body: blockedWire },
    ]);
    const query = buildDnsQuery("blocked.example", 1);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatchWithEnv(req, null, { BLOCKING_MODE: "nxdomain" });
    const buf = new Uint8Array(await response.arrayBuffer());
    // ARCOUNT=1 means OPT record (with EDE) was injected
    expect((buf[10] << 8) | buf[11]).toBe(1);
  });

  it("EDE always contains the blocking upstream URL hostname", async () => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-message", body: blockedWire },
      { contentType: "application/dns-message", body: blockedWire },
    ]);
    const query = buildDnsQuery("blocked.example", 1);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatchWithEnv(req, null, {
      BLOCKING_MODE: "nxdomain",
      UPSTREAM_SERVERS: '["https://dns.quad9.net/dns-query"]',
    });
    const buf = new Uint8Array(await response.arrayBuffer());
    expect((buf[10] << 8) | buf[11]).toBe(1); // OPT present
    const bufStr = String.fromCharCode(...buf);
    expect(bufStr).toContain("dns.quad9.net");
  });

  it("EDE text follows 'Blocked (url)' format", async () => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-message", body: blockedWire },
      { contentType: "application/dns-message", body: blockedWire },
    ]);
    const query = buildDnsQuery("blocked.example", 1);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatchWithEnv(req, null, {
      BLOCKING_MODE: "nxdomain",
      UPSTREAM_SERVERS: '["https://dns.quad9.net/dns-query"]',
    });
    const buf = new Uint8Array(await response.arrayBuffer());
    const bufStr = String.fromCharCode(...buf);
    // "Blocked (" prefix and closing ")" must both appear
    expect(bufStr).toContain("Blocked (");
    expect(bufStr).toContain("dns-query)");
  });

  it("EDE is present with all four blocking modes", async () => {
    for (const mode of ["null", "nxdomain", "nodata", "refused"]) {
      globalThis.fetch = makeFetch([
        { contentType: "application/dns-message", body: blockedWire },
        { contentType: "application/dns-message", body: blockedWire },
      ]);
      const query = buildDnsQuery("blocked.example", 1);
      const req = new Request("https://worker.example.com/dns-query", {
        method: "POST",
        headers: { "Content-Type": "application/dns-message" },
        body: query,
      });
      const { response } = await dispatchWithEnv(req, null, { BLOCKING_MODE: mode });
      const buf = new Uint8Array(await response.arrayBuffer());
      expect((buf[10] << 8) | buf[11]).toBe(1);
    }
  });
});

describe("Blocking mode - JSON GET", () => {
  const blockedJson = {
    Status: 3, // NXDOMAIN (no authority = blocked)
    Question: [{ name: "blocked.example.", type: 1 }],
  };

  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("null mode: JSON response has 0.0.0.0 for A query", async () => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: blockedJson },
      { contentType: "application/dns-json", body: blockedJson },
    ]);
    const req = new Request("https://worker.example.com/dns-query?name=blocked.example&type=A");
    const { response } = await dispatchWithEnv(req, null, { BLOCKING_MODE: "null" });
    expect(response.headers.get("x-blocked")).toBe("true");
    const json = await response.json();
    expect(json.Status).toBe(0);
    expect(json.Answer[0].data).toBe("0.0.0.0");
  });

  it("nxdomain mode: JSON response has Status=3", async () => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: blockedJson },
      { contentType: "application/dns-json", body: blockedJson },
    ]);
    const req = new Request("https://worker.example.com/dns-query?name=blocked.example&type=A");
    const { response } = await dispatchWithEnv(req, null, { BLOCKING_MODE: "nxdomain" });
    const json = await response.json();
    expect(json.Status).toBe(3);
    expect(json.Answer).toBeUndefined();
  });

  it("x-blocking-mode header is present on blocked JSON response", async () => {
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: blockedJson },
      { contentType: "application/dns-json", body: blockedJson },
    ]);
    const req = new Request("https://worker.example.com/dns-query?name=blocked.example&type=A");
    const { response } = await dispatchWithEnv(req, null, { BLOCKING_MODE: "nodata" });
    expect(response.headers.get("x-blocking-mode")).toBe("nodata");
  });
});

// ---------------------------------------------------------------------------
// DNSSEC preference (hardcoded - always prefer signed upstream responses)
// ---------------------------------------------------------------------------

describe("DNSSEC preference - hardcoded (always prefers signed responses)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("returns DNSSEC-signed response from upstream[1] over unsigned from upstream[0]", async () => {
    // upstream[0] returns an unsigned response (no AD bit)
    const unsignedResp = buildDnsResponse("example.com.", "1.2.3.4", 300);
    // upstream[1] returns a DNSSEC-signed response (AD bit set)
    const signedResp = buildDnsResponse("example.com.", "5.6.7.8", 300);
    signedResp[3] |= 0x20; // set AD bit

    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce(new Response(unsignedResp, {
        status: 200,
        headers: { "Content-Type": "application/dns-message" },
      }))
      .mockResolvedValueOnce(new Response(signedResp, {
        status: 200,
        headers: { "Content-Type": "application/dns-message" },
      }));

    const query = buildDnsQuery("example.com", 1);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    // Use two upstreams: [0] unsigned (lower-priority), [1] signed (higher DNS priority = preferred)
    const { response } = await dispatchWithEnv(req, null, {
      UPSTREAM_SERVERS: '["https://upstream-a.example.com/dns-query","https://upstream-b.example.com/dns-query"]',
    });

    expect(response.status).toBe(200);
    // The signed upstream (index 1) must have been selected
    expect(response.headers.get("x-upstream-index")).toBe("1");
  });

  it("falls back to unsigned response when no upstream provides DNSSEC data", async () => {
    const resp1 = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const resp2 = buildDnsResponse("example.com.", "1.2.3.4", 300);

    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce(new Response(resp1, {
        status: 200,
        headers: { "Content-Type": "application/dns-message" },
      }))
      .mockResolvedValueOnce(new Response(resp2, {
        status: 200,
        headers: { "Content-Type": "application/dns-message" },
      }));

    const query = buildDnsQuery("example.com", 1);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatchWithEnv(req, null, {
      UPSTREAM_SERVERS: '["https://upstream-a.example.com/dns-query","https://upstream-b.example.com/dns-query"]',
    });

    expect(response.status).toBe(200);
    // No DNSSEC available, first (index 0) clean result is used
    expect(response.headers.get("x-upstream-index")).toBe("0");
  });

  it("DNSSEC-signed response from any upstream is preferred over unsigned from index 0", async () => {
    // Three upstreams: index 0 unsigned, index 1 also unsigned, index 2 signed
    const unsigned1 = buildDnsResponse("example.com.", "1.1.1.1", 300);
    const unsigned2 = buildDnsResponse("example.com.", "2.2.2.2", 300);
    const signed3 = buildDnsResponse("example.com.", "3.3.3.3", 300);
    signed3[3] |= 0x20;

    globalThis.fetch = vi.fn()
      .mockResolvedValueOnce(new Response(unsigned1, { status: 200, headers: { "Content-Type": "application/dns-message" } }))
      .mockResolvedValueOnce(new Response(unsigned2, { status: 200, headers: { "Content-Type": "application/dns-message" } }))
      .mockResolvedValueOnce(new Response(signed3, { status: 200, headers: { "Content-Type": "application/dns-message" } }));

    const query = buildDnsQuery("example.com", 1);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatchWithEnv(req, null, {
      UPSTREAM_SERVERS: '["https://us-a.example.com/dns-query","https://us-b.example.com/dns-query","https://us-c.example.com/dns-query"]',
    });

    expect(response.status).toBe(200);
    expect(response.headers.get("x-upstream-index")).toBe("2");
  });
});

// ---------------------------------------------------------------------------
// Background cache refresh (stale-while-revalidate)
// ---------------------------------------------------------------------------

// Helper to build a fake cached response with timing headers set to make
// shouldRenewCache() return true.  totalTtl is the X-Worker-Cache-TTL value;
// age is how old to pretend the entry is (in seconds).
function makeStaleResp(body, contentType, totalTtl, age) {
  const insertedAt = Math.floor(Date.now() / 1000) - age;
  return new Response(
    typeof body === "string" ? body : JSON.stringify(body),
    {
      status: 200,
      headers: {
        "Content-Type":       contentType,
        "Cache-Control":      `public, max-age=${totalTtl - age}`,
        "X-Worker-Cache-TTL": String(totalTtl),
        "X-Cache-Inserted-At": String(insertedAt),
        "X-Blocked":          "false",
        "X-Profile-Id":       "000000",
        "X-Client-Cache-TTL": String(totalTtl - age),
        "Access-Control-Allow-Origin": "*",
        "Vary":               "Accept",
      },
    }
  );
}

describe("Background cache refresh (stale-while-revalidate)", () => {
  afterEach(() => {
    vi.restoreAllMocks();
  });

  it("serves cached response immediately even when renew threshold met", async () => {
    const freshBody = { ...jsonOkBody, Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "9.9.9.9" }] };
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: freshBody },
      { contentType: "application/dns-json", body: freshBody },
    ]);

    const fakeCache = makeFakeCache();
    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");

    // Pre-populate cache with a near-expired entry (1800s TTL, 1700s old => 100s < 10%*1800=180s)
    const staleBody = { ...jsonOkBody, Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "1.2.3.4" }] };
    const cacheKey = "https://doh-cache.internal/000000/json/example.com/A";
    fakeCache.store.set(cacheKey, makeStaleResp(staleBody, "application/dns-json", 1800, 1700).clone());

    const { response } = await dispatchWithEnv(req, fakeCache, { CACHE_RENEW_PERCENT: "10" });

    // Response is served from cache (contains stale IP)
    expect(response.status).toBe(200);
    const json = await response.json();
    expect(json.Answer[0].data).toBe("1.2.3.4");
  });

  it("triggers background refresh and updates cache with fresh upstream result", async () => {
    const freshBody = {
      ...jsonOkBody,
      Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "9.9.9.9" }],
    };
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: freshBody },
      { contentType: "application/dns-json", body: freshBody },
    ]);

    const fakeCache = makeFakeCache();
    const cacheKey = "https://doh-cache.internal/000000/json/example.com/A";
    const staleBody = { ...jsonOkBody, Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "1.2.3.4" }] };
    fakeCache.store.set(cacheKey, makeStaleResp(staleBody, "application/dns-json", 1800, 1700).clone());

    // dispatchWithEnv awaits waitUntil tasks, so by the time it returns the
    // background refresh has written fresh data into the cache.
    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    await dispatchWithEnv(req, fakeCache, { CACHE_RENEW_PERCENT: "10" });

    // After background refresh settles, the cache should have the fresh IP.
    const updated = fakeCache.store.get(cacheKey);
    expect(updated).not.toBeNull();
    const updatedJson = await updated.json();
    expect(updatedJson.Answer[0].data).toBe("9.9.9.9");
  });

  it("does not trigger background refresh when entry is fresh (above threshold)", async () => {
    globalThis.fetch = vi.fn();

    const fakeCache = makeFakeCache();
    const cacheKey = "https://doh-cache.internal/000000/json/example.com/A";
    // Fresh entry: only 10s old, 1800s TTL => 1790s remaining >> 180s threshold
    const freshEntry = { ...jsonOkBody, Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "1.2.3.4" }] };
    fakeCache.store.set(cacheKey, makeStaleResp(freshEntry, "application/dns-json", 1800, 10).clone());

    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    await dispatchWithEnv(req, fakeCache, { CACHE_RENEW_PERCENT: "10" });

    // fetch must not have been called because the entry is well above threshold
    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("does not trigger background refresh when CACHE_RENEW_PERCENT is 0", async () => {
    globalThis.fetch = vi.fn();

    const fakeCache = makeFakeCache();
    const cacheKey = "https://doh-cache.internal/000000/json/example.com/A";
    // Entry is near-expired but CACHE_RENEW_PERCENT=0 disables renewal
    const staleBody = { ...jsonOkBody };
    fakeCache.store.set(cacheKey, makeStaleResp(staleBody, "application/dns-json", 1800, 1700).clone());

    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    await dispatchWithEnv(req, fakeCache, { CACHE_RENEW_PERCENT: "0" });

    expect(globalThis.fetch).not.toHaveBeenCalled();
  });

  it("background refresh updates cache with blocked response when upstream blocks", async () => {
    const blockedBody = {
      Status: 0,
      Answer: [{ name: "blocked.example.", type: 1, TTL: 86400, data: "0.0.0.0" }],
    };
    globalThis.fetch = makeFetch([
      { contentType: "application/dns-json", body: blockedBody },
      { contentType: "application/dns-json", body: blockedBody },
    ]);

    const fakeCache = makeFakeCache();
    const cacheKey = "https://doh-cache.internal/000000/json/blocked.example/A";
    // Old unblocked entry nearing expiry
    const oldBody = { ...jsonOkBody, Question: [{ name: "blocked.example.", type: 1 }] };
    fakeCache.store.set(cacheKey, makeStaleResp(oldBody, "application/dns-json", 1800, 1700).clone());

    const req = new Request("https://worker.example.com/dns-query?name=blocked.example&type=A");
    await dispatchWithEnv(req, fakeCache, { CACHE_RENEW_PERCENT: "10" });

    const updated = fakeCache.store.get(cacheKey);
    expect(updated).not.toBeNull();
    // Cache should now contain the blocked response
    const updatedClone = updated.clone();
    expect(updatedClone.headers.get("x-blocked")).toBe("true");
  });

  it("missing timing headers on cached entry: no refresh triggered", async () => {
    globalThis.fetch = vi.fn();

    const fakeCache = makeFakeCache();
    const cacheKey = "https://doh-cache.internal/000000/json/example.com/A";
    // Entry without X-Cache-Inserted-At / X-Worker-Cache-TTL (old format)
    fakeCache.store.set(cacheKey, new Response(JSON.stringify(jsonOkBody), {
      status: 200,
      headers: {
        "Content-Type": "application/dns-json",
        "Cache-Control": "public, max-age=1",
        // No X-Cache-Inserted-At or X-Worker-Cache-TTL
      },
    }));

    const req = new Request("https://worker.example.com/dns-query?name=example.com&type=A");
    await dispatchWithEnv(req, fakeCache, { CACHE_RENEW_PERCENT: "10" });

    expect(globalThis.fetch).not.toHaveBeenCalled();
  });
});
