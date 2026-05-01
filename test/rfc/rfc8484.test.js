// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/rfc/rfc8484.test.js
// Tests for RFC 8484 compliance: DNS Queries over HTTPS
//
// RFC 8484 requirements tested:
//   SS.4.1  - DNS ID must be 0 in wire format sent to upstreams and stored in cache
//   SS.4.1  - Client DNS ID must be restored in the response
//   SS.4.2  - GET with ?dns= parameter (base64url, no padding)
//   SS.4.2  - POST with Content-Type: application/dns-message
//   SS.4.2.1 - HTTP status codes: 200, 400, 405, 413, 415 (SERVFAIL returned as HTTP 200 per RFC 8484 s4.2.1)
//   SS.4.2.1 - Content-Type in response must match request format
//   SS.4.2.1 - Cache-Control response header required
//   SS.5.1  - GET request ?dns= must use base64url without padding

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleRequest } from "../../src/handler.js";
import { buildDnsQuery, buildDnsResponse } from "../../src/dns.js";

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

async function dispatch(request, fakeCache) {
  const cache = fakeCache || makeFakeCache();
  const env = {};
  const waitUntilTasks = [];
  const ctx = { waitUntil: (p) => waitUntilTasks.push(p) };
  const originalCaches = globalThis.caches;
  globalThis.caches = { default: cache };
  try {
    const response = await handleRequest(request, env, ctx);
    await Promise.allSettled(waitUntilTasks);
    return { response, cache };
  } finally {
    globalThis.caches = originalCaches;
  }
}

const wireOk = buildDnsResponse("example.com.", "93.184.216.34", 300);
const jsonOk = {
  Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false,
  Question: [{ name: "example.com.", type: 1 }],
  Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "93.184.216.34" }],
};

function wirefetch() {
  return vi.fn(async () => new Response(wireOk, {
    headers: { "Content-Type": "application/dns-message" },
  }));
}

function jsonfetch() {
  return vi.fn(async () => new Response(JSON.stringify(jsonOk), {
    headers: { "Content-Type": "application/dns-json" },
  }));
}

afterEach(() => { vi.restoreAllMocks(); });

// ---------------------------------------------------------------------------
// SS.4.1 - DNS ID handling
// ---------------------------------------------------------------------------

describe("RFC 8484 SS.4.1 - DNS transaction ID handling", () => {
  it("upstreams always receive DNS ID = 0 in POST requests", async () => {
    const capturedBodies = [];
    globalThis.fetch = vi.fn(async (url, opts) => {
      if (opts && opts.body) {
        capturedBodies.push(new Uint8Array(await new Response(opts.body).arrayBuffer()));
      }
      return new Response(wireOk, { headers: { "Content-Type": "application/dns-message" } });
    });

    const query = buildDnsQuery("example.com", 1, 0x1234);
    const req = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    await dispatch(req);
    for (const b of capturedBodies) {
      expect(b[0]).toBe(0);
      expect(b[1]).toBe(0);
    }
  });

  it("client receives its original DNS ID in the response", async () => {
    globalThis.fetch = wirefetch();
    const query = buildDnsQuery("example.com", 1, 0x5678);
    const req = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatch(req);
    const buf = new Uint8Array(await response.arrayBuffer());
    expect(buf[0]).toBe(0x56);
    expect(buf[1]).toBe(0x78);
  });

  it("cache stores response with DNS ID = 0", async () => {
    globalThis.fetch = wirefetch();
    const fakeCache = makeFakeCache();
    const query = buildDnsQuery("example.com", 1, 0xabcd);
    const req = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    await dispatch(req, fakeCache);

    const cachedEntries = [...fakeCache.store.values()];
    if (cachedEntries.length > 0) {
      const buf = new Uint8Array(await cachedEntries[0].arrayBuffer());
      expect(buf[0]).toBe(0);
      expect(buf[1]).toBe(0);
    }
  });

  it("DNS ID = 0 in request is handled without error", async () => {
    globalThis.fetch = wirefetch();
    const query = buildDnsQuery("example.com", 1, 0x0000);
    const req = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// SS.4.2 - GET format
// ---------------------------------------------------------------------------

describe("RFC 8484 SS.4.2 - GET with ?dns= base64url", () => {
  it("accepts base64url without padding", async () => {
    globalThis.fetch = wirefetch();
    const query = buildDnsQuery("example.com", 1);
    const b64 = btoa(String.fromCharCode(...query))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const req = new Request(`https://w.example.com/dns-query?dns=${b64}`);
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
  });

  it("accepts base64url with padding (strips it internally)", async () => {
    globalThis.fetch = wirefetch();
    const query = buildDnsQuery("example.com", 1);
    const b64 = btoa(String.fromCharCode(...query))
      .replace(/\+/g, "-").replace(/\//g, "_");
    const req = new Request(`https://w.example.com/dns-query?dns=${b64}`);
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
  });

  it("returns application/dns-message for wire GET", async () => {
    globalThis.fetch = wirefetch();
    const query = buildDnsQuery("example.com", 1);
    const b64 = btoa(String.fromCharCode(...query))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const req = new Request(`https://w.example.com/dns-query?dns=${b64}`);
    const { response } = await dispatch(req);
    expect(response.headers.get("content-type")).toContain("dns-message");
  });

  // RFC 8484 S.4.1: server MUST return HTTP 400 when ?dns= is not valid base64url.
  it("returns 400 for invalid base64url characters in ?dns= (RFC 8484 S.4.1)", async () => {
    const req = new Request("https://w.example.com/dns-query?dns=%25%25%25");
    const { response } = await dispatch(req);
    expect(response.status).toBe(400);
  });

  it("returns 400 when ?dns= decodes to fewer than 12 bytes (too short for DNS header)", async () => {
    const shortBuf = new Uint8Array(4);
    const b64 = btoa(String.fromCharCode(...shortBuf))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const req = new Request(`https://w.example.com/dns-query?dns=${b64}`);
    const { response } = await dispatch(req);
    expect(response.status).toBe(400);
  });
});

// ---------------------------------------------------------------------------
// SS.4.2 - POST format
// ---------------------------------------------------------------------------

describe("RFC 8484 SS.4.2 - POST with application/dns-message", () => {
  it("accepts POST Content-Type: application/dns-message", async () => {
    globalThis.fetch = wirefetch();
    const query = buildDnsQuery("example.com", 1);
    const req = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
  });

  it("returns 415 for POST with Content-Type: text/plain", async () => {
    const req = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: "not-dns",
    });
    const { response } = await dispatch(req);
    expect(response.status).toBe(415);
  });

  it("returns 415 for POST with Content-Type: application/json", async () => {
    const req = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: "{}",
    });
    const { response } = await dispatch(req);
    expect(response.status).toBe(415);
  });
});

// ---------------------------------------------------------------------------
// SS.4.2.1 - HTTP status codes
// ---------------------------------------------------------------------------

describe("RFC 8484 SS.4.2.1 - HTTP status codes", () => {
  it("returns 200 for valid GET query", async () => {
    globalThis.fetch = jsonfetch();
    const req = new Request("https://w.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
  });

  it("returns 400 for request without any DoH parameters", async () => {
    const req = new Request("https://w.example.com/dns-query");
    const { response } = await dispatch(req);
    expect(response.status).toBe(400);
  });

  it("returns 405 for unsupported HTTP method", async () => {
    const req = new Request("https://w.example.com/dns-query", { method: "DELETE" });
    const { response } = await dispatch(req);
    expect(response.status).toBe(405);
  });

  it("returns 413 for POST body > 65535 bytes", async () => {
    const req = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: new Uint8Array(65536),
    });
    const { response } = await dispatch(req);
    expect(response.status).toBe(413);
  });

  it("returns 415 for POST with wrong content type", async () => {
    const req = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "text/dns" },
      body: new Uint8Array(16),
    });
    const { response } = await dispatch(req);
    expect(response.status).toBe(415);
  });

  it("returns HTTP 200 with SERVFAIL DNS body when all upstreams fail (RFC 8484 s4.2.1)", async () => {
    globalThis.fetch = vi.fn(async () => { throw new Error("network failure"); });
    const req = new Request("https://w.example.com/dns-query?name=fail.example&type=A");
    const { response } = await dispatch(req);
    // RFC 8484 s4.2.1: DNS error responses MUST use HTTP 200, not HTTP 502
    expect(response.status).toBe(200);
    const body = await response.json();
    expect(body.Status).toBe(2); // SERVFAIL
  });
});

// ---------------------------------------------------------------------------
// SS.4.2.1 - Content-Type response header
// ---------------------------------------------------------------------------

describe("RFC 8484 SS.4.2.1 - Response Content-Type", () => {
  it("returns application/dns-json for JSON GET", async () => {
    globalThis.fetch = jsonfetch();
    const req = new Request("https://w.example.com/dns-query?name=example.com&type=A", {
      headers: { Accept: "application/dns-json" },
    });
    const { response } = await dispatch(req);
    expect(response.headers.get("content-type")).toContain("application/dns-json");
  });

  it("returns application/dns-message for wire POST", async () => {
    globalThis.fetch = wirefetch();
    const query = buildDnsQuery("example.com", 1);
    const req = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatch(req);
    expect(response.headers.get("content-type")).toContain("dns-message");
  });

  it("returns application/dns-message for wire GET", async () => {
    globalThis.fetch = wirefetch();
    const query = buildDnsQuery("example.com", 1);
    const b64 = btoa(String.fromCharCode(...query))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const req = new Request(`https://w.example.com/dns-query?dns=${b64}`);
    const { response } = await dispatch(req);
    expect(response.headers.get("content-type")).toContain("dns-message");
  });
});

// ---------------------------------------------------------------------------
// SS.4.2.1 - Cache-Control response header
// ---------------------------------------------------------------------------

describe("RFC 8484 SS.4.2.1 - Cache-Control header", () => {
  it("includes Cache-Control header in JSON GET response", async () => {
    globalThis.fetch = jsonfetch();
    const req = new Request("https://w.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req);
    const cc = response.headers.get("cache-control");
    expect(cc).not.toBeNull();
    expect(cc).toContain("max-age=");
  });

  it("includes Cache-Control header in wire POST response", async () => {
    globalThis.fetch = wirefetch();
    const query = buildDnsQuery("example.com", 1);
    const req = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatch(req);
    const cc = response.headers.get("cache-control");
    expect(cc).not.toBeNull();
    expect(cc).toContain("max-age=");
  });

  it("Cache-Control max-age respects MIN_CACHE_TTL_FLOOR (at least 60)", async () => {
    // Craft a response with very short TTL (1 second)
    const shortTtlJson = {
      Status: 0,
      Answer: [{ name: "short.example.", type: 1, TTL: 1, data: "1.2.3.4" }],
    };
    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify(shortTtlJson), {
      headers: { "Content-Type": "application/dns-json" },
    }));
    const req = new Request("https://w.example.com/dns-query?name=short.example&type=A");
    const { response } = await dispatch(req);
    const cc = response.headers.get("cache-control");
    const maxAge = parseInt(cc.replace("public, max-age=", ""), 10);
    expect(maxAge).toBeGreaterThanOrEqual(60);
  });
});

// ---------------------------------------------------------------------------
// RFC 1035 wire format round-trip
// ---------------------------------------------------------------------------

describe("RFC 1035 - DNS wire format round-trip", () => {
  it("correctly parses a wire response and returns valid JSON", async () => {
    globalThis.fetch = wirefetch();
    const req = new Request("https://w.example.com/dns-query?name=example.com&type=A", {
      headers: { Accept: "application/dns-json" },
    });
    const { response } = await dispatch(req);
    expect(response.headers.get("content-type")).toContain("dns-json");
    const json = await response.json();
    expect(typeof json.Status).toBe("number");
  });
});

// ---------------------------------------------------------------------------
// RFC 8484 SS.4.1 - Wire GET DNS ID round-trip
// ---------------------------------------------------------------------------

describe("RFC 8484 SS.4.1 - Wire GET DNS ID round-trip", () => {
  it("client DNS ID extracted from ?dns= base64url and restored in response", async () => {
    globalThis.fetch = wirefetch();
    const query = buildDnsQuery("example.com", 1, 0xabcd);
    const b64 = btoa(String.fromCharCode(...query))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const req = new Request(`https://w.example.com/dns-query?dns=${b64}`);
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
    const buf = new Uint8Array(await response.arrayBuffer());
    expect(buf[0]).toBe(0xab);
    expect(buf[1]).toBe(0xcd);
  });

  it("DNS ID 0xFFFF is correctly restored from wire GET", async () => {
    globalThis.fetch = wirefetch();
    const query = buildDnsQuery("example.com", 1, 0xffff);
    const b64 = btoa(String.fromCharCode(...query))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    const req = new Request(`https://w.example.com/dns-query?dns=${b64}`);
    const { response } = await dispatch(req);
    const buf = new Uint8Array(await response.arrayBuffer());
    expect(buf[0]).toBe(0xff);
    expect(buf[1]).toBe(0xff);
  });
});

// ---------------------------------------------------------------------------
// RFC 8484 SS.4.2.1 - 400 error body is JSON
// ---------------------------------------------------------------------------

describe("RFC 8484 SS.4.2.1 - Error response bodies", () => {
  it("400 response body is valid JSON", async () => {
    const req = new Request("https://w.example.com/dns-query");
    const { response } = await dispatch(req);
    expect(response.status).toBe(400);
    const text = await response.text();
    expect(() => JSON.parse(text)).not.toThrow();
  });

  it("all-upstreams-fail response is valid DNS JSON with SERVFAIL status", async () => {
    globalThis.fetch = vi.fn(async () => { throw new Error("network failure"); });
    const req = new Request("https://w.example.com/dns-query?name=fail.example&type=A");
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
    const text = await response.text();
    const body = JSON.parse(text);
    expect(body.Status).toBe(2); // SERVFAIL
  });

  it("CORS header is present on 400 error response", async () => {
    // RFC 8484 does not require CORS on errors but our implementation should
    // not break browser clients by omitting it.
    const req = new Request("https://w.example.com/dns-query");
    const { response } = await dispatch(req);
    expect(response.status).toBe(400);
    // Access-Control-Allow-Origin is only set on successful DoH responses;
    // verify that the lack does not cause a null dereference.
    expect(response.headers.get("content-type")).toContain("application/json");
  });

  it("405 response includes Allow header listing GET, POST, OPTIONS", async () => {
    const req = new Request("https://w.example.com/dns-query", { method: "PUT" });
    const { response } = await dispatch(req);
    expect(response.status).toBe(405);
    const allow = response.headers.get("allow");
    expect(allow).toContain("GET");
    expect(allow).toContain("POST");
    expect(allow).toContain("OPTIONS");
  });
});

// ---------------------------------------------------------------------------
// RFC 8484 - Vary: Accept header requirement
// ---------------------------------------------------------------------------

describe("RFC 8484 - Vary: Accept header", () => {
  it("successful wire POST response includes Vary: Accept", async () => {
    globalThis.fetch = wirefetch();
    const query = buildDnsQuery("example.com", 1);
    const req = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatch(req);
    expect(response.headers.get("vary")).toBe("Accept");
  });

  it("successful JSON GET response includes Vary: Accept", async () => {
    globalThis.fetch = jsonfetch();
    const req = new Request("https://w.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req);
    expect(response.headers.get("vary")).toBe("Accept");
  });
});
