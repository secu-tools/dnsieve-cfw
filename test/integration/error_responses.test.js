// test/integration/error_responses.test.js
// Integration tests for error response handling: CORS headers, error format,
// status codes, and security properties across all error paths.

import { describe, it, expect } from "vitest";
import { handleRequest } from "../../src/handler.js";
import { buildDnsQuery } from "../../src/dns.js";

function fakeCtx() {
  return { waitUntil: () => {} };
}

// ---------------------------------------------------------------------------
// All error responses must include CORS and proper formatting
// ---------------------------------------------------------------------------

describe("Error responses - consistent formatting", () => {
  const errorScenarios = [
    {
      name: "405 Method Not Allowed (PUT)",
      request: () => new Request("https://worker.example.com/dns-query?name=x&type=A", { method: "PUT" }),
      expectedStatus: 405,
    },
    {
      name: "405 Method Not Allowed (DELETE)",
      request: () => new Request("https://worker.example.com/dns-query?name=x&type=A", { method: "DELETE" }),
      expectedStatus: 405,
    },
    {
      name: "405 Method Not Allowed (PATCH)",
      request: () => new Request("https://worker.example.com/dns-query?name=x&type=A", { method: "PATCH" }),
      expectedStatus: 405,
    },
    {
      name: "415 Unsupported Media Type",
      request: () => new Request("https://worker.example.com/dns-query", {
        method: "POST",
        headers: { "Content-Type": "text/plain" },
        body: "not dns",
      }),
      expectedStatus: 415,
    },
    {
      name: "400 Invalid DoH request (no params)",
      request: () => new Request("https://worker.example.com/dns-query", { method: "GET" }),
      expectedStatus: 400,
    },
    {
      name: "413 Oversized POST body",
      request: () => {
        const big = new Uint8Array(65536);
        big[2] = 0x01; big[5] = 1;
        return new Request("https://worker.example.com/dns-query", {
          method: "POST",
          headers: { "Content-Type": "application/dns-message" },
          body: big,
        });
      },
      expectedStatus: 413,
    },
    {
      name: "400 POST body too short",
      request: () => new Request("https://worker.example.com/dns-query", {
        method: "POST",
        headers: { "Content-Type": "application/dns-message" },
        body: new Uint8Array(5),
      }),
      expectedStatus: 400,
    },
  ];

  for (const scenario of errorScenarios) {
    it(`${scenario.name}: returns ${scenario.expectedStatus}`, async () => {
      const resp = await handleRequest(scenario.request(), {}, fakeCtx());
      expect(resp.status).toBe(scenario.expectedStatus);
    });

    it(`${scenario.name}: includes CORS header`, async () => {
      const resp = await handleRequest(scenario.request(), {}, fakeCtx());
      expect(resp.headers.get("access-control-allow-origin")).toBe("*");
    });

    it(`${scenario.name}: includes Cache-Control: no-store`, async () => {
      const resp = await handleRequest(scenario.request(), {}, fakeCtx());
      expect(resp.headers.get("cache-control")).toBe("no-store");
    });
  }
});

// ---------------------------------------------------------------------------
// OPTIONS / CORS preflight
// ---------------------------------------------------------------------------

describe("CORS preflight responses", () => {
  it("OPTIONS returns proper CORS headers", async () => {
    const req = new Request("https://worker.example.com/dns-query", { method: "OPTIONS" });
    const resp = await handleRequest(req, {}, fakeCtx());
    expect(resp.status).toBe(200);
    expect(resp.headers.get("access-control-allow-origin")).toBe("*");
    expect(resp.headers.get("access-control-allow-methods")).toContain("GET");
    expect(resp.headers.get("access-control-allow-methods")).toContain("POST");
    expect(resp.headers.get("access-control-allow-methods")).toContain("OPTIONS");
    expect(resp.headers.get("access-control-allow-headers")).toContain("Content-Type");
    expect(resp.headers.get("access-control-max-age")).toBeTruthy();
  });
});

// ---------------------------------------------------------------------------
// All upstreams failed - RFC 8484 s4.2.1 SERVFAIL response
// ---------------------------------------------------------------------------

describe("All upstreams failed - RFC 8484 s4.2.1 SERVFAIL response", () => {
  it("returns HTTP 200 with SERVFAIL DNS body and CORS when all upstreams fail", async () => {
    const env = {
      UPSTREAM_SERVERS: JSON.stringify(["https://localhost:1/dns-query"]),
      UPSTREAM_TIMEOUT_MS: "100",
    };
    const query = buildDnsQuery("noexist.test", 1);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const resp = await handleRequest(req, env, fakeCtx());
    // RFC 8484 s4.2.1: DNS errors must use HTTP 200, not 502
    expect(resp.status).toBe(200);
    expect(resp.headers.get("access-control-allow-origin")).toBe("*");
    expect(resp.headers.get("content-type")).toContain("application/dns-message");
    expect(resp.headers.get("cache-control")).toBe("no-store");
    // Response wire bytes must carry rcode=2 (SERVFAIL)
    const buf = new Uint8Array(await resp.arrayBuffer());
    expect(buf.length).toBeGreaterThanOrEqual(4);
    expect(buf[3] & 0x0f).toBe(2);
  });

  it("SERVFAIL wire response includes Vary: Accept (RFC 8484 S4.2.1)", async () => {
    const env = {
      UPSTREAM_SERVERS: JSON.stringify(["https://localhost:1/dns-query"]),
      UPSTREAM_TIMEOUT_MS: "100",
    };
    const query = buildDnsQuery("noexist.test", 1);
    const req = new Request("https://worker.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const resp = await handleRequest(req, env, fakeCtx());
    expect(resp.status).toBe(200);
    expect(resp.headers.get("vary")).toBe("Accept");
  });

  it("SERVFAIL JSON response includes Vary: Accept (RFC 8484 S4.2.1)", async () => {
    const env = {
      UPSTREAM_SERVERS: JSON.stringify(["https://localhost:1/dns-query"]),
      UPSTREAM_TIMEOUT_MS: "100",
    };
    const req = new Request("https://worker.example.com/dns-query?name=noexist.test&type=A");
    const resp = await handleRequest(req, env, fakeCtx());
    expect(resp.status).toBe(200);
    expect(resp.headers.get("vary")).toBe("Accept");
  });
});
