// test/integration/wire_get_blocked.test.js
// Integration tests: wire GET requests for blocked domains MUST use the
// configured BLOCKING_MODE to generate a local response instead of falling
// back to the upstream response as-is.
//
// Also covers RFC 8484 S.4.1 validation: malformed or too-short ?dns= values
// MUST return HTTP 400.

import { describe, it, expect, vi, afterEach } from "vitest";
import { handleRequest } from "../../src/handler.js";
import {
  buildDnsQuery,
  buildDnsResponse,
  buildBlockedResponse,
  wireToJson,
  inspectWireResponse,
  hasDoBit,
} from "../../src/dns.js";

// ---------------------------------------------------------------------------
// Shared helpers (mirror worker.test.js pattern)
// ---------------------------------------------------------------------------

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

async function dispatch(request, fakeCache) {
  return dispatchWithEnv(request, {}, fakeCache);
}

// Encode a Uint8Array as base64url (no padding).
function toBase64url(buf) {
  let b = "";
  for (let i = 0; i < buf.length; i++) b += String.fromCharCode(buf[i]);
  return btoa(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Build an upstream fetch mock that returns a blocked-looking wire response.
function makeBlockedWireFetch(domain, rcode = 0, ip = "0.0.0.0") {
  const body = rcode === 3
    ? buildDnsResponse(domain + ".", ip, 0, 3) // NXDOMAIN, nscount=0
    : buildDnsResponse(domain + ".", ip, 0);   // NOERROR with 0.0.0.0
  return vi.fn(async () => new Response(body, {
    headers: { "Content-Type": "application/dns-message" },
  }));
}

afterEach(() => { vi.restoreAllMocks(); });

// ---------------------------------------------------------------------------
// RFC 8484 S.4.1 - malformed / too-short wire GET must return 400
// ---------------------------------------------------------------------------

describe("RFC 8484 S.4.1 - wire GET validation (400 responses)", () => {
  it("returns 400 for invalid base64url characters in ?dns=", async () => {
    const req = new Request("https://w.example.com/dns-query?dns=!!!invalid!!!");
    const { response } = await dispatch(req);
    expect(response.status).toBe(400);
  });

  it("returns 400 for ?dns= that decodes to 0 bytes", async () => {
    // btoa("") encodes to empty string but that is valid base64 for 0 bytes
    const req = new Request("https://w.example.com/dns-query?dns=");
    const { response } = await dispatch(req);
    expect(response.status).toBe(400);
  });

  it("returns 400 for ?dns= that decodes to fewer than 12 bytes", async () => {
    const shortBuf = new Uint8Array(5);
    const req = new Request(`https://w.example.com/dns-query?dns=${toBase64url(shortBuf)}`);
    const { response } = await dispatch(req);
    expect(response.status).toBe(400);
  });

  it("returns 400 for ?dns= that decodes to exactly 11 bytes (one short of minimum)", async () => {
    const buf = new Uint8Array(11);
    const req = new Request(`https://w.example.com/dns-query?dns=${toBase64url(buf)}`);
    const { response } = await dispatch(req);
    expect(response.status).toBe(400);
  });

  it("returns 200 for a valid wire GET with exactly a 12-byte header", async () => {
    // 12-byte buffer with QDCOUNT=0 is technically valid (no question section).
    // The upstream will decide, so mock it.
    globalThis.fetch = vi.fn(async () =>
      new Response(buildDnsResponse("example.com.", "1.2.3.4", 60), {
        headers: { "Content-Type": "application/dns-message" },
      })
    );
    const buf = new Uint8Array(12); // all-zero 12-byte header
    const req = new Request(`https://w.example.com/dns-query?dns=${toBase64url(buf)}`);
    const { response } = await dispatch(req);
    expect(response.status).toBe(200);
  });

  it("returns 400 Content-Type text/plain for invalid base64url", async () => {
    const req = new Request("https://w.example.com/dns-query?dns=%25%25%25");
    const { response } = await dispatch(req);
    expect(response.status).toBe(400);
    expect(response.headers.get("content-type")).toContain("text/plain");
  });
});

// ---------------------------------------------------------------------------
// Wire GET blocked: BLOCKING_MODE is applied (not upstream passthrough)
// ---------------------------------------------------------------------------

describe("Wire GET blocked - null mode produces local 0.0.0.0 response", () => {
  it("A query: response has NOERROR + A=0.0.0.0", async () => {
    globalThis.fetch = makeBlockedWireFetch("blocked.example.com");

    const query = buildDnsQuery("blocked.example.com", 1);
    const req = new Request(`https://w.example.com/dns-query?dns=${toBase64url(query)}`);
    const { response } = await dispatchWithEnv(req, { BLOCKING_MODE: "null" });

    expect(response.status).toBe(200);
    const buf = new Uint8Array(await response.arrayBuffer());
    const json = wireToJson(buf);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(0);
    expect(Array.isArray(json.Answer)).toBe(true);
    expect(json.Answer[0].data).toBe("0.0.0.0");
    expect(json.Answer[0].type).toBe(1);
  });

  it("AAAA query: response has NOERROR + AAAA=::", async () => {
    const blockedAaaa = buildDnsResponse("blocked.example.com.", "0.0.0.0", 0);
    globalThis.fetch = vi.fn(async () =>
      new Response(blockedAaaa, { headers: { "Content-Type": "application/dns-message" } })
    );

    const query = buildDnsQuery("blocked.example.com", 28);
    const req = new Request(`https://w.example.com/dns-query?dns=${toBase64url(query)}`);
    const { response } = await dispatchWithEnv(req, { BLOCKING_MODE: "null" });

    const buf = new Uint8Array(await response.arrayBuffer());
    const json = wireToJson(buf);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(0);
    expect(Array.isArray(json.Answer)).toBe(true);
    // AAAA null record: all zeros (::)
    expect(json.Answer[0].type).toBe(28);
  });

  it("X-Blocked header is true", async () => {
    globalThis.fetch = makeBlockedWireFetch("blocked.example.com");
    const query = buildDnsQuery("blocked.example.com", 1);
    const req = new Request(`https://w.example.com/dns-query?dns=${toBase64url(query)}`);
    const { response } = await dispatchWithEnv(req, { BLOCKING_MODE: "null" });
    expect(response.headers.get("x-blocked")).toBe("true");
  });
});

describe("Wire GET blocked - nxdomain mode", () => {
  it("produces NXDOMAIN (rcode=3) response", async () => {
    // Use a zero-IP response that gets detected as blocked
    globalThis.fetch = makeBlockedWireFetch("blocked.example.com");
    const query = buildDnsQuery("blocked.example.com", 1);
    const req = new Request(`https://w.example.com/dns-query?dns=${toBase64url(query)}`);
    const { response } = await dispatchWithEnv(req, { BLOCKING_MODE: "nxdomain" });

    const buf = new Uint8Array(await response.arrayBuffer());
    const json = wireToJson(buf);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(3); // NXDOMAIN
    expect(json.Answer).toBeUndefined();
  });
});

describe("Wire GET blocked - nodata mode", () => {
  it("produces NOERROR with empty answer section", async () => {
    globalThis.fetch = makeBlockedWireFetch("blocked.example.com");
    const query = buildDnsQuery("blocked.example.com", 1);
    const req = new Request(`https://w.example.com/dns-query?dns=${toBase64url(query)}`);
    const { response } = await dispatchWithEnv(req, { BLOCKING_MODE: "nodata" });

    const buf = new Uint8Array(await response.arrayBuffer());
    const json = wireToJson(buf);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(0);
    expect(json.Answer).toBeUndefined();
  });
});

describe("Wire GET blocked - refused mode", () => {
  it("produces REFUSED (rcode=5) response", async () => {
    globalThis.fetch = makeBlockedWireFetch("blocked.example.com");
    const query = buildDnsQuery("blocked.example.com", 1);
    const req = new Request(`https://w.example.com/dns-query?dns=${toBase64url(query)}`);
    const { response } = await dispatchWithEnv(req, { BLOCKING_MODE: "refused" });

    const buf = new Uint8Array(await response.arrayBuffer());
    const json = wireToJson(buf);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(5); // REFUSED
  });
});

describe("Wire GET blocked - EDE is included in wire response", () => {
  it("blocked wire GET response has ARCOUNT >= 1 (OPT with EDE)", async () => {
    globalThis.fetch = makeBlockedWireFetch("blocked.example.com");
    const query = buildDnsQuery("blocked.example.com", 1);
    const req = new Request(`https://w.example.com/dns-query?dns=${toBase64url(query)}`);
    const { response } = await dispatchWithEnv(req, { BLOCKING_MODE: "null" });

    const buf = new Uint8Array(await response.arrayBuffer());
    const arcount = (buf[10] << 8) | buf[11];
    // EDE option is added in an OPT record; ARCOUNT must be at least 1
    expect(arcount).toBeGreaterThanOrEqual(1);
  });
});

describe("Wire GET blocked - response uses content-type dns-message", () => {
  it("Content-Type is application/dns-message for wire GET blocked", async () => {
    globalThis.fetch = makeBlockedWireFetch("blocked.example.com");
    const query = buildDnsQuery("blocked.example.com", 1);
    const req = new Request(`https://w.example.com/dns-query?dns=${toBase64url(query)}`);
    const { response } = await dispatchWithEnv(req, { BLOCKING_MODE: "null" });
    expect(response.headers.get("content-type")).toContain("application/dns-message");
  });
});

// ---------------------------------------------------------------------------
// RFC 6891 S.6.1.4 - DO bit cleared in response for non-DO clients
// ---------------------------------------------------------------------------

describe("RFC 6891 - DO bit cleared in wire response for non-DO clients", () => {
  it("non-DO client receives response with DO=0 in OPT", async () => {
    const wireResp = buildDnsResponse("example.com.", "1.2.3.4", 300);
    globalThis.fetch = vi.fn(async () =>
      new Response(wireResp, { headers: { "Content-Type": "application/dns-message" } })
    );

    // Query WITHOUT DO bit
    const query = buildDnsQuery("example.com", 1);
    expect(hasDoBit(query)).toBe(false);

    const req = new Request(`https://w.example.com/dns-query?dns=${toBase64url(query)}`);
    const { response } = await dispatch(req);

    expect(response.status).toBe(200);
    const buf = new Uint8Array(await response.arrayBuffer());
    // The response OPT record (if any) must have DO=0 for non-DO clients
    expect(hasDoBit(buf)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// RFC 4035 S.3.1.6 - CD bit propagation in JSON DoH blocked/SERVFAIL responses
// ---------------------------------------------------------------------------

describe("RFC 4035 S.3.1.6 - CD flag propagation in JSON blocked responses", () => {
  it("JSON blocked response has CD=false when ?cd= is absent", async () => {
    // Return a blocked-looking JSON response from the upstream
    globalThis.fetch = vi.fn(async () =>
      new Response(JSON.stringify({
        Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false,
        Question: [{ name: "blocked.example.com.", type: 1 }],
        Answer: [{ name: "blocked.example.com.", type: 1, TTL: 0, data: "0.0.0.0" }],
      }), { headers: { "Content-Type": "application/dns-json" } })
    );
    const req = new Request("https://w.example.com/dns-query?name=blocked.example.com&type=A");
    const { response } = await dispatchWithEnv(req, { BLOCKING_MODE: "null" });
    const json = await response.json();
    expect(json.CD).toBe(false);
  });

  it("JSON blocked response has CD=true when ?cd=1 is set", async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response(JSON.stringify({
        Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false,
        Question: [{ name: "blocked.example.com.", type: 1 }],
        Answer: [{ name: "blocked.example.com.", type: 1, TTL: 0, data: "0.0.0.0" }],
      }), { headers: { "Content-Type": "application/dns-json" } })
    );
    const req = new Request("https://w.example.com/dns-query?name=blocked.example.com&type=A&cd=1");
    const { response } = await dispatchWithEnv(req, { BLOCKING_MODE: "null" });
    const json = await response.json();
    expect(json.CD).toBe(true);
  });

  it("JSON blocked nxdomain response mirrors CD=true from ?cd=1", async () => {
    globalThis.fetch = vi.fn(async () =>
      new Response(JSON.stringify({
        Status: 3, TC: false, RD: true, RA: true, AD: false, CD: false,
        Question: [{ name: "blocked.example.com.", type: 1 }],
      }), { headers: { "Content-Type": "application/dns-json" } })
    );
    const req = new Request("https://w.example.com/dns-query?name=blocked.example.com&type=A&cd=1");
    const { response } = await dispatchWithEnv(req, { BLOCKING_MODE: "nxdomain" });
    const json = await response.json();
    expect(json.CD).toBe(true);
    expect(json.Status).toBe(3);
  });
});
