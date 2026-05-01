// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/rfc/rfc4034_dnssec.test.js
// Tests for RFC 4034 / RFC 4035 DNSSEC compliance
//
// RFC 4034 Section 2.1  - DNSKEY resource record format
// RFC 4034 Section 3.1  - RRSIG resource record format
// RFC 4034 Section 4.1  - NSEC resource record format
// RFC 4034 Section 5.1  - DS resource record format
// RFC 4035 Section 3.1.4.1 - Security-aware name servers must NOT include
//   DNSSEC authentication RRs (RRSIG, NSEC, DNSKEY, NSEC3) in responses to
//   clients that did not set the DO bit, unless the RR type was explicitly
//   requested.
// RFC 4035 Section 3.2.1 - Resolver behaviour regarding the DO bit
//   The proxy always sets DO=1 in outgoing queries so the cache is always
//   populated with DNSSEC records.
// RFC 5155 Section 3.1  - NSEC3 resource record format
//
// DNSSEC caching behaviour tested:
//   - Upstream always receives DO=1 regardless of client DO bit
//   - Cache is populated with full DNSSEC-signed response
//   - Non-DO client receives response stripped of DNSSEC RRs
//   - DO client receives full response including DNSSEC RRs
//   - Explicitly queried DNSSEC type is never stripped (even for non-DO client)
//   - Wire POST, Wire GET, and JSON DoH GET paths all tested
//   - Cache hit path also strips DNSSEC for non-DO clients

import { describe, it, expect, vi, beforeEach, afterEach } from "vitest";
import { handleRequest } from "../../src/handler.js";
import {
  buildDnsQuery,
  buildDnsQueryWithDo,
  buildDnsResponse,
  hasDoBit,
  stripDnssecFromWire,
  stripDnssecFromJson,
  extractQueryNameType,
  DNS_TYPE_TO_NUMBER,
} from "../../src/dns.js";

// ---------------------------------------------------------------------------
// Helpers
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

// Build a minimal RRSIG record buffer (type 46, fixed-length signature).
// Returns a wire-format DNS response with an A record and an RRSIG in Answer.
function buildWireResponseWithRrsig(name, ip, ttl = 300) {
  // A record portion identical to buildDnsResponse
  const labels = name.replace(/\.$/, "").split(".");
  let namelen = 0;
  for (const l of labels) namelen += 1 + l.length;
  namelen += 1;

  // RRSIG RDATA (RFC 4034 Section 3.1):
  //   type covered (2) = A (0x00 0x01)
  //   algorithm (1)    = 8 (RSASHA256)
  //   labels (1)       = number of labels in name
  //   original TTL (4)
  //   sig expiration (4)
  //   sig inception (4)
  //   key tag (2)
  //   signer name      = root label (1 byte: 0x00)
  //   signature        = 8 bytes of placeholder data
  const labelCount = labels.length;
  const rrsigRdata = new Uint8Array([
    0x00, 0x01,              // type covered = A
    0x08,                    // algorithm = 8 (RSA/SHA-256)
    labelCount,              // labels
    0x00, 0x00, 0x01, 0x2c, // original TTL = 300
    0x60, 0x00, 0x00, 0x00, // sig expiration (placeholder)
    0x5f, 0x00, 0x00, 0x00, // sig inception (placeholder)
    0x12, 0x34,              // key tag
    0x00,                    // signer name = root label
    0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe, // 8-byte placeholder sig
  ]);

  const ipParts = ip.split(".");
  // Header(12) + qsection(namelen+4) + A_RR(2+10+4) + RRSIG_RR(2+10+rrsigRdata.length)
  const totalSize = 12 + namelen + 4
    + 2 + 10 + 4                         // A record (name pointer + fixed + rdata)
    + 2 + 10 + rrsigRdata.length;        // RRSIG (name pointer + fixed + rdata)
  const buf = new Uint8Array(totalSize);

  buf[2] = 0x81; // QR=1 RD=1
  buf[3] = 0x80; // RA=1 rcode=0
  buf[4] = 0x00; buf[5] = 0x01; // QDCOUNT=1
  buf[6] = 0x00; buf[7] = 0x02; // ANCOUNT=2 (A + RRSIG)

  let off = 12;
  for (const label of labels) {
    buf[off++] = label.length;
    for (let i = 0; i < label.length; i++) buf[off++] = label.charCodeAt(i);
  }
  buf[off++] = 0;
  buf[off++] = 0x00; buf[off++] = 0x01; // QTYPE A
  buf[off++] = 0x00; buf[off++] = 0x01; // QCLASS IN

  // A record
  buf[off++] = 0xc0; buf[off++] = 0x0c; // name pointer to question
  buf[off++] = 0x00; buf[off++] = 0x01; // TYPE A
  buf[off++] = 0x00; buf[off++] = 0x01; // CLASS IN
  buf[off++] = (ttl >> 24) & 0xff; buf[off++] = (ttl >> 16) & 0xff;
  buf[off++] = (ttl >>  8) & 0xff; buf[off++] = ttl & 0xff;
  buf[off++] = 0x00; buf[off++] = 0x04; // RDLENGTH 4
  buf[off++] = parseInt(ipParts[0], 10); buf[off++] = parseInt(ipParts[1], 10);
  buf[off++] = parseInt(ipParts[2], 10); buf[off++] = parseInt(ipParts[3], 10);

  // RRSIG record
  buf[off++] = 0xc0; buf[off++] = 0x0c; // name pointer
  buf[off++] = 0x00; buf[off++] = 0x2e; // TYPE RRSIG (46)
  buf[off++] = 0x00; buf[off++] = 0x01; // CLASS IN
  buf[off++] = (ttl >> 24) & 0xff; buf[off++] = (ttl >> 16) & 0xff;
  buf[off++] = (ttl >>  8) & 0xff; buf[off++] = ttl & 0xff;
  buf[off++] = (rrsigRdata.length >> 8) & 0xff;
  buf[off++] =  rrsigRdata.length       & 0xff;
  buf.set(rrsigRdata, off);

  return buf;
}

// Build a JSON DoH response containing an A record and an RRSIG record.
function buildJsonResponseWithRrsig(name, ip) {
  return {
    Status: 0,
    TC: false, RD: true, RA: true, AD: true, CD: false,
    Question: [{ name, type: 1 }],
    Answer: [
      { name, type: 1,  TTL: 300, data: ip },
      { name, type: 46, TTL: 300, data: "1 8 2 300 1610000000 1600000000 1234 . deadbeef=" },
    ],
  };
}

afterEach(() => { vi.restoreAllMocks(); });

// ---------------------------------------------------------------------------
// RFC 4035 Section 3.2.1 - Outgoing DO bit forcing
// ---------------------------------------------------------------------------

describe("RFC 4035 SS.3.2.1 - Upstream always receives DO=1", () => {
  it("wire POST: upstream receives DO=1 even when client sent DO=0 query", async () => {
    const capturedBodies = [];
    globalThis.fetch = vi.fn(async (url, opts) => {
      if (opts && opts.body) {
        capturedBodies.push(new Uint8Array(await new Response(opts.body).arrayBuffer()));
      }
      return new Response(buildDnsResponse("example.com.", "1.2.3.4", 300), {
        headers: { "Content-Type": "application/dns-message" },
      });
    });

    // Client query with DO=0 (no OPT record)
    const query = buildDnsQuery("example.com", 1);
    const req = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    await dispatch(req);

    expect(capturedBodies.length).toBeGreaterThan(0);
    for (const body of capturedBodies) {
      expect(hasDoBit(body)).toBe(true);
    }
  });

  it("wire POST: upstream still receives DO=1 when client explicitly sent DO=1", async () => {
    const capturedBodies = [];
    globalThis.fetch = vi.fn(async (url, opts) => {
      if (opts && opts.body) {
        capturedBodies.push(new Uint8Array(await new Response(opts.body).arrayBuffer()));
      }
      return new Response(buildDnsResponse("example.com.", "1.2.3.4", 300), {
        headers: { "Content-Type": "application/dns-message" },
      });
    });

    const query = buildDnsQueryWithDo("example.com", 1, 0, true);
    const req = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    await dispatch(req);

    expect(capturedBodies.length).toBeGreaterThan(0);
    for (const body of capturedBodies) {
      expect(hasDoBit(body)).toBe(true);
    }
  });

  it("JSON GET: upstream always receives do=1 query parameter", async () => {
    const capturedUrls = [];
    globalThis.fetch = vi.fn(async (url) => {
      capturedUrls.push(url);
      return new Response(JSON.stringify({ Status: 0, Answer: [] }), {
        headers: { "Content-Type": "application/dns-json" },
      });
    });

    // Client query without ?do=
    const req = new Request("https://w.example.com/dns-query?name=example.com&type=A");
    await dispatch(req);

    expect(capturedUrls.length).toBeGreaterThan(0);
    for (const u of capturedUrls) {
      const parsed = new URL(u);
      expect(parsed.searchParams.get("do")).toBe("1");
    }
  });

  it("JSON GET: upstream receives do=1 even when client explicitly sent do=1", async () => {
    const capturedUrls = [];
    globalThis.fetch = vi.fn(async (url) => {
      capturedUrls.push(url);
      return new Response(JSON.stringify({ Status: 0, Answer: [] }), {
        headers: { "Content-Type": "application/dns-json" },
      });
    });

    const req = new Request("https://w.example.com/dns-query?name=example.com&type=A&do=1");
    await dispatch(req);

    for (const u of capturedUrls) {
      const parsed = new URL(u);
      expect(parsed.searchParams.get("do")).toBe("1");
    }
  });
});

// ---------------------------------------------------------------------------
// RFC 4035 Section 3.1.4.1 - DNSSEC response stripping for non-DO clients
// ---------------------------------------------------------------------------

describe("RFC 4035 SS.3.1.4.1 - DNSSEC stripping for non-DO clients (wire POST)", () => {
  it("non-DO client does not receive RRSIG records in response", async () => {
    const wireWithDnssec = buildWireResponseWithRrsig("example.com.", "1.2.3.4");
    globalThis.fetch = vi.fn(async () => new Response(wireWithDnssec, {
      headers: { "Content-Type": "application/dns-message" },
    }));

    const query = buildDnsQuery("example.com", 1); // DO=0
    const req = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatch(req);
    const buf = new Uint8Array(await response.arrayBuffer());
    // ANCOUNT must be 1 (only the A record; RRSIG stripped)
    const ancount = (buf[6] << 8) | buf[7];
    expect(ancount).toBe(1);
  });

  it("DO client receives both A and RRSIG records in response", async () => {
    const wireWithDnssec = buildWireResponseWithRrsig("example.com.", "1.2.3.4");
    globalThis.fetch = vi.fn(async () => new Response(wireWithDnssec, {
      headers: { "Content-Type": "application/dns-message" },
    }));

    const query = buildDnsQueryWithDo("example.com", 1, 0, true); // DO=1
    const req = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    });
    const { response } = await dispatch(req);
    const buf = new Uint8Array(await response.arrayBuffer());
    // ANCOUNT must be 2 (A + RRSIG both kept for DO client)
    const ancount = (buf[6] << 8) | buf[7];
    expect(ancount).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// RFC 4035 Section 3.1.4.1 - JSON path
// ---------------------------------------------------------------------------

describe("RFC 4035 SS.3.1.4.1 - DNSSEC stripping for non-DO clients (JSON GET)", () => {
  it("non-DO client does not receive RRSIG in JSON response", async () => {
    const jsonResp = buildJsonResponseWithRrsig("example.com.", "1.2.3.4");
    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify(jsonResp), {
      headers: { "Content-Type": "application/dns-json" },
    }));

    // JSON GET without ?do= -> DO=0
    const req = new Request("https://w.example.com/dns-query?name=example.com&type=A");
    const { response } = await dispatch(req);
    const body = await response.json();

    const types = (body.Answer || []).map(rr => rr.type);
    expect(types).not.toContain(46); // RRSIG must be stripped
    expect(types).toContain(1);      // A record must remain
  });

  it("DO client receives RRSIG in JSON response (?do=1)", async () => {
    const jsonResp = buildJsonResponseWithRrsig("example.com.", "1.2.3.4");
    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify(jsonResp), {
      headers: { "Content-Type": "application/dns-json" },
    }));

    const req = new Request("https://w.example.com/dns-query?name=example.com&type=A&do=1");
    const { response } = await dispatch(req);
    const body = await response.json();

    const types = (body.Answer || []).map(rr => rr.type);
    expect(types).toContain(46); // RRSIG kept for DO client
    expect(types).toContain(1);
  });
});

// ---------------------------------------------------------------------------
// RFC 4035 - DNSSEC type explicitly queried: exception to the stripping rule
// ---------------------------------------------------------------------------

describe("RFC 4035 - Explicitly queried DNSSEC type is not stripped", () => {
  it("non-DO client requesting type=RRSIG receives RRSIG in Answer", async () => {
    const jsonResp = {
      Status: 0,
      Question: [{ name: "example.com.", type: 46 }],
      Answer: [
        { name: "example.com.", type: 46, TTL: 300, data: "1 8 2 300 1610000000 1600000000 1234 . deadbeef=" },
      ],
    };
    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify(jsonResp), {
      headers: { "Content-Type": "application/dns-json" },
    }));

    // Client requests RRSIG directly but does not set DO bit (do= absent)
    const req = new Request("https://w.example.com/dns-query?name=example.com&type=RRSIG");
    const { response } = await dispatch(req);
    const body = await response.json();

    const types = (body.Answer || []).map(rr => rr.type);
    expect(types).toContain(46); // RRSIG kept because it was explicitly queried
  });

  it("non-DO client requesting type=DNSKEY receives DNSKEY in Answer", async () => {
    const jsonResp = {
      Status: 0,
      Question: [{ name: "example.com.", type: 48 }],
      Answer: [
        { name: "example.com.", type: 48, TTL: 300, data: "257 3 8 BASE64KEY==" },
      ],
    };
    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify(jsonResp), {
      headers: { "Content-Type": "application/dns-json" },
    }));

    const req = new Request("https://w.example.com/dns-query?name=example.com&type=DNSKEY");
    const { response } = await dispatch(req);
    const body = await response.json();

    const types = (body.Answer || []).map(rr => rr.type);
    expect(types).toContain(48); // DNSKEY kept because explicitly queried
  });
});

// ---------------------------------------------------------------------------
// DNSSEC + cache interaction
// ---------------------------------------------------------------------------

describe("DNSSEC cache: full signed response cached; non-DO client gets stripped", () => {
  it("cache stores the full RRSIG-bearing response", async () => {
    const wireWithDnssec = buildWireResponseWithRrsig("example.com.", "1.2.3.4");
    globalThis.fetch = vi.fn(async () => new Response(wireWithDnssec, {
      headers: { "Content-Type": "application/dns-message" },
    }));

    const fakeCache = makeFakeCache();
    // First request: DO=1 client populates the cache
    const queryDo = buildDnsQueryWithDo("example.com", 1, 0, true);
    const req = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: queryDo,
    });
    await dispatch(req, fakeCache);

    // The cached response must retain the RRSIG (ANCOUNT=2)
    const entries = [...fakeCache.store.values()];
    expect(entries.length).toBeGreaterThan(0);
    const cachedBuf = new Uint8Array(await entries[0].clone().arrayBuffer());
    const cachedAncount = (cachedBuf[6] << 8) | cachedBuf[7];
    expect(cachedAncount).toBe(2); // A + RRSIG cached
  });

  it("non-DO client hitting warm cache receives RRSIG-stripped response", async () => {
    const wireWithDnssec = buildWireResponseWithRrsig("example.com.", "1.2.3.4");

    // Populate cache with a signed response directly (simulates prior DO=1 request)
    const fakeCache = makeFakeCache();

    // First DO=1 request to populate cache
    globalThis.fetch = vi.fn(async () => new Response(wireWithDnssec, {
      headers: { "Content-Type": "application/dns-message" },
    }));
    const queryDo = buildDnsQueryWithDo("example.com", 1, 0, true);
    await dispatch(new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: queryDo,
    }), fakeCache);

    // Second request: non-DO client, should hit cache and receive stripped response
    vi.restoreAllMocks();
    const queryNoDo = buildDnsQuery("example.com", 1); // DO=0
    const req2 = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: queryNoDo,
    });
    const { response } = await dispatch(req2, fakeCache);
    const buf = new Uint8Array(await response.arrayBuffer());
    const ancount = (buf[6] << 8) | buf[7];
    expect(ancount).toBe(1); // Only A record; RRSIG stripped for non-DO client
  });

  it("DO client hitting warm cache receives full RRSIG-bearing response", async () => {
    const wireWithDnssec = buildWireResponseWithRrsig("example.com.", "1.2.3.4");
    const fakeCache = makeFakeCache();

    // Populate cache
    globalThis.fetch = vi.fn(async () => new Response(wireWithDnssec, {
      headers: { "Content-Type": "application/dns-message" },
    }));
    const queryDo = buildDnsQueryWithDo("example.com", 1, 0, true);
    await dispatch(new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: queryDo,
    }), fakeCache);

    // DO=1 client hits warm cache
    vi.restoreAllMocks();
    const req2 = new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: buildDnsQueryWithDo("example.com", 1, 0, true),
    });
    const { response } = await dispatch(req2, fakeCache);
    const buf = new Uint8Array(await response.arrayBuffer());
    const ancount = (buf[6] << 8) | buf[7];
    expect(ancount).toBe(2); // Full response for DO client
  });

  it("wire GET and wire POST same query share the same cache key", async () => {
    const wireResp = buildDnsResponse("example.com.", "1.2.3.4", 300);
    let fetchCount = 0;
    globalThis.fetch = vi.fn(async () => {
      fetchCount++;
      return new Response(wireResp, { headers: { "Content-Type": "application/dns-message" } });
    });

    const fakeCache = makeFakeCache();
    const query = buildDnsQuery("example.com", 1);

    // Wire POST
    await dispatch(new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    }), fakeCache);

    const prevFetchCount = fetchCount;

    // Wire GET for same query - should hit the cache populated by POST
    const b64 = btoa(String.fromCharCode(...query))
      .replace(/\+/g, "-").replace(/\//g, "_").replace(/=/g, "");
    await dispatch(
      new Request(`https://w.example.com/dns-query?dns=${b64}`),
      fakeCache
    );

    // fetchCount should not have increased if cache was hit
    expect(fetchCount).toBe(prevFetchCount);
  });

  it("JSON GET and wire POST same query share the same cache key", async () => {
    const wireResp = buildDnsResponse("example.com.", "1.2.3.4", 300);
    let fetchCount = 0;
    globalThis.fetch = vi.fn(async () => {
      fetchCount++;
      return new Response(wireResp, { headers: { "Content-Type": "application/dns-message" } });
    });

    const fakeCache = makeFakeCache();
    const query = buildDnsQuery("example.com", 1);

    // Wire POST first to populate cache
    await dispatch(new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: query,
    }), fakeCache);

    const prevFetchCount = fetchCount;

    // JSON GET for same name/type should hit the same cache entry
    await dispatch(
      new Request("https://w.example.com/dns-query?name=example.com&type=A"),
      fakeCache
    );

    expect(fetchCount).toBe(prevFetchCount);
  });
});

// ---------------------------------------------------------------------------
// Unit: stripDnssecFromWire
// ---------------------------------------------------------------------------

describe("stripDnssecFromWire", () => {
  it("returns original buffer when no DNSSEC RRs present", () => {
    const buf = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const out = stripDnssecFromWire(buf, 1);
    expect(out).toBe(buf);
  });

  it("removes RRSIG (type 46) from Answer for non-DO query", () => {
    const buf = buildWireResponseWithRrsig("example.com.", "1.2.3.4");
    const anBefore = (buf[6] << 8) | buf[7];
    expect(anBefore).toBe(2); // A + RRSIG
    const out = stripDnssecFromWire(buf, 1); // queryQtype = A
    const anAfter = (out[6] << 8) | out[7];
    expect(anAfter).toBe(1); // Only A
  });

  it("keeps RRSIG (type 46) when RRSIG is the explicitly queried type", () => {
    const buf = buildWireResponseWithRrsig("example.com.", "1.2.3.4");
    const out = stripDnssecFromWire(buf, 46); // queryQtype = RRSIG
    const anAfter = (out[6] << 8) | out[7];
    expect(anAfter).toBe(2); // Both A and RRSIG kept
  });

  it("returns original buffer unchanged for short input", () => {
    const buf = new Uint8Array(4);
    expect(stripDnssecFromWire(buf, 1)).toBe(buf);
  });
});

// ---------------------------------------------------------------------------
// Unit: stripDnssecFromJson
// ---------------------------------------------------------------------------

describe("stripDnssecFromJson", () => {
  it("returns original object when no DNSSEC RRs present", () => {
    const json = { Status: 0, Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "1.2.3.4" }] };
    const out = stripDnssecFromJson(json, 1);
    expect(out).toBe(json); // same reference
  });

  it("removes RRSIG (type 46) from Answer when queryQtype != 46", () => {
    const json = buildJsonResponseWithRrsig("example.com.", "1.2.3.4");
    const out = stripDnssecFromJson(json, 1); // queryQtype A
    const types = out.Answer.map(rr => rr.type);
    expect(types).not.toContain(46);
    expect(types).toContain(1);
  });

  it("keeps RRSIG (type 46) when RRSIG is explicitly queried", () => {
    const json = buildJsonResponseWithRrsig("example.com.", "1.2.3.4");
    const out = stripDnssecFromJson(json, 46); // queryQtype RRSIG
    const types = out.Answer.map(rr => rr.type);
    expect(types).toContain(46);
  });

  it("removes NSEC (type 47) from Authority section unconditionally", () => {
    const json = {
      Status: 0,
      Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "1.2.3.4" }],
      Authority: [
        { name: "example.com.", type: 6,  TTL: 900, data: "ns1. hostmaster. 1 3600 900 604800 300" },
        { name: "example.com.", type: 47, TTL: 300, data: "example2.com. A NS" },
      ],
    };
    const out = stripDnssecFromJson(json, 1);
    const authTypes = (out.Authority || []).map(rr => rr.type);
    expect(authTypes).not.toContain(47); // NSEC stripped from Authority
    expect(authTypes).toContain(6);      // SOA kept
  });

  it("removes DNSKEY (type 48) and NSEC3 (type 50) from Answer for non-DO queries", () => {
    const json = {
      Status: 0,
      Answer: [
        { name: "example.com.", type: 1,  TTL: 300, data: "1.2.3.4" },
        { name: "example.com.", type: 48, TTL: 3600, data: "257 3 8 BASE64KEY" },
        { name: "example.com.", type: 50, TTL: 300, data: "1 0 10 - AABB A" },
      ],
    };
    const out = stripDnssecFromJson(json, 1);
    const types = out.Answer.map(rr => rr.type);
    expect(types).not.toContain(48); // DNSKEY stripped
    expect(types).not.toContain(50); // NSEC3 stripped
    expect(types).toContain(1);      // A kept
  });

  it("does not mutate original json object", () => {
    const json = buildJsonResponseWithRrsig("example.com.", "1.2.3.4");
    const origLength = json.Answer.length;
    stripDnssecFromJson(json, 1);
    expect(json.Answer.length).toBe(origLength); // original unchanged
  });
});

// ---------------------------------------------------------------------------
// Unit: hasDoBit
// ---------------------------------------------------------------------------

describe("hasDoBit", () => {
  it("returns false for null input", () => {
    expect(hasDoBit(null)).toBe(false);
  });

  it("returns false for short buffer", () => {
    expect(hasDoBit(new Uint8Array(4))).toBe(false);
  });

  it("returns false for query without OPT record", () => {
    const buf = buildDnsQuery("example.com", 1);
    expect(hasDoBit(buf)).toBe(false);
  });

  it("returns false for query with OPT but DO=0", () => {
    const buf = buildDnsQueryWithDo("example.com", 1, 0, false);
    expect(hasDoBit(buf)).toBe(false);
  });

  it("returns true for query with OPT and DO=1", () => {
    const buf = buildDnsQueryWithDo("example.com", 1, 0, true);
    expect(hasDoBit(buf)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Unit: extractQueryNameType
// ---------------------------------------------------------------------------

describe("extractQueryNameType", () => {
  it("returns null for null input", () => {
    expect(extractQueryNameType(null)).toBeNull();
  });

  it("returns null for buffer shorter than 12 bytes", () => {
    expect(extractQueryNameType(new Uint8Array(4))).toBeNull();
  });

  it("extracts name and type from a standard A query", () => {
    const buf = buildDnsQuery("example.com", 1);
    const result = extractQueryNameType(buf);
    expect(result).not.toBeNull();
    expect(result.name).toBe("example.com.");
    expect(result.qtype).toBe(1);
  });

  it("extracts name and type from an AAAA query", () => {
    const buf = buildDnsQuery("ipv6.example.com", 28);
    const result = extractQueryNameType(buf);
    expect(result).not.toBeNull();
    expect(result.name).toBe("ipv6.example.com.");
    expect(result.qtype).toBe(28);
  });

  it("returns null when QDCOUNT=0", () => {
    const buf = buildDnsQuery("example.com", 1);
    buf[4] = 0; buf[5] = 0; // QDCOUNT=0
    expect(extractQueryNameType(buf)).toBeNull();
  });
});
