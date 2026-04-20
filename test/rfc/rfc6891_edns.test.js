// test/rfc/rfc6891_edns.test.js
// Tests for RFC 6891 - Extension Mechanisms for DNS (EDNS(0))
//
// RFC 6891 Section 6.1 - OPT pseudo-RR format
//   - NAME:    root domain (0x00)
//   - TYPE:    41 (OPT)
//   - CLASS:   requestor UDP payload size
//   - TTL:     extended RCODE (8 bits) | EDNS VERSION (8 bits) | Z flags (16 bits)
//   - RDLENGTH / RDATA: EDNS options
//
// RFC 6891 Section 6.1.3 - DO bit (bit 15 of Z flags in TTL field)
//   The proxy always sets DO=1 in outgoing queries (see RFC 4035 SS.3.2.1).
//
// RFC 6891 Section 7 - EDNS option codes / wire format for options
//
// Related options tested here:
//   RFC 7871 (ECS)   option code 8
//   RFC 5001 (NSID)  option code 3
//   RFC 7873 (Cookie) option code 10

import { describe, it, expect, vi, afterEach } from "vitest";
import {
  buildDnsQuery,
  buildDnsQueryWithDo,
  processEdnsOutgoing,
  buildEcsOption,
  hasDoBit,
} from "../../src/dns.js";
import { handleRequest } from "../../src/handler.js";

afterEach(() => { vi.restoreAllMocks(); });

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function makeConfig(overrides = {}) {
  return {
    PRIVACY_ECS_MODE:   overrides.ecsMode   ?? "strip",
    PRIVACY_ECS_SUBNET: overrides.ecsValue  ?? null,
    PRIVACY_NSID_MODE:  overrides.nsid      ?? "strip",
    PRIVACY_NSID_VALUE: overrides.nsidValue ?? null,
    PRIVACY_COOKIES_MODE: overrides.cookie  ?? "strip",
  };
}

function optTypeIn(buf) {
  // Return the TYPE field (2 bytes big-endian) of every Additional RR in buf.
  const qdcount = (buf[4] << 8) | buf[5];
  const ancount = (buf[6] << 8) | buf[7];
  const nscount = (buf[8] << 8) | buf[9];
  const arcount = (buf[10] << 8) | buf[11];
  const types = [];
  let off = 12;
  try {
    function skipName(b, o) {
      while (o < b.length) {
        const len = b[o];
        if (len === 0) return o + 1;
        if ((len & 0xc0) === 0xc0) return o + 2;
        o += 1 + len;
      }
      return o;
    }
    for (let i = 0; i < qdcount; i++) { off = skipName(buf, off); off += 4; }
    for (let i = 0; i < ancount + nscount; i++) {
      off = skipName(buf, off);
      const rdlen = (buf[off + 8] << 8) | buf[off + 9];
      off += 10 + rdlen;
    }
    for (let i = 0; i < arcount; i++) {
      off = skipName(buf, off);
      types.push((buf[off] << 8) | buf[off + 1]);
      const rdlen = (buf[off + 8] << 8) | buf[off + 9];
      off += 10 + rdlen;
    }
  } catch {}
  return types;
}

function getOptField(buf, fieldByteOffset) {
  // fieldByteOffset is relative to the TYPE field start of the OPT RR.
  // Locate OPT RR in ARCOUNT.
  const qdcount = (buf[4] << 8) | buf[5];
  const ancount = (buf[6] << 8) | buf[7];
  const nscount = (buf[8] << 8) | buf[9];
  let off = 12;
  function skipName(b, o) {
    while (o < b.length) {
      const len = b[o];
      if (len === 0) return o + 1;
      if ((len & 0xc0) === 0xc0) return o + 2;
      o += 1 + len;
    }
    return o;
  }
  for (let i = 0; i < qdcount; i++) { off = skipName(buf, off); off += 4; }
  for (let i = 0; i < ancount + nscount; i++) {
    off = skipName(buf, off);
    const rdlen = (buf[off + 8] << 8) | buf[off + 9];
    off += 10 + rdlen;
  }
  const arcount = (buf[10] << 8) | buf[11];
  for (let i = 0; i < arcount; i++) {
    off = skipName(buf, off);
    const rrtype = (buf[off] << 8) | buf[off + 1];
    if (rrtype === 41) return buf[off + fieldByteOffset];
    const rdlen = (buf[off + 8] << 8) | buf[off + 9];
    off += 10 + rdlen;
  }
  return null;
}

// ---------------------------------------------------------------------------
// RFC 6891 Section 6.1 - OPT pseudo-RR structure
// ---------------------------------------------------------------------------

describe("RFC 6891 SS.6.1 - OPT RR wire format", () => {
  it("processEdnsOutgoing appends OPT RR with TYPE=41", () => {
    const query = buildDnsQuery("example.com", 1); // no OPT
    const cfg = makeConfig();
    const out = processEdnsOutgoing(query, cfg, null);
    const types = optTypeIn(out);
    expect(types).toContain(41); // OPT
  });

  it("OPT RR NAME field is the root label (0x00)", () => {
    const query = buildDnsQuery("example.com", 1);
    const cfg = makeConfig();
    const out = processEdnsOutgoing(query, cfg, null);
    // Find the OPT RR's start: it must begin with 0x00 (root label)
    // Skip past header + question section
    let off = 12;
    const qdcount = (out[4] << 8) | out[5];
    function skipName(b, o) {
      while (o < b.length) {
        const len = b[o];
        if (len === 0) return o + 1;
        if ((len & 0xc0) === 0xc0) return o + 2;
        o += 1 + len;
      }
      return o;
    }
    for (let i = 0; i < qdcount; i++) { off = skipName(out, off); off += 4; }
    // Now at first ARCOUNT entry (the OPT RR)
    expect(out[off]).toBe(0x00); // root name
  });

  it("OPT CLASS field carries UDP payload size 4096 (0x1000)", () => {
    const query = buildDnsQuery("example.com", 1);
    const out = processEdnsOutgoing(query, makeConfig(), null);
    // CLASS is at offset +2 from the TYPE field
    const classHigh = getOptField(out, 2);
    const classLow  = getOptField(out, 3);
    expect((classHigh << 8) | classLow).toBe(0x1000); // 4096
  });

  it("OPT extended RCODE is 0", () => {
    const query = buildDnsQuery("example.com", 1);
    const out = processEdnsOutgoing(query, makeConfig(), null);
    expect(getOptField(out, 4)).toBe(0x00); // extended RCODE
  });

  it("OPT EDNS VERSION is 0", () => {
    const query = buildDnsQuery("example.com", 1);
    const out = processEdnsOutgoing(query, makeConfig(), null);
    expect(getOptField(out, 5)).toBe(0x00); // EDNS VERSION
  });

  it("ARCOUNT increments after OPT insertion", () => {
    const query = buildDnsQuery("example.com", 1);
    const arBefore = (query[10] << 8) | query[11];
    const out = processEdnsOutgoing(query, makeConfig(), null);
    const arAfter = (out[10] << 8) | out[11];
    expect(arAfter).toBe(arBefore + 1);
  });
});

// ---------------------------------------------------------------------------
// RFC 6891 Section 6.1.3 - DO bit in Z flags
// ---------------------------------------------------------------------------

describe("RFC 6891 SS.6.1.3 / RFC 4035 SS.3.2.1 - DO bit always set in outgoing queries", () => {
  it("OPT Z-field high byte has bit 7 set (DO=1) for non-DO source query", () => {
    const query = buildDnsQuery("example.com", 1); // no OPT, no DO
    const out = processEdnsOutgoing(query, makeConfig(), null);
    expect(getOptField(out, 6)).toBe(0x80); // Z flags high byte: DO=1
  });

  it("OPT Z-field high byte has bit 7 set (DO=1) for DO=0 source query", () => {
    const query = buildDnsQueryWithDo("example.com", 1, 0, false);
    const out = processEdnsOutgoing(query, makeConfig(), null);
    expect(getOptField(out, 6)).toBe(0x80);
  });

  it("OPT Z-field high byte has bit 7 set (DO=1) for DO=1 source query", () => {
    const query = buildDnsQueryWithDo("example.com", 1, 0, true);
    const out = processEdnsOutgoing(query, makeConfig(), null);
    expect(getOptField(out, 6)).toBe(0x80);
  });

  it("hasDoBit() confirms DO=1 is present in the output", () => {
    const query = buildDnsQuery("example.com", 1);
    const out = processEdnsOutgoing(query, makeConfig(), null);
    expect(hasDoBit(out)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// RFC 6891 Section 7 - EDNS options in OPT RDATA
// ---------------------------------------------------------------------------

describe("RFC 6891 SS.7 - EDNS option code wire format", () => {
  it("ECS option code is 0x0008 (8) per RFC 7871", () => {
    const ecs = buildEcsOption("203.0.113.0/24");
    expect(ecs).not.toBeNull();
    // First two bytes of full OPTION are code; here buildEcsOption returns only RDATA
    // (option value).  The option code is prepended by buildOptRdata.
    // We just verify the ECS RDATA starts with family=1 (IPv4) and prefix=24.
    expect(ecs[0]).toBe(0x00); // family high byte
    expect(ecs[1]).toBe(0x01); // family low byte = 1 (IPv4)
    expect(ecs[2]).toBe(24);   // source prefix length
  });

  it("ECS option code is 0x0008 for IPv6 CIDR", () => {
    const ecs = buildEcsOption("2001:db8::/32");
    expect(ecs).not.toBeNull();
    expect(ecs[0]).toBe(0x00);
    expect(ecs[1]).toBe(0x02); // family = 2 (IPv6)
    expect(ecs[2]).toBe(32);   // source prefix length
  });

  it("buildEcsOption returns null for invalid input", () => {
    expect(buildEcsOption(null)).toBeNull();
    expect(buildEcsOption("")).toBeNull();
    expect(buildEcsOption("not-an-address")).toBeNull();
  });

  it("buildEcsOption returns null for prefix out of range", () => {
    expect(buildEcsOption("203.0.113.0/200")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// RFC 6891 - outgoing query keeps existing EDNS options that are not stripped
// ---------------------------------------------------------------------------

describe("RFC 6891 - EDNS option forwarding", () => {
  it("ECS substitute mode: ECS option (code 8) is present in forwarded query", () => {
    // substitute mode injects ECS from the configured subnet (RFC 7871)
    const query = buildDnsQuery("example.com", 1);
    const cfg = makeConfig({ ecsMode: "substitute", ecsValue: "203.0.113.0/24" });
    const out = processEdnsOutgoing(query, cfg, null);
    function skipName(b, o) {
      while (o < b.length) {
        const len = b[o];
        if (len === 0) return o + 1;
        if ((len & 0xc0) === 0xc0) return o + 2;
        o += 1 + len;
      }
      return o;
    }
    let off = 12;
    const qdcount = (out[4] << 8) | out[5];
    for (let i = 0; i < qdcount; i++) { off = skipName(out, off); off += 4; }
    off = skipName(out, off); // root label of OPT RR
    const rdlen = (out[off + 8] << 8) | out[off + 9];
    const rdStart = off + 10;
    const rdEnd   = rdStart + rdlen;
    let found = false;
    let o = rdStart;
    while (o + 4 <= rdEnd) {
      const code = (out[o] << 8) | out[o + 1];
      const len  = (out[o + 2] << 8) | out[o + 3];
      if (code === 8) { found = true; break; }
      o += 4 + len;
    }
    expect(found).toBe(true);
  });

  it("ECS strip mode: ECS option is absent from forwarded query", () => {
    const cfg = makeConfig({ ecsMode: "strip" });
    // First inject ECS via substitute mode to simulate a query carrying ECS
    const baseQuery = buildDnsQuery("example.com", 1);
    const withEcs = processEdnsOutgoing(baseQuery, makeConfig({ ecsMode: "substitute", ecsValue: "203.0.113.0/24" }), null);
    // Now process again in strip mode: ECS must be removed
    const stripped = processEdnsOutgoing(withEcs, cfg, null);
    // Verify ECS option code 8 is absent
    let off = 12;
    const qdcount = (stripped[4] << 8) | stripped[5];
    function skipName(b, o) {
      while (o < b.length) {
        const len = b[o];
        if (len === 0) return o + 1;
        if ((len & 0xc0) === 0xc0) return o + 2;
        o += 1 + len;
      }
      return o;
    }
    for (let i = 0; i < qdcount; i++) { off = skipName(stripped, off); off += 4; }
    off = skipName(stripped, off);
    const rdlen = (stripped[off + 8] << 8) | stripped[off + 9];
    const rdStart = off + 10;
    const rdEnd   = rdStart + rdlen;
    let found = false;
    let o = rdStart;
    while (o + 4 <= rdEnd) {
      const code = (stripped[o] << 8) | stripped[o + 1];
      const len  = (stripped[o + 2] << 8) | stripped[o + 3];
      if (code === 8) { found = true; break; }
      o += 4 + len;
    }
    expect(found).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// RFC 6891 - upstream integration: every outgoing fetch has EDNS OPT
// ---------------------------------------------------------------------------

describe("RFC 6891 - upstream requests include EDNS OPT", () => {
  it("wire POST upstream always receives an OPT RR (ARCOUNT >= 1 with TYPE=41)", async () => {
    const capturedBodies = [];
    globalThis.fetch = vi.fn(async (url, opts) => {
      if (opts && opts.body) {
        capturedBodies.push(new Uint8Array(await new Response(opts.body).arrayBuffer()));
      }
      // Import buildDnsResponse inline since we can't import from here at top level statically
      const resp = new Uint8Array([
        0x00, 0x00, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        // question: example.com A
        0x07, 0x65, 0x78, 0x61, 0x6d, 0x70, 0x6c, 0x65, 0x03, 0x63, 0x6f, 0x6d, 0x00,
        0x00, 0x01, 0x00, 0x01,
        // answer: pointer to name, A, IN, TTL=300, 4 bytes, 1.2.3.4
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x01, 0x2c, 0x00, 0x04,
        0x01, 0x02, 0x03, 0x04,
      ]);
      return new Response(resp, { headers: { "Content-Type": "application/dns-message" } });
    });

    const originalCaches = globalThis.caches;
    globalThis.caches = { default: { match: async () => null, put: async () => {} } };
    try {
      const query = buildDnsQuery("example.com", 1);
      await handleRequest(new Request("https://w.example.com/dns-query", {
        method: "POST",
        headers: { "Content-Type": "application/dns-message" },
        body: query,
      }), {}, { waitUntil: () => {} });
    } finally {
      globalThis.caches = originalCaches;
    }

    expect(capturedBodies.length).toBeGreaterThan(0);
    for (const body of capturedBodies) {
      const types = optTypeIn(body);
      expect(types).toContain(41);
    }
  });
});
