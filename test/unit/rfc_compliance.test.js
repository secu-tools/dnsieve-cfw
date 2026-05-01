// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/unit/rfc_compliance.test.js
// Unit tests for RFC compliance requirements.
//
// Covers:
//   - buildServfailResponse and buildBlockedResponse MUST mirror the RD bit,
//     OPCODE, and CD bit from the original query (RFC 1035 S.4.1.1,
//     RFC 4035 S.3.1.6).
//   - clearDoBitInResponse MUST clear the DO bit for non-DO clients
//     (RFC 6891 S.6.1.4 / RFC 3225).
//   - getConfig MUST fall back to defaults when UPSTREAM_SERVERS is a
//     non-array JSON value (null, object, number, string).

import { describe, it, expect } from "vitest";
import {
  buildServfailResponse,
  buildBlockedResponse,
  buildDnsQuery,
  clearDoBitInResponse,
  hasDoBit,
  buildDnsQueryWithDo,
  processEdnsOutgoing,
} from "../../src/dns.js";
import { getConfig, UPSTREAM_SERVERS } from "../../src/config.js";

// ---------------------------------------------------------------------------
// RFC 1035 S.4.1.1 - RD bit must be mirrored in synthetic responses
// ---------------------------------------------------------------------------

describe("RFC 1035 S.4.1.1 - RD bit in buildServfailResponse", () => {
  it("mirrors RD=1 from query into SERVFAIL response", () => {
    // buildDnsQuery sets RD=1 (byte 2 bit 0)
    const query = buildDnsQuery("example.com", 1);
    expect(query[2] & 0x01).toBe(1); // RD=1 in query
    const sfail = buildServfailResponse(query);
    expect(sfail[2] & 0x01).toBe(1); // RD must be mirrored
  });

  it("mirrors RD=0 from query into SERVFAIL response", () => {
    const query = buildDnsQuery("example.com", 1);
    query[2] = query[2] & ~0x01; // clear RD bit
    expect(query[2] & 0x01).toBe(0);
    const sfail = buildServfailResponse(query);
    expect(sfail[2] & 0x01).toBe(0); // RD must be 0
  });

  it("SERVFAIL response always has QR=1 and RA=1", () => {
    const query = buildDnsQuery("example.com", 1);
    const sfail = buildServfailResponse(query);
    expect(sfail[2] & 0x80).toBe(0x80); // QR=1
    expect(sfail[3] & 0x80).toBe(0x80); // RA=1
  });

  it("SERVFAIL RCODE is 2", () => {
    const query = buildDnsQuery("example.com", 1);
    const sfail = buildServfailResponse(query);
    expect(sfail[3] & 0x0f).toBe(2);
  });

  it("minimal fallback header has QR=1 and RCODE=2 when queryBytes is null", () => {
    const sfail = buildServfailResponse(null);
    expect(sfail.length).toBe(12);
    expect(sfail[2] & 0x80).toBe(0x80); // QR=1
    expect(sfail[3] & 0x0f).toBe(2);    // SERVFAIL
  });
});

describe("RFC 1035 S.4.1.1 - RD bit in buildBlockedResponse", () => {
  it("mirrors RD=1 from query into blocked response (null mode)", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    expect(query[2] & 0x01).toBe(1); // buildDnsQuery sets RD=1
    const resp = buildBlockedResponse(query, "null");
    expect(resp[2] & 0x80).toBe(0x80); // QR=1
    expect(resp[2] & 0x01).toBe(1);    // RD mirrored
    expect(resp[3] & 0x80).toBe(0x80); // RA=1
  });

  it("mirrors RD=0 from query into blocked response (nxdomain mode)", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    query[2] = query[2] & ~0x01; // clear RD bit
    const resp = buildBlockedResponse(query, "nxdomain");
    expect(resp[2] & 0x01).toBe(0); // RD must be 0
    expect(resp[3] & 0x0f).toBe(3); // NXDOMAIN
  });

  it("mirrors RD=1 for nodata mode", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    const resp = buildBlockedResponse(query, "nodata");
    expect(resp[2] & 0x01).toBe(1);
    expect(resp[3] & 0x0f).toBe(0); // NOERROR
  });

  it("mirrors RD=1 for refused mode", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    const resp = buildBlockedResponse(query, "refused");
    expect(resp[2] & 0x01).toBe(1);
    expect(resp[3] & 0x0f).toBe(5); // REFUSED
  });

  it("QR=1 is always set in blocked response (response bit)", () => {
    const query = buildDnsQuery("blocked.example.com", 28);
    const resp = buildBlockedResponse(query, "null");
    expect(resp[2] & 0x80).toBe(0x80);
  });
});

// ---------------------------------------------------------------------------
// RFC 1035 S.4.1.1 - OPCODE mirroring in synthetic responses
// ---------------------------------------------------------------------------

describe("RFC 1035 S.4.1.1 - OPCODE mirroring in buildServfailResponse", () => {
  it("OPCODE=0 (standard query) is preserved in SERVFAIL response", () => {
    const query = buildDnsQuery("example.com", 1);
    expect((query[2] >> 3) & 0x0f).toBe(0); // OPCODE=0
    const sfail = buildServfailResponse(query);
    expect((sfail[2] >> 3) & 0x0f).toBe(0);
  });

  it("non-standard OPCODE is mirrored into SERVFAIL response", () => {
    const query = buildDnsQuery("example.com", 1);
    // Inject OPCODE=4 into byte 2 (bits 6-3)
    query[2] = (query[2] & 0x87) | (4 << 3);
    expect((query[2] >> 3) & 0x0f).toBe(4);
    const sfail = buildServfailResponse(query);
    expect((sfail[2] >> 3) & 0x0f).toBe(4);
  });

  it("OPCODE mirroring does not disturb RD or QR bits", () => {
    const query = buildDnsQuery("example.com", 1);
    query[2] = (query[2] & 0x87) | (2 << 3); // OPCODE=2
    const sfail = buildServfailResponse(query);
    expect(sfail[2] & 0x80).toBe(0x80); // QR=1
    expect(sfail[2] & 0x01).toBe(query[2] & 0x01); // RD preserved
    expect((sfail[2] >> 3) & 0x0f).toBe(2); // OPCODE=2
  });
});

describe("RFC 1035 S.4.1.1 - OPCODE mirroring in buildBlockedResponse", () => {
  it("OPCODE=0 is preserved in blocked response", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    expect((query[2] >> 3) & 0x0f).toBe(0);
    const resp = buildBlockedResponse(query, "null");
    expect((resp[2] >> 3) & 0x0f).toBe(0);
  });

  it("non-standard OPCODE is mirrored into blocked response (nxdomain mode)", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    query[2] = (query[2] & 0x87) | (4 << 3); // OPCODE=4
    const resp = buildBlockedResponse(query, "nxdomain");
    expect((resp[2] >> 3) & 0x0f).toBe(4);
  });

  it("OPCODE mirroring does not disturb QR, RD, or rcode", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    query[2] = (query[2] & 0x87) | (3 << 3); // OPCODE=3
    const resp = buildBlockedResponse(query, "refused");
    expect(resp[2] & 0x80).toBe(0x80); // QR=1
    expect((resp[2] >> 3) & 0x0f).toBe(3); // OPCODE=3
    expect(resp[3] & 0x0f).toBe(5); // REFUSED rcode
  });
});

// ---------------------------------------------------------------------------
// RFC 4035 S.3.1.6 - CD bit mirroring in synthetic responses
// ---------------------------------------------------------------------------

describe("RFC 4035 S.3.1.6 - CD bit mirroring in buildServfailResponse", () => {
  it("CD=0 in query produces CD=0 in SERVFAIL response", () => {
    const query = buildDnsQuery("example.com", 1);
    query[3] = query[3] & ~0x10; // clear CD bit
    const sfail = buildServfailResponse(query);
    expect(sfail[3] & 0x10).toBe(0);
  });

  it("CD=1 in query produces CD=1 in SERVFAIL response", () => {
    const query = buildDnsQuery("example.com", 1);
    query[3] = query[3] | 0x10; // set CD bit
    const sfail = buildServfailResponse(query);
    expect(sfail[3] & 0x10).toBe(0x10);
  });

  it("SERVFAIL rcode is still 2 and RA=1 when CD=1", () => {
    const query = buildDnsQuery("example.com", 1);
    query[3] = query[3] | 0x10;
    const sfail = buildServfailResponse(query);
    expect(sfail[3] & 0x0f).toBe(2);   // SERVFAIL
    expect(sfail[3] & 0x80).toBe(0x80); // RA=1
    expect(sfail[3] & 0x60).toBe(0);    // Z bits remain 0
  });
});

describe("RFC 4035 S.3.1.6 - CD bit mirroring in buildBlockedResponse", () => {
  it("CD=0 in query produces CD=0 in blocked response", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    query[3] = query[3] & ~0x10;
    const resp = buildBlockedResponse(query, "null");
    expect(resp[3] & 0x10).toBe(0);
  });

  it("CD=1 in query produces CD=1 in blocked response (null mode)", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    query[3] = query[3] | 0x10;
    const resp = buildBlockedResponse(query, "null");
    expect(resp[3] & 0x10).toBe(0x10);
  });

  it("CD=1 is preserved across all blocking modes", () => {
    for (const mode of ["null", "nxdomain", "nodata", "refused"]) {
      const query = buildDnsQuery("blocked.example.com", 1);
      query[3] = query[3] | 0x10;
      const resp = buildBlockedResponse(query, mode);
      expect(resp[3] & 0x10).toBe(0x10);
    }
  });

  it("RA=1 and correct rcode are preserved when CD=1", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    query[3] = query[3] | 0x10;
    const resp = buildBlockedResponse(query, "nxdomain");
    expect(resp[3] & 0x80).toBe(0x80); // RA=1
    expect(resp[3] & 0x0f).toBe(3);    // NXDOMAIN
    expect(resp[3] & 0x60).toBe(0);    // Z bits remain 0
  });
});

// ---------------------------------------------------------------------------
// RFC 6891 S.6.1.4 / RFC 3225 - DO bit mirroring
// ---------------------------------------------------------------------------

describe("RFC 6891 S.6.1.4 - clearDoBitInResponse", () => {
  function makeResponseWithDo(doBit) {
    // Build a minimal response buffer with an OPT record.
    // Use processEdnsOutgoing on a plain query to get a buffer with OPT.
    const cfg = getConfig({});
    const query = buildDnsQuery("example.com", 1);
    const withOpt = processEdnsOutgoing(query, cfg, null);
    // processEdnsOutgoing always sets DO=1. Build a minimal 12-byte response
    // header and append the OPT from the query as a stand-in (enough for tests).
    const resp = new Uint8Array(withOpt.length);
    resp.set(withOpt);
    // Set QR=1 so it looks like a response
    resp[2] |= 0x80;
    return resp;
  }

  it("clears DO=1 to DO=0 in a response with OPT", () => {
    const resp = makeResponseWithDo(true);
    // Verify DO is initially set after processEdnsOutgoing
    expect(hasDoBit(resp)).toBe(true);
    const cleared = clearDoBitInResponse(resp);
    expect(hasDoBit(cleared)).toBe(false);
  });

  it("returns buffer unchanged when DO is already 0", () => {
    const query = buildDnsQuery("example.com", 1);
    // buildDnsQuery has no OPT record, so hasDoBit is false
    expect(hasDoBit(query)).toBe(false);
    const result = clearDoBitInResponse(query);
    expect(result).toBe(query); // same reference - no copy made
  });

  it("returns buffer unchanged when there is no OPT record", () => {
    const buf = new Uint8Array(20);
    buf[10] = 0; buf[11] = 0; // ARCOUNT=0
    const result = clearDoBitInResponse(buf);
    expect(result).toBe(buf);
  });

  it("returns short buffer unchanged", () => {
    const buf = new Uint8Array(6);
    const result = clearDoBitInResponse(buf);
    expect(result).toBe(buf);
  });

  it("DO bit clearing does not affect other EDNS options", () => {
    // Build a query with OPT, which processEdnsOutgoing populates with DO=1
    const cfg = getConfig({});
    const query = buildDnsQuery("example.com", 1);
    const withOpt = processEdnsOutgoing(query, cfg, null);
    expect(hasDoBit(withOpt)).toBe(true);
    const cleared = clearDoBitInResponse(withOpt);
    expect(hasDoBit(cleared)).toBe(false);
    // Length should be unchanged (only a bit was cleared)
    expect(cleared.length).toBe(withOpt.length);
  });
});

// ---------------------------------------------------------------------------
// getConfig UPSTREAM_SERVERS validation
// ---------------------------------------------------------------------------

describe("getConfig UPSTREAM_SERVERS: non-array JSON falls back to defaults", () => {
  it("null JSON value falls back gracefully (no crash)", () => {
    expect(() => getConfig({ UPSTREAM_SERVERS: "null" })).not.toThrow();
    const cfg = getConfig({ UPSTREAM_SERVERS: "null" });
    expect(cfg.UPSTREAM_SERVERS).toEqual(UPSTREAM_SERVERS);
    expect(cfg.UPSTREAM_COUNT).toBe(UPSTREAM_SERVERS.length);
  });

  it("JSON object value falls back to defaults", () => {
    const cfg = getConfig({ UPSTREAM_SERVERS: '{"url":"https://dns.example.com"}' });
    expect(cfg.UPSTREAM_SERVERS).toEqual(UPSTREAM_SERVERS);
    expect(cfg.UPSTREAM_COUNT).toBe(UPSTREAM_SERVERS.length);
  });

  it("JSON number value falls back to defaults", () => {
    const cfg = getConfig({ UPSTREAM_SERVERS: "42" });
    expect(cfg.UPSTREAM_SERVERS).toEqual(UPSTREAM_SERVERS);
    expect(cfg.UPSTREAM_COUNT).toBe(UPSTREAM_SERVERS.length);
  });

  it("JSON boolean value falls back to defaults", () => {
    const cfg = getConfig({ UPSTREAM_SERVERS: "true" });
    expect(cfg.UPSTREAM_SERVERS).toEqual(UPSTREAM_SERVERS);
    expect(cfg.UPSTREAM_COUNT).toBe(UPSTREAM_SERVERS.length);
  });

  it("valid JSON array is accepted", () => {
    const urls = ["https://dns.example.com/dns-query"];
    const cfg = getConfig({ UPSTREAM_SERVERS: JSON.stringify(urls) });
    expect(cfg.UPSTREAM_SERVERS).toEqual(urls);
    expect(cfg.UPSTREAM_COUNT).toBe(1);
  });

  it("empty JSON array is accepted", () => {
    const cfg = getConfig({ UPSTREAM_SERVERS: "[]" });
    expect(cfg.UPSTREAM_SERVERS).toEqual([]);
    expect(cfg.UPSTREAM_COUNT).toBe(0);
  });

  it("invalid JSON falls back to defaults", () => {
    const cfg = getConfig({ UPSTREAM_SERVERS: "not-json" });
    expect(cfg.UPSTREAM_SERVERS).toEqual(UPSTREAM_SERVERS);
    expect(cfg.UPSTREAM_COUNT).toBe(UPSTREAM_SERVERS.length);
  });
});
