// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/unit/dns_edge_cases.test.js
// Edge case tests for DNS wire parsing: malformed packets, boundary conditions,
// compression pointer safety, buffer bounds, and truncated payloads.

import { describe, it, expect } from "vitest";
import {
  readDnsName,
  skipName,
  extractQueryNameType,
  inspectWireResponse,
  wireToJson,
  parseRdata,
  buildDnsQuery,
  buildDnsResponse,
  buildDnsQueryWithDo,
  toASCII,
  normalizeType,
  extractMinTtl,
  extractMinTtlWire,
  isBlockedOrNxdomain,
  isServerFailure,
  buildEcsOption,
  stripDnssecFromWire,
  stripDnssecFromJson,
} from "../../src/dns.js";

// ---------------------------------------------------------------------------
// readDnsName compression pointer edge cases
// ---------------------------------------------------------------------------

describe("readDnsName - compression pointer edge cases", () => {
  it("throws on circular compression pointer loop", () => {
    // Two pointers pointing at each other: offset 12 -> 14, offset 14 -> 12
    const buf = new Uint8Array(16);
    buf[12] = 0xc0; buf[13] = 14; // pointer to offset 14
    buf[14] = 0xc0; buf[15] = 12; // pointer to offset 12
    expect(() => readDnsName(buf, 12)).toThrow("loop");
  });

  it("handles self-referencing pointer (points to itself)", () => {
    const buf = new Uint8Array(14);
    buf[12] = 0xc0; buf[13] = 12; // pointer to itself
    expect(() => readDnsName(buf, 12)).toThrow("loop");
  });

  it("handles pointer at end of buffer (off+1 is undefined)", () => {
    // Compression byte at last position, buf[off+1] is undefined -> treated as 0
    const buf = new Uint8Array(13);
    buf[12] = 0xc0; // pointer byte, but buf[13] doesn't exist
    // readDnsName should handle gracefully (no crash)
    let result;
    expect(() => { result = readDnsName(buf, 12); }).not.toThrow();
  });

  it("follows valid forward pointer without crashing", () => {
    // Create a name at offset 16, then a pointer at offset 12 that points forward
    const buf = new Uint8Array(24);
    // Name at offset 16: 3com0
    buf[16] = 3; buf[17] = 0x63; buf[18] = 0x6f; buf[19] = 0x6d; buf[20] = 0;
    // Pointer at offset 12 to offset 16
    buf[12] = 0xc0; buf[13] = 16;
    const result = readDnsName(buf, 12);
    expect(result.name).toBe("com.");
  });

  it("handles deeply nested (but valid) compression", () => {
    const buf = new Uint8Array(120);
    // Root label at offset 100
    buf[100] = 0;
    // Chain of single-hop pointers
    let off = 12;
    for (let i = 0; i < 40; i++) {
      buf[off] = 0xc0;
      buf[off + 1] = off + 2;
      off += 2;
    }
    // Final pointer to the root label
    buf[off] = 0xc0;
    buf[off + 1] = 100;
    const result = readDnsName(buf, 12);
    expect(result.name).toBe(".");
  });
});

// ---------------------------------------------------------------------------
// extractQueryNameType - malformed inputs
// ---------------------------------------------------------------------------

describe("extractQueryNameType - malformed inputs", () => {
  it("returns null for null input", () => {
    expect(extractQueryNameType(null)).toBeNull();
  });

  it("returns null for empty buffer", () => {
    expect(extractQueryNameType(new Uint8Array(0))).toBeNull();
  });

  it("returns null for 11-byte buffer (too short for DNS header)", () => {
    expect(extractQueryNameType(new Uint8Array(11))).toBeNull();
  });

  it("returns null when qdcount is 0", () => {
    const buf = new Uint8Array(12);
    // All zeros = qdcount 0
    expect(extractQueryNameType(buf)).toBeNull();
  });

  it("returns null for truncated question section", () => {
    const buf = new Uint8Array(14);
    buf[4] = 0; buf[5] = 1; // QDCOUNT=1
    buf[12] = 50; // label length 50 but only 1 byte follows
    buf[13] = 0x41;
    expect(extractQueryNameType(buf)).toBeNull();
  });

  it("returns valid result for minimal valid query", () => {
    const query = buildDnsQuery("a.b", 1);
    const result = extractQueryNameType(query);
    expect(result).not.toBeNull();
    expect(result.name).toBe("a.b.");
    expect(result.qtype).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// inspectWireResponse - boundary conditions
// ---------------------------------------------------------------------------

describe("inspectWireResponse - boundary conditions", () => {
  it("returns safe defaults for buffer shorter than 4 bytes", () => {
    expect(inspectWireResponse(new Uint8Array(0))).toEqual({ blocked: false, servfail: false });
    expect(inspectWireResponse(new Uint8Array(3))).toEqual({ blocked: false, servfail: false });
  });

  it("detects SERVFAIL (rcode=2)", () => {
    const buf = new Uint8Array(12);
    buf[3] = 0x02; // rcode=2
    expect(inspectWireResponse(buf).servfail).toBe(true);
  });

  it("detects block: NXDOMAIN with nscount=0", () => {
    const buf = new Uint8Array(12);
    buf[3] = 0x03; // rcode=3 (NXDOMAIN)
    buf[8] = 0; buf[9] = 0; // nscount=0
    expect(inspectWireResponse(buf).blocked).toBe(true);
  });

  it("does not flag legitimate NXDOMAIN (nscount > 0)", () => {
    const buf = new Uint8Array(12);
    buf[3] = 0x03; // rcode=3
    buf[8] = 0; buf[9] = 1; // nscount=1
    expect(inspectWireResponse(buf).blocked).toBe(false);
  });

  it("detects A record 0.0.0.0 as blocked", () => {
    const resp = buildDnsResponse("blocked.com", "0.0.0.0");
    const result = inspectWireResponse(resp);
    expect(result.blocked).toBe(true);
  });

  it("does not flag normal A record as blocked", () => {
    const resp = buildDnsResponse("good.com", "93.184.216.34");
    const result = inspectWireResponse(resp);
    expect(result.blocked).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// wireToJson - malformed packets
// ---------------------------------------------------------------------------

describe("wireToJson - malformed and truncated packets", () => {
  it("returns null for empty buffer", () => {
    expect(wireToJson(new Uint8Array(0))).toBeNull();
  });

  it("returns null for 11-byte buffer", () => {
    expect(wireToJson(new Uint8Array(11))).toBeNull();
  });

  it("handles response with qdcount=0 (no questions)", () => {
    const buf = new Uint8Array(12);
    buf[2] = 0x80; // QR=1
    buf[4] = 0; buf[5] = 0; // QDCOUNT=0
    const json = wireToJson(buf);
    expect(json).not.toBeNull();
    expect(json.Question).toBeUndefined();
  });

  it("parses a valid A response correctly", () => {
    const resp = buildDnsResponse("example.com", "1.2.3.4", 300);
    const json = wireToJson(resp);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(0);
    expect(json.Answer).toHaveLength(1);
    expect(json.Answer[0].data).toBe("1.2.3.4");
    expect(json.Answer[0].TTL).toBe(300);
  });

  it("correctly sets RD/RA/AD/CD flags", () => {
    const resp = buildDnsResponse("example.com", "1.2.3.4");
    // buildDnsResponse sets QR=1, RD=1, RA=1
    const json = wireToJson(resp);
    expect(json.RD).toBe(true);
    expect(json.RA).toBe(true);
    expect(json.AD).toBe(false);
    expect(json.CD).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// TTL extraction edge cases
// ---------------------------------------------------------------------------

describe("TTL extraction edge cases", () => {
  it("extractMinTtl returns null for empty JSON", () => {
    expect(extractMinTtl({})).toBeNull();
  });

  it("extractMinTtl returns null for JSON with no TTL fields", () => {
    expect(extractMinTtl({ Answer: [{ name: "x", type: 1 }] })).toBeNull();
  });

  it("extractMinTtl picks minimum from Answer and Authority", () => {
    const json = {
      Answer: [{ TTL: 300 }, { TTL: 60 }],
      Authority: [{ TTL: 120 }],
    };
    expect(extractMinTtl(json)).toBe(60);
  });

  it("extractMinTtl handles TTL=0", () => {
    expect(extractMinTtl({ Answer: [{ TTL: 0 }] })).toBe(0);
  });

  it("extractMinTtlWire returns null for short buffer", () => {
    expect(extractMinTtlWire(new Uint8Array(11))).toBeNull();
  });

  it("extractMinTtlWire returns null for response with no records", () => {
    const buf = new Uint8Array(12);
    buf[4] = 0; buf[5] = 0; // QDCOUNT=0
    buf[6] = 0; buf[7] = 0; // ANCOUNT=0
    expect(extractMinTtlWire(buf)).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// isBlockedOrNxdomain - edge cases
// ---------------------------------------------------------------------------

describe("isBlockedOrNxdomain - edge cases", () => {
  it("returns true for NXDOMAIN with Authority=null", () => {
    expect(isBlockedOrNxdomain({ Status: 3, Authority: null })).toBe(true);
  });

  it("returns true for NXDOMAIN with Authority=undefined", () => {
    expect(isBlockedOrNxdomain({ Status: 3 })).toBe(true);
  });

  it("returns false for NXDOMAIN with SOA in Authority", () => {
    expect(isBlockedOrNxdomain({
      Status: 3,
      Authority: [{ name: "example.com.", type: 6, TTL: 300, data: "ns1.example.com. admin.example.com. 1 3600 900 604800 86400" }],
    })).toBe(false);
  });

  it("returns true for A=0.0.0.0", () => {
    expect(isBlockedOrNxdomain({
      Status: 0,
      Answer: [{ type: 1, data: "0.0.0.0" }],
    })).toBe(true);
  });

  it("returns true for AAAA=::", () => {
    expect(isBlockedOrNxdomain({
      Status: 0,
      Answer: [{ type: 28, data: "::" }],
    })).toBe(true);
  });

  it("returns true for AAAA=::0", () => {
    expect(isBlockedOrNxdomain({
      Status: 0,
      Answer: [{ type: 28, data: "::0" }],
    })).toBe(true);
  });

  it("returns false for normal NOERROR response", () => {
    expect(isBlockedOrNxdomain({
      Status: 0,
      Answer: [{ type: 1, data: "93.184.216.34" }],
    })).toBe(false);
  });

  it("returns false for SERVFAIL", () => {
    expect(isBlockedOrNxdomain({ Status: 2 })).toBe(false);
  });

  it("isServerFailure returns true for Status=2", () => {
    expect(isServerFailure({ Status: 2 })).toBe(true);
  });

  it("isServerFailure returns false for Status=0", () => {
    expect(isServerFailure({ Status: 0 })).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// buildEcsOption - edge cases
// ---------------------------------------------------------------------------

describe("buildEcsOption - edge cases", () => {
  it("returns null for empty string", () => {
    expect(buildEcsOption("")).toBeNull();
  });

  it("returns null for null", () => {
    expect(buildEcsOption(null)).toBeNull();
  });

  it("returns null for string without slash", () => {
    expect(buildEcsOption("192.168.1.1")).toBeNull();
  });

  it("returns null for prefix > 128", () => {
    expect(buildEcsOption("10.0.0.0/129")).toBeNull();
  });

  it("returns null for negative prefix", () => {
    expect(buildEcsOption("10.0.0.0/-1")).toBeNull();
  });

  it("builds valid IPv4 ECS option", () => {
    const result = buildEcsOption("203.0.113.0/24");
    expect(result).not.toBeNull();
    expect(result[0]).toBe(0); expect(result[1]).toBe(1); // IPv4 family
    expect(result[2]).toBe(24); // prefix length
    expect(result[3]).toBe(0); // scope prefix
  });

  it("builds valid IPv6 ECS option", () => {
    const result = buildEcsOption("2001:db8::/32");
    expect(result).not.toBeNull();
    expect(result[0]).toBe(0); expect(result[1]).toBe(2); // IPv6 family
    expect(result[2]).toBe(32);
  });

  it("builds /0 prefix (no address bytes)", () => {
    const result = buildEcsOption("0.0.0.0/0");
    expect(result).not.toBeNull();
    expect(result.length).toBe(4); // only header, no address bytes
    expect(result[2]).toBe(0);
  });

  it("returns null for IPv4 with wrong number of octets", () => {
    expect(buildEcsOption("192.168.1/24")).toBeNull();
  });

  it("returns null for IPv4 with out-of-range octet", () => {
    expect(buildEcsOption("256.0.0.0/8")).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// toASCII - edge cases
// ---------------------------------------------------------------------------

describe("toASCII - edge cases", () => {
  it("lowercases ASCII domains", () => {
    expect(toASCII("EXAMPLE.COM")).toBe("example.com");
  });

  it("handles root label", () => {
    expect(toASCII(".")).toBe(".");
  });

  it("handles empty string", () => {
    expect(toASCII("")).toBe("");
  });

  it("converts IDN domains to punycode", () => {
    const result = toASCII("münchen.de");
    expect(result).toContain("xn--");
    expect(result).toContain(".de");
  });
});

// ---------------------------------------------------------------------------
// normalizeType - edge cases
// ---------------------------------------------------------------------------

describe("normalizeType - edge cases", () => {
  it("defaults to A for empty input", () => {
    expect(normalizeType("")).toBe("A");
  });

  it("defaults to A for null", () => {
    expect(normalizeType(null)).toBe("A");
  });

  it("normalizes known type names", () => {
    expect(normalizeType("a")).toBe("A");
    expect(normalizeType("aaaa")).toBe("AAAA");
    expect(normalizeType("cname")).toBe("CNAME");
    expect(normalizeType("MX")).toBe("MX");
  });

  it("handles numeric type strings", () => {
    expect(normalizeType("1")).toBe("A");
    expect(normalizeType("28")).toBe("AAAA");
  });

  it("passes through unknown types as uppercase", () => {
    expect(normalizeType("custom")).toBe("CUSTOM");
  });
});

// ---------------------------------------------------------------------------
// DNSSEC stripping edge cases
// ---------------------------------------------------------------------------

describe("stripDnssecFromWire - edge cases", () => {
  it("returns original buffer for short input", () => {
    const short = new Uint8Array(5);
    expect(stripDnssecFromWire(short, 1)).toBe(short);
  });

  it("returns original buffer when no DNSSEC records to strip", () => {
    const resp = buildDnsResponse("example.com", "1.2.3.4", 300);
    const result = stripDnssecFromWire(resp, 1);
    expect(result).toBe(resp); // same reference, nothing removed
  });
});

describe("stripDnssecFromJson - edge cases", () => {
  it("returns original when no DNSSEC records present", () => {
    const json = { Answer: [{ type: 1, data: "1.2.3.4" }] };
    const result = stripDnssecFromJson(json, 1);
    expect(result).toBe(json);
  });

  it("strips RRSIG from Answer for non-DO client", () => {
    const json = {
      Answer: [
        { type: 1, name: "example.com.", TTL: 300, data: "1.2.3.4" },
        { type: 46, name: "example.com.", TTL: 300, data: "sig..." },
      ],
    };
    const result = stripDnssecFromJson(json, 1);
    expect(result.Answer).toHaveLength(1);
    expect(result.Answer[0].type).toBe(1);
  });

  it("keeps RRSIG in Answer when queryQtype is RRSIG (46)", () => {
    const json = {
      Answer: [{ type: 46, name: "example.com.", TTL: 300, data: "sig..." }],
    };
    const result = stripDnssecFromJson(json, 46);
    expect(result.Answer).toHaveLength(1);
  });

  it("always strips DNSSEC types from Authority", () => {
    const json = {
      Authority: [
        { type: 47, name: "example.com.", TTL: 300, data: "nsec..." },
        { type: 6, name: "example.com.", TTL: 300, data: "soa..." },
      ],
    };
    const result = stripDnssecFromJson(json, 1);
    expect(result.Authority).toHaveLength(1);
    expect(result.Authority[0].type).toBe(6);
  });
});
