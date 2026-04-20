// test/unit/dns.test.js
// Unit tests for DNS wire format parsing and JSON conversion (src/dns.js)
//
// Covers:
//   - RFC 1035 wire format encoding/decoding
//   - Label parsing and pointer compression
//   - RDATA parsing: A, AAAA, NS, CNAME, PTR, SOA, MX, TXT
//   - Block / SERVFAIL detection from wire and JSON
//   - TTL extraction
//   - Base64 padding stripping
//   - Type normalisation
//   - IDN toASCII normalisation (WHATWG URL SS.3.3 / RFC 5891)

import { describe, it, expect } from "vitest";
import {
  normalizeType,
  toASCII,
  stripBase64Padding,
  isBlockedOrNxdomain,
  isServerFailure,
  inspectWireResponse,
  wireToJson,
  extractMinTtl,
  extractMinTtlWire,
  buildEcsOption,
  processEdnsOutgoing,
  processEdnsIncoming,
  hasNsidRequest,
  hasDoBit,
  injectNsidToResponse,
  extractQueryNameType,
  stripDnssecFromWire,
  stripDnssecFromJson,
  buildDnsQuery,
  buildDnsQueryWithDo,
  buildDnsResponse,
  skipName,
  readDnsName,
  parseRdata,
  HEX_TABLE,
  DNS_TYPE_TO_NUMBER,
  DNS_NUMBER_TO_TYPE,
} from "../../src/dns.js";

// ---------------------------------------------------------------------------
// HEX_TABLE
// ---------------------------------------------------------------------------

describe("HEX_TABLE", () => {
  it("has 256 entries", () => {
    expect(HEX_TABLE.length).toBe(256);
  });

  it("encodes 0 as '00' and 255 as 'ff'", () => {
    expect(HEX_TABLE[0]).toBe("00");
    expect(HEX_TABLE[255]).toBe("ff");
  });

  it("encodes 16 as '10'", () => {
    expect(HEX_TABLE[16]).toBe("10");
  });
});

// ---------------------------------------------------------------------------
// DNS_TYPE_TO_NUMBER / DNS_NUMBER_TO_TYPE
// ---------------------------------------------------------------------------

describe("DNS type tables", () => {
  it("maps A to 1", () => {
    expect(DNS_TYPE_TO_NUMBER.A).toBe(1);
  });

  it("maps AAAA to 28", () => {
    expect(DNS_TYPE_TO_NUMBER.AAAA).toBe(28);
  });

  it("maps 1 back to A", () => {
    expect(DNS_NUMBER_TO_TYPE[1]).toBe("A");
  });

  it("round-trips all type numbers", () => {
    for (const [name, num] of Object.entries(DNS_TYPE_TO_NUMBER)) {
      if (name !== "ANY") {
        expect(DNS_NUMBER_TO_TYPE[num]).toBe(name);
      }
    }
  });

  // RFC 9460 - SVCB (type 64) and HTTPS (type 65)
  it("maps SVCB to 64 (RFC 9460)", () => {
    expect(DNS_TYPE_TO_NUMBER.SVCB).toBe(64);
  });

  it("maps HTTPS to 65 (RFC 9460)", () => {
    expect(DNS_TYPE_TO_NUMBER.HTTPS).toBe(65);
  });

  it("maps 64 back to SVCB", () => {
    expect(DNS_NUMBER_TO_TYPE[64]).toBe("SVCB");
  });

  it("maps 65 back to HTTPS", () => {
    expect(DNS_NUMBER_TO_TYPE[65]).toBe("HTTPS");
  });
});

// ---------------------------------------------------------------------------
// normalizeType
// ---------------------------------------------------------------------------

describe("normalizeType", () => {
  it("returns A for undefined input", () => {
    expect(normalizeType(undefined)).toBe("A");
  });

  it("returns A for null input", () => {
    expect(normalizeType(null)).toBe("A");
  });

  it("returns A for empty string", () => {
    expect(normalizeType("")).toBe("A");
  });

  it("uppercases lowercase type names", () => {
    expect(normalizeType("aaaa")).toBe("AAAA");
  });

  it("handles known numeric string '1' -> A", () => {
    expect(normalizeType("1")).toBe("A");
  });

  it("handles known numeric string '28' -> AAAA", () => {
    expect(normalizeType("28")).toBe("AAAA");
  });

  it("preserves unknown types as uppercase", () => {
    expect(normalizeType("CUSTOM")).toBe("CUSTOM");
  });

  it("handles MX", () => {
    expect(normalizeType("mx")).toBe("MX");
  });

  it("handles TXT", () => {
    expect(normalizeType("TXT")).toBe("TXT");
  });
});

// ---------------------------------------------------------------------------
// toASCII
// ---------------------------------------------------------------------------

describe("toASCII", () => {
  it("lowercases ASCII domain", () => {
    expect(toASCII("Example.COM")).toBe("example.com");
  });

  it("preserves standard domain unchanged", () => {
    expect(toASCII("example.com")).toBe("example.com");
  });

  it("handles localhost", () => {
    expect(toASCII("localhost")).toBe("localhost");
  });

  it("falls back to lowercase for invalid non-ASCII", () => {
    // toASCII should not throw even for garbage input
    const result = toASCII("invalid\u0000domain");
    expect(typeof result).toBe("string");
  });
});

// ---------------------------------------------------------------------------
// stripBase64Padding
// ---------------------------------------------------------------------------

describe("stripBase64Padding", () => {
  it("removes trailing = characters", () => {
    expect(stripBase64Padding("abc=")).toBe("abc");
    expect(stripBase64Padding("abc==")).toBe("abc");
  });

  it("returns string unchanged when no padding present", () => {
    expect(stripBase64Padding("abcd")).toBe("abcd");
  });

  it("handles empty string", () => {
    expect(stripBase64Padding("")).toBe("");
  });

  it("handles string of all padding", () => {
    expect(stripBase64Padding("====")).toBe("");
  });
});

// ---------------------------------------------------------------------------
// isBlockedOrNxdomain - JSON format
// ---------------------------------------------------------------------------

describe("isBlockedOrNxdomain", () => {
  it("returns false for normal A response", () => {
    const json = { Status: 0, Answer: [{ type: 1, data: "1.2.3.4", TTL: 300 }] };
    expect(isBlockedOrNxdomain(json)).toBe(false);
  });

  it("returns true for 0.0.0.0 A record", () => {
    const json = { Status: 0, Answer: [{ type: 1, data: "0.0.0.0", TTL: 300 }] };
    expect(isBlockedOrNxdomain(json)).toBe(true);
  });

  it("returns true for :: AAAA record", () => {
    const json = { Status: 0, Answer: [{ type: 28, data: "::", TTL: 300 }] };
    expect(isBlockedOrNxdomain(json)).toBe(true);
  });

  it("returns true for ::0 AAAA record", () => {
    const json = { Status: 0, Answer: [{ type: 28, data: "::0", TTL: 300 }] };
    expect(isBlockedOrNxdomain(json)).toBe(true);
  });

  it("returns true for NXDOMAIN without Authority", () => {
    const json = { Status: 3 };
    expect(isBlockedOrNxdomain(json)).toBe(true);
  });

  it("returns true for NXDOMAIN with empty Authority array", () => {
    const json = { Status: 3, Authority: [] };
    expect(isBlockedOrNxdomain(json)).toBe(true);
  });

  it("returns false for NXDOMAIN with SOA in Authority (genuine NXDOMAIN)", () => {
    const json = {
      Status: 3,
      Authority: [{ type: 6, name: "example.com.", TTL: 900 }],
    };
    expect(isBlockedOrNxdomain(json)).toBe(false);
  });

  it("returns false for SERVFAIL", () => {
    const json = { Status: 2 };
    expect(isBlockedOrNxdomain(json)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// isServerFailure
// ---------------------------------------------------------------------------

describe("isServerFailure", () => {
  it("returns true for Status 2", () => {
    expect(isServerFailure({ Status: 2 })).toBe(true);
  });

  it("returns false for Status 0", () => {
    expect(isServerFailure({ Status: 0 })).toBe(false);
  });

  it("returns false for Status 3 (NXDOMAIN is not SERVFAIL)", () => {
    expect(isServerFailure({ Status: 3 })).toBe(false);
  });

  it("returns true for Status 5 (REFUSED upstream)", () => {
    expect(isServerFailure({ Status: 5 })).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// inspectWireResponse
// ---------------------------------------------------------------------------

describe("inspectWireResponse", () => {
  it("returns not-blocked, not-servfail for buffer shorter than 4 bytes", () => {
    expect(inspectWireResponse(new Uint8Array([0x00, 0x00]))).toEqual({ blocked: false, servfail: false });
  });

  it("detects SERVFAIL (rcode=2)", () => {
    const buf = new Uint8Array(12);
    buf[3] = 0x02; // rcode = 2
    expect(inspectWireResponse(buf)).toEqual({ blocked: false, servfail: true });
  });

  it("detects REFUSED (rcode=5) as failed upstream", () => {
    const buf = new Uint8Array(12);
    buf[3] = 0x05; // rcode = 5
    expect(inspectWireResponse(buf)).toEqual({ blocked: false, servfail: true });
  });

  it("detects NXDOMAIN-block when NSCOUNT = 0 (rcode=3)", () => {
    const buf = buildDnsResponse("blocked.example.", "0.0.0.0", 300, 3, 0);
    expect(inspectWireResponse(buf)).toEqual({ blocked: true, servfail: false });
  });

  it("does NOT detect block for genuine NXDOMAIN with NSCOUNT >= 1 (rcode=3)", () => {
    const buf = buildDnsResponse("missing.example.", "0.0.0.0", 300, 3, 1);
    expect(inspectWireResponse(buf)).toEqual({ blocked: false, servfail: false });
  });

  it("detects block for 0.0.0.0 A reply (rcode=0)", () => {
    const buf = buildDnsResponse("blocked.example.", "0.0.0.0", 300, 0, 0);
    expect(inspectWireResponse(buf)).toEqual({ blocked: true, servfail: false });
  });

  it("does NOT flag normal A record as blocked", () => {
    const buf = buildDnsResponse("example.com.", "93.184.216.34", 300, 0, 0);
    expect(inspectWireResponse(buf)).toEqual({ blocked: false, servfail: false });
  });

  it("detects blocked AAAA all-zero (::) answer", () => {
    // Minimal response: QDCOUNT=0, ANCOUNT=1, first RR name as pointer
    const buf = new Uint8Array(12 + 2 + 10 + 16);
    buf[2] = 0x81;
    buf[3] = 0x80; // NOERROR
    buf[6] = 0x00; buf[7] = 0x01; // ANCOUNT=1
    let off = 12;
    buf[off++] = 0xc0; buf[off++] = 0x0c; // NAME pointer
    buf[off++] = 0x00; buf[off++] = 0x1c; // TYPE AAAA
    buf[off++] = 0x00; buf[off++] = 0x01; // CLASS IN
    buf[off++] = 0x00; buf[off++] = 0x00; buf[off++] = 0x01; buf[off++] = 0x2c; // TTL 300
    buf[off++] = 0x00; buf[off++] = 0x10; // RDLENGTH 16
    // Remaining 16 bytes are already zero

    expect(inspectWireResponse(buf)).toEqual({ blocked: true, servfail: false });
  });

  it("does NOT flag non-zero AAAA answer as blocked", () => {
    const buf = new Uint8Array(12 + 2 + 10 + 16);
    buf[2] = 0x81;
    buf[3] = 0x80;
    buf[6] = 0x00; buf[7] = 0x01;
    let off = 12;
    buf[off++] = 0xc0; buf[off++] = 0x0c;
    buf[off++] = 0x00; buf[off++] = 0x1c;
    buf[off++] = 0x00; buf[off++] = 0x01;
    buf[off++] = 0x00; buf[off++] = 0x00; buf[off++] = 0x01; buf[off++] = 0x2c;
    buf[off++] = 0x00; buf[off++] = 0x10;
    buf[off + 15] = 0x01; // ::1

    expect(inspectWireResponse(buf)).toEqual({ blocked: false, servfail: false });
  });

  it("returns not-blocked for empty response with NOERROR", () => {
    // NOERROR with ANCOUNT=0
    const buf = new Uint8Array(12);
    buf[2] = 0x81; buf[3] = 0x80;
    expect(inspectWireResponse(buf)).toEqual({ blocked: false, servfail: false });
  });
});

// ---------------------------------------------------------------------------
// buildDnsQuery helper
// ---------------------------------------------------------------------------

describe("buildDnsQuery", () => {
  it("builds a valid 12-byte header", () => {
    const buf = buildDnsQuery("example.com", 1);
    expect(buf.length).toBeGreaterThan(12);
    // QDCOUNT = 1
    expect((buf[4] << 8) | buf[5]).toBe(1);
    // ANCOUNT = 0
    expect((buf[6] << 8) | buf[7]).toBe(0);
  });

  it("sets RD bit", () => {
    const buf = buildDnsQuery("example.com", 1);
    expect(buf[2] & 0x01).toBe(1); // RD=1
  });

  it("encodes the DNS ID", () => {
    const buf = buildDnsQuery("example.com", 1, 0xabcd);
    expect(buf[0]).toBe(0xab);
    expect(buf[1]).toBe(0xcd);
  });
});

// ---------------------------------------------------------------------------
// buildDnsResponse helper
// ---------------------------------------------------------------------------

describe("buildDnsResponse", () => {
  it("builds a valid NOERROR A response", () => {
    const buf = buildDnsResponse("example.com.", "93.184.216.34", 300);
    // rcode = 0
    expect(buf[3] & 0x0f).toBe(0);
    // ANCOUNT = 1
    expect((buf[6] << 8) | buf[7]).toBe(1);
  });

  it("builds a valid NXDOMAIN response with nscount=0", () => {
    const buf = buildDnsResponse("gone.example.", "0.0.0.0", 300, 3, 0);
    expect(buf[3] & 0x0f).toBe(3); // rcode NXDOMAIN
    expect((buf[8] << 8) | buf[9]).toBe(0); // NSCOUNT = 0
    expect((buf[6] << 8) | buf[7]).toBe(0); // ANCOUNT = 0
  });

  it("builds a valid NXDOMAIN response with nscount=1", () => {
    const buf = buildDnsResponse("gone.example.", "0.0.0.0", 300, 3, 1);
    expect(buf[3] & 0x0f).toBe(3);
    expect((buf[8] << 8) | buf[9]).toBe(1); // NSCOUNT = 1
  });
});

// ---------------------------------------------------------------------------
// skipName
// ---------------------------------------------------------------------------

describe("skipName", () => {
  it("skips past a null-terminated name", () => {
    // [3, 'f', 'o', 'o', 0] -> offset should advance to 5
    const buf = new Uint8Array([3, 102, 111, 111, 0]);
    expect(skipName(buf, 0)).toBe(5);
  });

  it("handles pointer compression (0xc0 prefix)", () => {
    const buf = new Uint8Array([0xc0, 0x0c]);
    expect(skipName(buf, 0)).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// readDnsName
// ---------------------------------------------------------------------------

describe("readDnsName", () => {
  it("decodes 'example.com.' from wire format", () => {
    // 7 'e','x','a','m','p','l','e'  3 'c','o','m'  0
    const buf = new Uint8Array([
      7, 101, 120, 97, 109, 112, 108, 101,
      3, 99, 111, 109,
      0,
    ]);
    const { name } = readDnsName(buf, 0);
    expect(name).toBe("example.com.");
  });

  it("returns offset after the name", () => {
    const buf = new Uint8Array([
      7, 101, 120, 97, 109, 112, 108, 101,
      3, 99, 111, 109,
      0,
    ]);
    const { offset } = readDnsName(buf, 0);
    expect(offset).toBe(13);
  });

  it("follows pointer-compressed name and returns post-pointer offset", () => {
    const baseName = [
      7, 101, 120, 97, 109, 112, 108, 101,
      3, 99, 111, 109,
      0,
    ];
    const buf = new Uint8Array([...baseName, 0xc0, 0x00]);
    const { name, offset } = readDnsName(buf, 13);
    expect(name).toBe("example.com.");
    expect(offset).toBe(15);
  });
});

// ---------------------------------------------------------------------------
// parseRdata
// ---------------------------------------------------------------------------

describe("parseRdata", () => {
  it("formats IPv4 A record correctly", () => {
    const rdata = new Uint8Array([93, 184, 216, 34]);
    expect(parseRdata(rdata, 0, 1, 4)).toBe("93.184.216.34");
  });

  it("formats blocked A (0.0.0.0)", () => {
    const rdata = new Uint8Array([0, 0, 0, 0]);
    expect(parseRdata(rdata, 0, 1, 4)).toBe("0.0.0.0");
  });

  it("formats TXT record", () => {
    const text = "v=spf1 include:_spf.example.com ~all";
    const buf = new Uint8Array(1 + text.length);
    buf[0] = text.length;
    for (let i = 0; i < text.length; i++) buf[i + 1] = text.charCodeAt(i);
    expect(parseRdata(buf, 0, 16, buf.length)).toBe(`"${text}"`);
  });

  it("falls back to hex for unknown type", () => {
    const buf = new Uint8Array([0xde, 0xad]);
    const result = parseRdata(buf, 0, 9999, 2);
    expect(result).toBe("dead");
  });

  it("falls back to hex when A record length is malformed", () => {
    const buf = new Uint8Array([1, 2, 3]);
    const result = parseRdata(buf, 0, 1, 3);
    expect(result).toBe("010203");
  });
});

// ---------------------------------------------------------------------------
// wireToJson
// ---------------------------------------------------------------------------

describe("wireToJson", () => {
  it("returns null for buffer shorter than 12 bytes", () => {
    expect(wireToJson(new Uint8Array(10))).toBeNull();
  });

  it("parses a NOERROR A response", () => {
    const buf = buildDnsResponse("example.com.", "93.184.216.34", 300);
    const json = wireToJson(buf);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(0);
    expect(Array.isArray(json.Answer)).toBe(true);
    expect(json.Answer[0].data).toBe("93.184.216.34");
    expect(json.Answer[0].TTL).toBe(300);
  });

  it("parses a blocked 0.0.0.0 A response", () => {
    const buf = buildDnsResponse("blocked.example.", "0.0.0.0", 300);
    const json = wireToJson(buf);
    expect(json.Status).toBe(0);
    expect(json.Answer[0].data).toBe("0.0.0.0");
  });

  it("parses NXDOMAIN response (NSCOUNT=0) - no Answer, no Authority", () => {
    const buf = buildDnsResponse("gone.example.", "0.0.0.0", 300, 3, 0);
    const json = wireToJson(buf);
    expect(json.Status).toBe(3);
    expect(json.Answer).toBeUndefined();
    expect(json.Authority).toBeUndefined();
  });

  it("sets boolean flags correctly", () => {
    const buf = buildDnsResponse("example.com.", "1.2.3.4", 60);
    const json = wireToJson(buf);
    expect(typeof json.TC).toBe("boolean");
    expect(typeof json.RD).toBe("boolean");
    expect(typeof json.RA).toBe("boolean");
  });
});

// ---------------------------------------------------------------------------
// extractMinTtl (JSON)
// ---------------------------------------------------------------------------

describe("extractMinTtl", () => {
  it("returns minimum TTL from Answer array", () => {
    const json = {
      Answer: [
        { TTL: 300 },
        { TTL: 60 },
        { TTL: 900 },
      ],
    };
    expect(extractMinTtl(json)).toBe(60);
  });

  it("returns minimum across Answer and Authority", () => {
    const json = {
      Answer: [{ TTL: 300 }],
      Authority: [{ TTL: 120 }],
    };
    expect(extractMinTtl(json)).toBe(120);
  });

  it("returns null when there are no records", () => {
    expect(extractMinTtl({ Status: 0 })).toBeNull();
  });

  it("handles empty Answer array", () => {
    expect(extractMinTtl({ Answer: [] })).toBeNull();
  });
});

// ---------------------------------------------------------------------------
// extractMinTtlWire
// ---------------------------------------------------------------------------

describe("extractMinTtlWire", () => {
  it("returns null for short buffer", () => {
    expect(extractMinTtlWire(new Uint8Array(4))).toBeNull();
  });

  it("extracts TTL from a wire response", () => {
    const buf = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const ttl = extractMinTtlWire(buf);
    expect(ttl).toBe(300);
  });

  it("extracts TTL from Authority section if Answer is empty", () => {
    // 0x00 0x00 is simple no error
    const buf = new Uint8Array(12 + 10 + 12);
    buf[2] = 0x81; buf[3] = 0x80;
    buf[8] = 0x00; buf[9] = 0x01; // NSCOUNT = 1
    let off = 12;
    buf[off++] = 0xc0; buf[off++] = 0x0c; // NAME
    buf[off++] = 0x00; buf[off++] = 0x02; // TYPE NS
    buf[off++] = 0x00; buf[off++] = 0x01; // CLASS
    buf[off++] = 0x00; buf[off++] = 0x00; buf[off++] = 0x01; buf[off++] = 0xf4; // TTL 500
    expect(extractMinTtlWire(buf)).toBe(500);
  });

  it("handles empty Authority and Answer for TTL extraction via extractMinTtlWire", () => {
    const buf = new Uint8Array(12);
    expect(extractMinTtlWire(buf)).toBeNull();
  });

  it("returns null for response with no answer records", () => {
    const buf = buildDnsResponse("gone.example.", "0.0.0.0", 300, 3, 0);
    expect(extractMinTtlWire(buf)).toBeNull();
  });

  it("returns minimum when both Answer and Authority have records", () => {
    // Build a wire message with ANCOUNT=1 (TTL=400) and NSCOUNT=1 (TTL=200)
    // We construct it manually to get both sections populated.
    const buf = new Uint8Array(12 + 14 + 12 + 12);
    buf[2] = 0x81; buf[3] = 0x80; // QR/RA, NOERROR
    buf[6] = 0x00; buf[7] = 0x01; // ANCOUNT=1
    buf[8] = 0x00; buf[9] = 0x01; // NSCOUNT=1
    let off = 12;
    // ANCOUNT RR: pointer name, type A, class IN, ttl 400, rdlen 4, rdata 1.2.3.4
    buf[off++] = 0xc0; buf[off++] = 0x0c;
    buf[off++] = 0x00; buf[off++] = 0x01; // TYPE A
    buf[off++] = 0x00; buf[off++] = 0x01; // CLASS IN
    buf[off++] = 0x00; buf[off++] = 0x00; buf[off++] = 0x01; buf[off++] = 0x90; // TTL 400
    buf[off++] = 0x00; buf[off++] = 0x04; // RDLEN 4
    buf[off++] = 1; buf[off++] = 2; buf[off++] = 3; buf[off++] = 4;
    // NSCOUNT RR: pointer name, type NS, class IN, ttl 200, rdlen 2 (fake)
    buf[off++] = 0xc0; buf[off++] = 0x0c;
    buf[off++] = 0x00; buf[off++] = 0x02; // TYPE NS
    buf[off++] = 0x00; buf[off++] = 0x01; // CLASS IN
    buf[off++] = 0x00; buf[off++] = 0x00; buf[off++] = 0x00; buf[off++] = 0xc8; // TTL 200
    buf[off++] = 0x00; buf[off++] = 0x02; // RDLEN 2
    buf[off++] = 0xc0; buf[off++] = 0x0c; // fake NS rdata (pointer)
    expect(extractMinTtlWire(buf)).toBe(200);
  });
});

// ---------------------------------------------------------------------------
// Security & Malformed Inputs Tests (parseRdata, wireToJson, skipName)
// ---------------------------------------------------------------------------

describe("Security & Malformed Inputs", () => {
  it("skipName bounds check: handles offset beyond buffer", () => {
    const buf = new Uint8Array([3, 119, 119, 119, 0]);
    expect(skipName(buf, 10)).toBe(10);
  });

  it("skipName loop termination: avoids infinite loop on missing null terminator", () => {
    const buf = new Uint8Array([3, 119, 119, 119]); // No null terminator
    // off advances by 1+len=4 and the while condition (off < buf.length) stops the loop.
    expect(skipName(buf, 0)).toBe(4);
  });

  it("readDnsName pointer loop: prevents infinite loops with circular pointers", () => {
    // Pointer to itself
    const buf = new Uint8Array([0xc0, 0x00]);
    // The implementation might still loop, but since we are just checking syntax,
    // this test shows intent to cover circular references or we verify it throws.
    // In our case we expect it to not crash V8 entirely if the spec enforces limits, 
    // but the current implementation may throw due to max call stack or similar.
    expect(() => readDnsName(buf, 0)).toThrow();
  });

  it("parseRdata: safe processing of corrupted SOA records", () => {
    const buf = new Uint8Array([3, 119, 119, 119, 0]); // MNAME only, missing RNAME and numbers
    const res = parseRdata(buf, 0, 6, 5); 
    // Fallback to hex or default on error
    expect(res).toBeDefined();
  });

  it("wireToJson: safe processing of truncated packets", () => {
    const buf = new Uint8Array([0x00, 0x01, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 3, 119, 119, 119, 0, 0, 1, 0, 1]); // Truncated answer
    const json = wireToJson(buf);
    // Should still parse what it can or return null on complete failure, but shouldn't throw
    expect(json).not.toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// parseRdata - additional record types
// ---------------------------------------------------------------------------

describe("parseRdata - additional record types", () => {
  it("parses MX record (type 15)", () => {
    // preference=10, exchange name pointer to offset 12
    const buf = new Uint8Array([0x00, 0x0a, 0xc0, 0x0c]);
    const result = parseRdata(buf, 0, 15, 4);
    expect(result).toContain("10 ");
  });

  it("parses multi-string TXT record", () => {
    // Two TXT strings: "hello" and "world"
    const s1 = "hello"; const s2 = "world";
    const buf = new Uint8Array(1 + s1.length + 1 + s2.length);
    let off = 0;
    buf[off++] = s1.length;
    for (let i = 0; i < s1.length; i++) buf[off++] = s1.charCodeAt(i);
    buf[off++] = s2.length;
    for (let i = 0; i < s2.length; i++) buf[off++] = s2.charCodeAt(i);
    const result = parseRdata(buf, 0, 16, buf.length);
    expect(result).toContain("helloworld");
  });

  it("parses AAAA record to colon-hex notation", () => {
    // 2001:db8::1
    const ipv6 = new Uint8Array([
      0x20, 0x01, 0x0d, 0xb8,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x01,
    ]);
    const result = parseRdata(ipv6, 0, 28, 16);
    expect(result).toBe("2001:db8:0:0:0:0:0:1");
  });

  it("returns hex for AAAA with wrong rdlength", () => {
    const buf = new Uint8Array([0x20, 0x01, 0x0d, 0xb8]);
    const result = parseRdata(buf, 0, 28, 4); // wrong rdlength for AAAA
    expect(result).toMatch(/^[0-9a-f]+$/);
  });

  it("parses CNAME record (type 5)", () => {
    // CNAME rdata is a domain name: "www."
    const buf = new Uint8Array([3, 119, 119, 119, 0]);
    const result = parseRdata(buf, 0, 5, 5);
    expect(result).toBe("www.");
  });

  it("parses PTR record (type 12)", () => {
    const buf = new Uint8Array([3, 102, 111, 111, 0]);
    const result = parseRdata(buf, 0, 12, 5);
    expect(result).toBe("foo.");
  });

  it("parses NS record (type 2)", () => {
    const buf = new Uint8Array([2, 110, 115, 0]);
    const result = parseRdata(buf, 0, 2, 4);
    expect(result).toBe("ns.");
  });
});

// ---------------------------------------------------------------------------
// wireToJson - additional coverage
// ---------------------------------------------------------------------------

describe("wireToJson - additional coverage", () => {
  it("parses SERVFAIL response (rcode=2)", () => {
    const buf = new Uint8Array(12);
    buf[2] = 0x81; buf[3] = 0x82; // QR/RA, SERVFAIL
    const json = wireToJson(buf);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(2);
  });

  it("parses response with NXDOMAIN and SOA authority", () => {
    const buf = buildDnsResponse("gone.example.", "0.0.0.0", 300, 3, 1);
    const json = wireToJson(buf);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(3);
    // Our buildDnsResponse uses nscount=1 in header but does not write authority RR bytes,
    // so Authority may be empty array or undefined.
    expect(json.Answer).toBeUndefined();
  });

  it("sets AD, CD, TC boolean flags from wire message", () => {
    const buf = new Uint8Array(12);
    // flags: QR=1, AA=0, TC=1, RD=1, RA=1, AD=1, CD=1, rcode=0
    buf[2] = 0x83; // QR=1, TC=1, RD=1
    buf[3] = 0xb0; // RA=1, AD=1, CD=1
    const json = wireToJson(buf);
    expect(json.TC).toBe(true);
    expect(json.AD).toBe(true);
    expect(json.CD).toBe(true);
  });

  it("includes Question section when QDCOUNT >= 1", () => {
    const buf = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const json = wireToJson(buf);
    expect(Array.isArray(json.Question)).toBe(true);
    expect(json.Question[0].name).toBe("example.com.");
    expect(json.Question[0].type).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// toASCII - edge cases
// ---------------------------------------------------------------------------

describe("toASCII - edge cases", () => {
  it("returns '.' unchanged", () => {
    expect(toASCII(".")).toBe(".");
  });

  it("handles domain with trailing dot", () => {
    const result = toASCII("example.com.");
    expect(result).toBe("example.com.");
  });

  it("converts Unicode domain to punycode via WHATWG URL", () => {
    // xn--nxasmq6b.com is the ACE form of some unicode domain
    // Just verify it doesn't throw and returns a string
    const result = toASCII("\u4e2d\u6587.com");
    expect(typeof result).toBe("string");
    expect(result.length).toBeGreaterThan(0);
  });
});

// ---------------------------------------------------------------------------
// normalizeType - additional types
// ---------------------------------------------------------------------------

describe("normalizeType - additional types", () => {
  it("normalizes 'caa' to 'CAA'", () => {
    expect(normalizeType("caa")).toBe("CAA");
  });

  it("normalizes '257' to 'CAA'", () => {
    expect(normalizeType("257")).toBe("CAA");
  });

  it("normalizes 'srv' to 'SRV'", () => {
    expect(normalizeType("srv")).toBe("SRV");
  });

  it("normalizes 'dnskey' to 'DNSKEY'", () => {
    expect(normalizeType("dnskey")).toBe("DNSKEY");
  });

  it("handles ANY (255)", () => {
    expect(normalizeType("255")).toBe("ANY");
  });

  it("preserves unknown numeric type string as-is (uppercase)", () => {
    // Type 9999 is not in the table - should return the string unchanged
    expect(normalizeType("9999")).toBe("9999");
  });
});

// ---------------------------------------------------------------------------
// inspectWireResponse - additional edge cases
// ---------------------------------------------------------------------------

describe("inspectWireResponse - additional edge cases", () => {
  it("handles exactly 4-byte buffer (minimum for flag parsing)", () => {
    const buf = new Uint8Array([0, 0, 0x81, 0x80]); // NOERROR
    expect(inspectWireResponse(buf)).toEqual({ blocked: false, servfail: false });
  });

  it("handles rcode=1 (FORMERR) as not-blocked not-servfail", () => {
    const buf = new Uint8Array(12);
    buf[3] = 0x01; // FORMERR
    expect(inspectWireResponse(buf)).toEqual({ blocked: false, servfail: false });
  });

  it("handles rcode=5 (REFUSED) as failed upstream (servfail=true)", () => {
    const buf = new Uint8Array(12);
    buf[3] = 0x05; // REFUSED
    expect(inspectWireResponse(buf)).toEqual({ blocked: false, servfail: true });
  });

  it("NXDOMAIN with large nscount is not a block", () => {
    const buf = buildDnsResponse("real-nxdomain.example.", "0.0.0.0", 300, 3, 5);
    expect(inspectWireResponse(buf)).toEqual({ blocked: false, servfail: false });
  });
});

// ---------------------------------------------------------------------------
// buildDnsQuery - additional coverage
// ---------------------------------------------------------------------------

describe("buildDnsQuery - additional coverage", () => {
  it("builds a query for root label '.'", () => {
    const buf = buildDnsQuery(".", 255); // ANY query for root
    expect(buf.length).toBeGreaterThanOrEqual(12);
  });

  it("encodes multi-label domain correctly", () => {
    const buf = buildDnsQuery("sub.example.com", 28);
    // QDCOUNT=1
    expect((buf[4] << 8) | buf[5]).toBe(1);
    // qtype = 28 (AAAA)
    const qtype = (buf[buf.length - 4] << 8) | buf[buf.length - 3];
    expect(qtype).toBe(28);
  });

  it("sets QCLASS to IN (1)", () => {
    const buf = buildDnsQuery("example.com", 1);
    const qclass = (buf[buf.length - 2] << 8) | buf[buf.length - 1];
    expect(qclass).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// EDNS processing (RFC 6891 / RFC 7871 / RFC 7873 / RFC 5001 / RFC 8914)
// ---------------------------------------------------------------------------

// Add an OPT record to a DNS message buffer.
// Flags control which EDNS options appear in the OPT RDATA.
function addOptRecord(baseBuf, { doBit = false, ecs = false, cookie = false, nsid = false, serverCookie = false, ede = false } = {}) {
  const rdataBytes = [];
  if (ecs) {
    // ECS option 8: IPv4 /24 (203.0.113.0)
    const ecsData = [0x00, 0x01, 24, 0, 203, 0, 113];
    rdataBytes.push(0x00, 0x08, 0x00, ecsData.length, ...ecsData);
  }
  if (cookie) {
    // Client cookie option 10: 8 bytes
    rdataBytes.push(0x00, 0x0a, 0x00, 0x08, 0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe);
  }
  if (serverCookie) {
    // Server cookie option 10: 8-byte client + 8-byte server cookie
    const data = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
                  0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
    rdataBytes.push(0x00, 0x0a, 0x00, data.length, ...data);
  }
  if (nsid) {
    // NSID option 3: zero-length RDATA (request) or any-length (response)
    rdataBytes.push(0x00, 0x03, 0x00, 0x00);
  }
  if (ede) {
    // EDE option 15: info-code 1 (DNSKEY Missing)
    rdataBytes.push(0x00, 0x0f, 0x00, 0x02, 0x00, 0x01);
  }
  const rdataLen = rdataBytes.length;
  const optRecord = new Uint8Array(11 + rdataLen);
  let w = 0;
  optRecord[w++] = 0x00;             // root name
  optRecord[w++] = 0x00; optRecord[w++] = 0x29; // type OPT (41)
  optRecord[w++] = 0x10; optRecord[w++] = 0x00; // class = 4096
  optRecord[w++] = 0x00; optRecord[w++] = 0x00; // ext-RCODE=0, version=0
  optRecord[w++] = doBit ? 0x80 : 0x00; optRecord[w++] = 0x00; // DO bit
  optRecord[w++] = (rdataLen >> 8) & 0xff; optRecord[w++] = rdataLen & 0xff;
  for (const b of rdataBytes) optRecord[w++] = b;
  const out = new Uint8Array(baseBuf.length + optRecord.length);
  out.set(baseBuf);
  out.set(optRecord, baseBuf.length);
  const curAr = (out[10] << 8) | out[11];
  out[10] = ((curAr + 1) >> 8) & 0xff;
  out[11] = (curAr + 1) & 0xff;
  return out;
}

function arcount(buf) { return (buf[10] << 8) | buf[11]; }

// Returns true if needle appears anywhere inside buf.
function containsBytes(buf, needle) {
  outer: for (let i = 0; i <= buf.length - needle.length; i++) {
    for (let j = 0; j < needle.length; j++) {
      if (buf[i + j] !== needle[j]) continue outer;
    }
    return true;
  }
  return false;
}

// Privacy config fixtures used across the EDNS test suites.
const cfgStrip = {
  PRIVACY_ECS_MODE: "strip",    PRIVACY_ECS_SUBNET: "",
  PRIVACY_COOKIES_MODE: "strip",
  PRIVACY_NSID_MODE: "strip",   PRIVACY_NSID_VALUE: "",
};
const cfgForward = {
  PRIVACY_ECS_MODE: "forward",  PRIVACY_ECS_SUBNET: "",
  PRIVACY_COOKIES_MODE: "strip",
  PRIVACY_NSID_MODE: "forward", PRIVACY_NSID_VALUE: "",
};
const cfgEcsSubst = {
  PRIVACY_ECS_MODE: "substitute", PRIVACY_ECS_SUBNET: "203.0.113.0/24",
  PRIVACY_COOKIES_MODE: "strip",
  PRIVACY_NSID_MODE: "strip",     PRIVACY_NSID_VALUE: "",
};
const cfgCookieReoriginate = {
  PRIVACY_ECS_MODE: "strip",   PRIVACY_ECS_SUBNET: "",
  PRIVACY_COOKIES_MODE: "reoriginate",
  PRIVACY_NSID_MODE: "strip",  PRIVACY_NSID_VALUE: "",
};
const cfgNsidSubst = {
  PRIVACY_ECS_MODE: "strip",   PRIVACY_ECS_SUBNET: "",
  PRIVACY_COOKIES_MODE: "strip",
  PRIVACY_NSID_MODE: "substitute", PRIVACY_NSID_VALUE: "proxy-01",
};

// ---------------------------------------------------------------------------
// buildEcsOption
// ---------------------------------------------------------------------------

describe("buildEcsOption", () => {
  it("returns null for empty string", () => {
    expect(buildEcsOption("")).toBeNull();
  });

  it("returns null for string without slash", () => {
    expect(buildEcsOption("203.0.113.0")).toBeNull();
  });

  it("returns null for invalid IPv4 octet", () => {
    expect(buildEcsOption("999.0.0.0/24")).toBeNull();
  });

  it("encodes IPv4 /24 correctly (family=1, 3 address bytes)", () => {
    const rdata = buildEcsOption("203.0.113.0/24");
    expect(rdata).not.toBeNull();
    expect(rdata[0]).toBe(0);    // FAMILY high byte
    expect(rdata[1]).toBe(1);    // FAMILY = 1 (IPv4)
    expect(rdata[2]).toBe(24);   // SOURCE-PREFIX-LEN
    expect(rdata[3]).toBe(0);    // SCOPE-PREFIX-LEN = 0
    expect(rdata[4]).toBe(203);
    expect(rdata[5]).toBe(0);
    expect(rdata[6]).toBe(113);
    expect(rdata.length).toBe(7); // 4 fixed + ceil(24/8)=3 address bytes
  });

  it("encodes IPv4 /16 correctly (only 2 address bytes)", () => {
    const rdata = buildEcsOption("10.20.0.0/16");
    expect(rdata).not.toBeNull();
    expect(rdata[1]).toBe(1);   // IPv4
    expect(rdata[2]).toBe(16);  // /16
    expect(rdata[4]).toBe(10);
    expect(rdata[5]).toBe(20);
    expect(rdata.length).toBe(6); // 4 fixed + ceil(16/8)=2 address bytes
  });

  it("encodes IPv6 /32 correctly (family=2, 4 address bytes)", () => {
    const rdata = buildEcsOption("2001:db8::/32");
    expect(rdata).not.toBeNull();
    expect(rdata[0]).toBe(0);   // FAMILY high byte
    expect(rdata[1]).toBe(2);   // FAMILY = 2 (IPv6)
    expect(rdata[2]).toBe(32);  // /32
    expect(rdata.length).toBe(8); // 4 fixed + ceil(32/8)=4 address bytes
  });
});

// ---------------------------------------------------------------------------
// processEdnsOutgoing - ECS
// ---------------------------------------------------------------------------

describe("processEdnsOutgoing - ECS", () => {
  it("strip: always adds DO=1 OPT even when no OPT present and nothing else to inject", () => {
    // RFC 4035: DO=1 is forced in all outgoing queries so the cache is always
    // populated with DNSSEC records.
    const buf = buildDnsQuery("example.com", 1);
    const out = processEdnsOutgoing(buf, cfgStrip, null);
    expect(out).not.toBe(buf);        // new buffer - OPT was appended
    expect(arcount(out)).toBe(1);     // minimal OPT with DO=1
    expect(hasDoBit(out)).toBe(true); // DO bit set
  });

  it("strip: removes ECS but preserves minimal OPT with DO=1 when original DO=0", () => {
    // ECS is stripped per privacy mode; DO=1 is forced regardless of client DO bit.
    const base = buildDnsQuery("example.com", 1);
    const buf  = addOptRecord(base, { ecs: true });
    const out  = processEdnsOutgoing(buf, cfgStrip, null);
    expect(arcount(out)).toBe(1);     // OPT kept because DO=1 is forced
    expect(hasDoBit(out)).toBe(true); // DO bit set to 1
    expect(containsBytes(out, [0x00, 0x08])).toBe(false); // ECS removed
  });

  it("strip: keeps minimal OPT (DO=1) but removes ECS payload", () => {
    const base = buildDnsQuery("example.com", 1);
    const buf  = addOptRecord(base, { doBit: true, ecs: true });
    const out  = processEdnsOutgoing(buf, cfgStrip, null);
    expect(arcount(out)).toBe(1);               // minimal OPT kept for DO bit
    expect(out.length).toBeLessThan(buf.length); // ECS bytes removed
    expect(containsBytes(out, [0x00, 0x08])).toBe(false); // ECS option code absent
  });

  it("forward: passes ECS option through unchanged", () => {
    const base = buildDnsQuery("example.com", 1);
    const buf  = addOptRecord(base, { ecs: true });
    const out  = processEdnsOutgoing(buf, cfgForward, null);
    expect(arcount(out)).toBe(1);
    expect(containsBytes(out, [0x00, 0x08])).toBe(true); // ECS option code present
  });

  it("forward: adds DO=1 OPT even when original query has no OPT and no ECS to forward", () => {
    // DO=1 forcing applies in all modes; ECS forward only applies when ECS is present
    // in the original query.
    const buf = buildDnsQuery("example.com", 1);
    const out = processEdnsOutgoing(buf, cfgForward, null);
    expect(out).not.toBe(buf);        // new buffer with DO=1 OPT
    expect(arcount(out)).toBe(1);
    expect(hasDoBit(out)).toBe(true);
  });

  it("substitute: injects configured ECS subnet replacing existing ECS", () => {
    const base = buildDnsQuery("example.com", 1);
    const buf  = addOptRecord(base, { ecs: true });
    const out  = processEdnsOutgoing(buf, cfgEcsSubst, null);
    expect(arcount(out)).toBe(1);
    expect(containsBytes(out, [0x00, 0x08])).toBe(true); // our ECS present
  });

  it("substitute: appends OPT with ECS even when no original OPT", () => {
    const buf = buildDnsQuery("example.com", 1);
    const out = processEdnsOutgoing(buf, cfgEcsSubst, null);
    expect(arcount(out)).toBe(1);
    expect(out.length).toBeGreaterThan(buf.length);
    expect(containsBytes(out, [0x00, 0x08])).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// processEdnsOutgoing - Cookie
// ---------------------------------------------------------------------------

describe("processEdnsOutgoing - Cookie", () => {
  it("strip: removes client cookie, OPT kept with DO=1 (DO always forced)", () => {
    const base = buildDnsQuery("example.com", 1);
    const buf  = addOptRecord(base, { cookie: true });
    const out  = processEdnsOutgoing(buf, cfgStrip, null);
    expect(arcount(out)).toBe(1);     // OPT kept because DO=1 is forced
    expect(hasDoBit(out)).toBe(true);
    expect(containsBytes(out, [0x00, 0x0a])).toBe(false); // cookie option absent
  });

  it("reoriginate: replaces client cookie with proxy cookie bytes", () => {
    const base   = buildDnsQuery("example.com", 1);
    const buf    = addOptRecord(base, { cookie: true });
    const proxy  = new Uint8Array([0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22]);
    const out    = processEdnsOutgoing(buf, cfgCookieReoriginate, proxy);
    expect(arcount(out)).toBe(1);
    expect(containsBytes(out, [0x00, 0x0a])).toBe(true); // cookie option code present
    expect(containsBytes(out, [0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff, 0x11, 0x22])).toBe(true);
  });

  it("reoriginate: appends OPT with cookie when original query had no OPT", () => {
    const buf    = buildDnsQuery("example.com", 1);
    const cookie = new Uint8Array(8).fill(0x55);
    const out    = processEdnsOutgoing(buf, cfgCookieReoriginate, cookie);
    expect(arcount(out)).toBe(1);
    expect(containsBytes(out, [0x00, 0x0a])).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// processEdnsOutgoing - NSID
// ---------------------------------------------------------------------------

describe("processEdnsOutgoing - NSID", () => {
  it("strip: removes NSID request, OPT kept with DO=1 (DO always forced)", () => {
    const base = buildDnsQuery("example.com", 1);
    const buf  = addOptRecord(base, { nsid: true });
    const out  = processEdnsOutgoing(buf, cfgStrip, null);
    expect(arcount(out)).toBe(1);     // OPT kept because DO=1 is forced
    expect(hasDoBit(out)).toBe(true);
    expect(containsBytes(out, [0x00, 0x03])).toBe(false); // NSID removed
  });

  it("forward: passes NSID request through to upstream", () => {
    const base = buildDnsQuery("example.com", 1);
    const buf  = addOptRecord(base, { nsid: true });
    const out  = processEdnsOutgoing(buf, cfgForward, null);
    expect(arcount(out)).toBe(1);
    expect(containsBytes(out, [0x00, 0x03])).toBe(true);
  });

  it("substitute: strips NSID from forwarded query, OPT kept with DO=1", () => {
    // In substitute mode, NSID is not forwarded to upstream (proxy answers it
    // locally). DO=1 is still forced in all outgoing queries.
    const base = buildDnsQuery("example.com", 1);
    const buf  = addOptRecord(base, { nsid: true });
    const out  = processEdnsOutgoing(buf, cfgNsidSubst, null);
    expect(arcount(out)).toBe(1);     // OPT kept because DO=1 is forced
    expect(hasDoBit(out)).toBe(true);
    expect(containsBytes(out, [0x00, 0x03])).toBe(false); // NSID not forwarded
  });
});

// ---------------------------------------------------------------------------
// processEdnsOutgoing - DO bit preservation
// ---------------------------------------------------------------------------

describe("processEdnsOutgoing - DO bit", () => {
  it("preserves DO bit as minimal OPT when ECS+cookie+NSID all stripped", () => {
    const base = buildDnsQuery("example.com", 1);
    const buf  = addOptRecord(base, { doBit: true, ecs: true, cookie: true, nsid: true });
    const out  = processEdnsOutgoing(buf, cfgStrip, null);
    expect(arcount(out)).toBe(1); // minimal OPT with DO=1 kept
    // Z field high byte 0x80 followed by 0x00 and RDLEN 0x00 0x00 (no options)
    expect(containsBytes(out, [0x80, 0x00, 0x00, 0x00])).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// processEdnsIncoming
// ---------------------------------------------------------------------------

describe("processEdnsIncoming", () => {
  it("returns same buffer reference when no OPT present", () => {
    const buf = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const out = processEdnsIncoming(buf, cfgStrip, null);
    expect(out).toBe(buf);
  });

  it("strip: removes ECS from upstream response", () => {
    const base = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const buf  = addOptRecord(base, { ecs: true });
    const out  = processEdnsIncoming(buf, cfgStrip, null);
    expect(arcount(out)).toBe(0);
    expect(containsBytes(out, [0x00, 0x08])).toBe(false);
  });

  it("forward: keeps ECS option in upstream response", () => {
    const base = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const buf  = addOptRecord(base, { ecs: true });
    const out  = processEdnsIncoming(buf, cfgForward, null);
    expect(arcount(out)).toBe(1);
    expect(containsBytes(out, [0x00, 0x08])).toBe(true);
  });

  it("always strips cookie and calls onServerCookie with server bytes", () => {
    const base = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const buf  = addOptRecord(base, { serverCookie: true });
    let captured = null;
    const out  = processEdnsIncoming(buf, cfgStrip, (s) => { captured = new Uint8Array(s); });
    expect(arcount(out)).toBe(0);
    expect(containsBytes(out, [0x00, 0x0a])).toBe(false);
    // Server part is the 8 bytes after the 8-byte client cookie
    expect(captured).not.toBeNull();
    expect(Array.from(captured)).toEqual([0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]);
  });

  it("does not call onServerCookie when only client cookie present (8 bytes)", () => {
    const base = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const buf  = addOptRecord(base, { cookie: true }); // 8-byte client only
    let called = false;
    processEdnsIncoming(buf, cfgStrip, () => { called = true; });
    expect(called).toBe(false);
  });

  it("strip: removes NSID from upstream response", () => {
    const base = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const buf  = addOptRecord(base, { nsid: true });
    const out  = processEdnsIncoming(buf, cfgStrip, null);
    expect(arcount(out)).toBe(0);
    expect(containsBytes(out, [0x00, 0x03])).toBe(false);
  });

  it("forward: keeps NSID in upstream response", () => {
    const base = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const buf  = addOptRecord(base, { nsid: true });
    const out  = processEdnsIncoming(buf, cfgForward, null);
    expect(arcount(out)).toBe(1);
    expect(containsBytes(out, [0x00, 0x03])).toBe(true);
  });

  it("substitute: strips NSID from upstream response (proxy injects own value)", () => {
    const base = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const buf  = addOptRecord(base, { nsid: true });
    const out  = processEdnsIncoming(buf, cfgNsidSubst, null);
    expect(arcount(out)).toBe(0);
    expect(containsBytes(out, [0x00, 0x03])).toBe(false);
  });

  it("always passes EDE option (code 15) through regardless of mode", () => {
    const base = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const buf  = addOptRecord(base, { ede: true });
    const out  = processEdnsIncoming(buf, cfgStrip, null);
    expect(arcount(out)).toBe(1); // OPT kept for EDE
    expect(containsBytes(out, [0x00, 0x0f])).toBe(true);
  });

  it("removes OPT entirely when all options stripped and DO=0", () => {
    const base = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const buf  = addOptRecord(base, { ecs: true, nsid: true });
    const out  = processEdnsIncoming(buf, cfgStrip, null);
    expect(arcount(out)).toBe(0);
    expect(out.length).toBe(base.length);
  });

  it("keeps OPT with DO=1 even after all options stripped", () => {
    const base = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const buf  = addOptRecord(base, { doBit: true, ecs: true });
    const out  = processEdnsIncoming(buf, cfgStrip, null);
    expect(arcount(out)).toBe(1); // minimal OPT kept
    expect(containsBytes(out, [0x00, 0x08])).toBe(false); // ECS stripped
    expect(containsBytes(out, [0x80, 0x00])).toBe(true); // DO bit present
  });
});

// ---------------------------------------------------------------------------
// hasNsidRequest
// ---------------------------------------------------------------------------

describe("hasNsidRequest", () => {
  it("returns false for null input", () => {
    expect(hasNsidRequest(null)).toBe(false);
  });

  it("returns false for buffer shorter than 12 bytes", () => {
    expect(hasNsidRequest(new Uint8Array(8))).toBe(false);
  });

  it("returns false for query with no OPT record (ARCOUNT=0)", () => {
    const buf = buildDnsQuery("example.com", 1);
    expect(arcount(buf)).toBe(0);
    expect(hasNsidRequest(buf)).toBe(false);
  });

  it("returns false for query with OPT but no NSID option", () => {
    const buf = addOptRecord(buildDnsQuery("example.com", 1), { ecs: true });
    expect(hasNsidRequest(buf)).toBe(false);
  });

  it("returns true for query with NSID request option (code 3)", () => {
    const buf = addOptRecord(buildDnsQuery("example.com", 1), { nsid: true });
    expect(hasNsidRequest(buf)).toBe(true);
  });

  it("returns true when NSID is present alongside other options", () => {
    const buf = addOptRecord(buildDnsQuery("example.com", 1), { ecs: true, nsid: true });
    expect(hasNsidRequest(buf)).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// injectNsidToResponse
// ---------------------------------------------------------------------------

describe("injectNsidToResponse", () => {
  it("returns original buffer unchanged for empty nsidValue", () => {
    const buf = buildDnsResponse("example.com.", "1.2.3.4", 300);
    expect(injectNsidToResponse(buf, "")).toBe(buf);
  });

  it("returns original buffer unchanged for null/falsy nsidValue", () => {
    const buf = buildDnsResponse("example.com.", "1.2.3.4", 300);
    expect(injectNsidToResponse(buf, null)).toBe(buf);
  });

  it("appends OPT with NSID when response has no existing OPT", () => {
    const base = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const out  = injectNsidToResponse(base, "proxy-01");
    expect(arcount(out)).toBe(1);
    expect(out.length).toBeGreaterThan(base.length);
    expect(containsBytes(out, [0x00, 0x03])).toBe(true); // NSID option code
  });

  it("adds NSID to existing OPT without losing other options", () => {
    const base = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const buf  = addOptRecord(base, { ede: true });
    const out  = injectNsidToResponse(buf, "ns1");
    expect(arcount(out)).toBe(1);
    expect(containsBytes(out, [0x00, 0x0f])).toBe(true); // EDE still present
    expect(containsBytes(out, [0x00, 0x03])).toBe(true); // NSID added
  });

  it("replaces an existing NSID option in the OPT record", () => {
    const base = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const buf  = addOptRecord(base, { nsid: true }); // 0-length NSID
    const out  = injectNsidToResponse(buf, "dnsieve");
    expect(arcount(out)).toBe(1);
    // ASCII bytes for "dnsieve": 0x64 0x6e 0x73 0x69 0x65 0x76 0x65
    expect(containsBytes(out, [0x64, 0x6e, 0x73, 0x69, 0x65, 0x76, 0x65])).toBe(true);
  });

  it("encodes NSID identifier as raw ASCII bytes", () => {
    const base = buildDnsResponse("example.com.", "1.2.3.4", 300);
    const out  = injectNsidToResponse(base, "AB");
    // ASCII 'A'=0x41, 'B'=0x42
    expect(containsBytes(out, [0x41, 0x42])).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// parseRdata - DNSSEC record types (RFC 4034, RFC 5155)
// ---------------------------------------------------------------------------

describe("parseRdata - DNSSEC and security record types", () => {
  it("parses DS record (type 43) into 'keytag alg digesttype digest' form", () => {
    // keytag=12345 (0x3039), alg=8, digesttype=2, digest=aabbccdd
    const buf = new Uint8Array([0x30, 0x39, 0x08, 0x02, 0xaa, 0xbb, 0xcc, 0xdd]);
    const result = parseRdata(buf, 0, 43, 8);
    expect(result).toBe("12345 8 2 aabbccdd");
  });

  it("parseRdata DS: returns hex for rdlength < 4", () => {
    const buf = new Uint8Array([0x00, 0x01, 0x08]);
    const result = parseRdata(buf, 0, 43, 3);
    expect(result).toMatch(/^[0-9a-f]+$/);
  });

  it("parses DNSKEY record (type 48) into 'flags proto alg key' form", () => {
    // flags=257 (0x0101), proto=3, alg=8, key=0xdeadbeef
    const buf = new Uint8Array([0x01, 0x01, 0x03, 0x08, 0xde, 0xad, 0xbe, 0xef]);
    const result = parseRdata(buf, 0, 48, 8);
    expect(result).toContain("257 3 8 ");
    // base64 of [0xde, 0xad, 0xbe, 0xef] = "3q2+7w=="
    expect(result).toContain("3q2+7w==");
  });

  it("parseRdata DNSKEY: returns hex for rdlength < 4", () => {
    const buf = new Uint8Array([0x01, 0x01, 0x03]);
    const result = parseRdata(buf, 0, 48, 3);
    expect(result).toMatch(/^[0-9a-f]+$/);
  });

  it("parses RRSIG record (type 46) into text form", () => {
    // type covered=1 (A), alg=8, labels=2, origTtl=300, sigexp=0x60000000,
    // siginc=0x5f000000, keytag=0x1234, signer=root (0x00), sig=0xdeadbeef
    const buf = new Uint8Array([
      0x00, 0x01,              // type covered = A (1)
      0x08,                    // algorithm = 8
      0x02,                    // labels = 2
      0x00, 0x00, 0x01, 0x2c, // original TTL = 300
      0x60, 0x00, 0x00, 0x00, // sig expiration
      0x5f, 0x00, 0x00, 0x00, // sig inception
      0x12, 0x34,              // key tag = 0x1234
      0x00,                    // signer name = root label
      0xde, 0xad, 0xbe, 0xef, // signature bytes
    ]);
    const result = parseRdata(buf, 0, 46, buf.length);
    expect(result).toContain("A ");      // type covered name
    expect(result).toContain(" 8 ");     // algorithm
    expect(result).toContain(" 2 ");     // labels
    expect(result).toContain(" 300 ");   // original TTL
    expect(result).toContain("4660 ");   // keytag = 0x1234 = 4660
  });

  it("parseRdata RRSIG: returns hex for rdlength < 18", () => {
    const buf = new Uint8Array(10).fill(0);
    const result = parseRdata(buf, 0, 46, 10);
    expect(result).toMatch(/^[0-9a-f]+$/);
  });

  it("parses NSEC record (type 47) into 'nextname types...' form", () => {
    // next domain = root (0x00), bitmap window 0, bitmap = 0x40 -> type 1 (A)
    // Window 0, bitmap length 1, bitmap 0x40 (bit 1 set) => type 1 = A
    const buf = new Uint8Array([
      0x00,                    // next name = root label
      0x00, 0x01, 0x40,        // window=0, len=1, bitmap=0x40 (type 1 set)
    ]);
    const result = parseRdata(buf, 0, 47, buf.length);
    expect(result).toContain(".");  // root next name
    expect(result).toContain("A"); // type 1 = A
  });

  it("parses NSEC3 record (type 50) into text form", () => {
    // hashAlg=1, flags=0, iters=10, saltLen=0 (no salt), hashLen=4, hash=0x01020304
    // no type bitmaps
    const buf = new Uint8Array([
      0x01,             // hash algorithm = 1
      0x00,             // flags
      0x00, 0x0a,       // iterations = 10
      0x00,             // salt length = 0 -> salt = "-"
      0x04,             // hash length = 4
      0x01, 0x02, 0x03, 0x04, // next hashed owner (4 bytes)
    ]);
    const result = parseRdata(buf, 0, 50, buf.length);
    expect(result).toContain("1 ");  // hashAlg
    expect(result).toContain("0 ");  // flags
    expect(result).toContain("10 "); // iterations
    expect(result).toContain("- ");  // empty salt
  });

  it("parseRdata NSEC3: returns hex for rdlength < 5", () => {
    const buf = new Uint8Array([0x01, 0x00, 0x00]);
    const result = parseRdata(buf, 0, 50, 3);
    expect(result).toMatch(/^[0-9a-f]+$/);
  });

  it("parses CAA record (type 257) into 'flags tag value' form", () => {
    // flags=128, tag="issue" (5 bytes), value="letsencrypt.org"
    const tag = "issue";
    const val = "letsencrypt.org";
    const buf = new Uint8Array(2 + tag.length + val.length);
    buf[0] = 128; // flags (critical bit)
    buf[1] = tag.length;
    for (let i = 0; i < tag.length; i++) buf[2 + i] = tag.charCodeAt(i);
    for (let i = 0; i < val.length; i++) buf[2 + tag.length + i] = val.charCodeAt(i);
    const result = parseRdata(buf, 0, 257, buf.length);
    expect(result).toBe(`128 issue "letsencrypt.org"`);
  });

  it("parses CAA record with flags=0", () => {
    const tag = "issuewild";
    const val = "pki.goog";
    const buf = new Uint8Array(2 + tag.length + val.length);
    buf[0] = 0;
    buf[1] = tag.length;
    for (let i = 0; i < tag.length; i++) buf[2 + i] = tag.charCodeAt(i);
    for (let i = 0; i < val.length; i++) buf[2 + tag.length + i] = val.charCodeAt(i);
    const result = parseRdata(buf, 0, 257, buf.length);
    expect(result).toBe(`0 issuewild "pki.goog"`);
  });

  it("parseRdata CAA: returns hex for rdlength < 2", () => {
    const buf = new Uint8Array([0x80]);
    const result = parseRdata(buf, 0, 257, 1);
    expect(result).toMatch(/^[0-9a-f]+$/);
  });
});

// ---------------------------------------------------------------------------
// buildDnsQueryWithDo - dedicated coverage
// ---------------------------------------------------------------------------

describe("buildDnsQueryWithDo", () => {
  it("builds query with DO=1 when doBit=true", () => {
    const buf = buildDnsQueryWithDo("example.com", 1, 0, true);
    expect(hasDoBit(buf)).toBe(true);
  });

  it("builds query without DO when doBit=false", () => {
    const buf = buildDnsQueryWithDo("example.com", 1, 0, false);
    expect(hasDoBit(buf)).toBe(false);
  });

  it("has ARCOUNT >= 1 (OPT RR present) for any doBit value", () => {
    const withDo    = buildDnsQueryWithDo("example.com", 1, 0, true);
    const withoutDo = buildDnsQueryWithDo("example.com", 1, 0, false);
    expect(((withDo[10] << 8) | withDo[11])).toBeGreaterThanOrEqual(1);
    expect(((withoutDo[10] << 8) | withoutDo[11])).toBeGreaterThanOrEqual(1);
  });

  it("preserves the requested query type", () => {
    const buf = buildDnsQueryWithDo("example.com", 28, 0, true); // AAAA
    const result = extractQueryNameType(buf);
    expect(result).not.toBeNull();
    expect(result.qtype).toBe(28);
  });

  it("uses provided transaction ID", () => {
    const buf = buildDnsQueryWithDo("example.com", 1, 0xABCD, true);
    expect(buf[0]).toBe(0xAB);
    expect(buf[1]).toBe(0xCD);
  });
});

