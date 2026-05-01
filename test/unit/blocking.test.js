// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/unit/blocking.test.js
// Unit tests for blocking response builders and EDE injection

import { describe, it, expect } from "vitest";
import {
  buildBlockedResponse,
  buildEdeOption,
  injectEdeToResponse,
  buildDnsQuery,
  buildDnsResponse,
  wireToJson,
  extractQueryNameType,
  inspectWireResponse,
  DNS_TYPE_TO_NUMBER,
} from "../../src/dns.js";

// ---------------------------------------------------------------------------
// buildEdeOption
// ---------------------------------------------------------------------------

describe("buildEdeOption", () => {
  it("builds EDE with info-code 15 (Blocked) and no text", () => {
    const opt = buildEdeOption(15);
    expect(opt.code).toBe(15);
    expect(opt.data.length).toBe(2);
    expect((opt.data[0] << 8) | opt.data[1]).toBe(15);
  });

  it("builds EDE with info-code and extra text", () => {
    const opt = buildEdeOption(15, "Blocked by resolver");
    expect(opt.code).toBe(15);
    // 2 bytes info-code + text bytes
    expect(opt.data.length).toBe(2 + "Blocked by resolver".length);
    expect((opt.data[0] << 8) | opt.data[1]).toBe(15);
  });

  it("encodes extra text as UTF-8", () => {
    const opt = buildEdeOption(15, "test");
    const textBytes = opt.data.subarray(2);
    expect(new TextDecoder().decode(textBytes)).toBe("test");
  });
});

// ---------------------------------------------------------------------------
// injectEdeToResponse
// ---------------------------------------------------------------------------

describe("injectEdeToResponse", () => {
  it("appends EDE to a response without OPT", () => {
    const resp = buildDnsResponse("example.com", "1.2.3.4", 300);
    const result = injectEdeToResponse(resp, 15, "Blocked");
    // Should have ARCOUNT=1 now
    expect((result[10] << 8) | result[11]).toBe(1);
    // Parse the response and check it's still valid
    const json = wireToJson(result);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(0);
  });

  it("returns buffer unchanged for null/short input", () => {
    expect(injectEdeToResponse(null, 15)).toBeNull();
    expect(injectEdeToResponse(new Uint8Array(4), 15).length).toBe(4);
  });

  it("does not duplicate EDE if already present", () => {
    const resp = buildDnsResponse("example.com", "1.2.3.4", 300);
    const first = injectEdeToResponse(resp, 15, "Blocked");
    const second = injectEdeToResponse(first, 15, "Other text");
    // ARCOUNT should still be 1, not 2
    expect((second[10] << 8) | second[11]).toBe(1);
  });
});

// ---------------------------------------------------------------------------
// buildBlockedResponse - null mode
// ---------------------------------------------------------------------------

describe("buildBlockedResponse - null mode", () => {
  it("builds A=0.0.0.0 for A query", () => {
    const query = buildDnsQuery("example.com", 1, 0x1234);
    const resp = buildBlockedResponse(query, "null");
    const json = wireToJson(resp);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(0);
    expect(json.Answer).toHaveLength(1);
    expect(json.Answer[0].type).toBe(1);
    expect(json.Answer[0].data).toBe("0.0.0.0");
    expect(json.Answer[0].TTL).toBe(0);
  });

  it("builds AAAA=:: for AAAA query", () => {
    const query = buildDnsQuery("example.com", 28, 0x1234);
    const resp = buildBlockedResponse(query, "null");
    const json = wireToJson(resp);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(0);
    expect(json.Answer).toHaveLength(1);
    expect(json.Answer[0].type).toBe(28);
  });

  it("returns empty answer for non-A/AAAA query types", () => {
    const query = buildDnsQuery("example.com", 15, 0x1234); // MX
    const resp = buildBlockedResponse(query, "null");
    const json = wireToJson(resp);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(0);
    expect(json.Answer).toBeUndefined();
  });

  it("preserves DNS ID from query", () => {
    const query = buildDnsQuery("example.com", 1, 0xABCD);
    const resp = buildBlockedResponse(query, "null");
    expect((resp[0] << 8) | resp[1]).toBe(0xABCD);
  });

  it("flags as blocked by inspectWireResponse for A query", () => {
    const query = buildDnsQuery("example.com", 1, 0);
    const resp = buildBlockedResponse(query, "null");
    const { blocked } = inspectWireResponse(resp);
    expect(blocked).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// buildBlockedResponse - nxdomain mode
// ---------------------------------------------------------------------------

describe("buildBlockedResponse - nxdomain mode", () => {
  it("returns NXDOMAIN (rcode=3) with no answer", () => {
    const query = buildDnsQuery("example.com", 1, 0x1234);
    const resp = buildBlockedResponse(query, "nxdomain");
    const json = wireToJson(resp);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(3);
    expect(json.Answer).toBeUndefined();
  });

  it("has no authority section (NSCOUNT=0)", () => {
    const query = buildDnsQuery("example.com", 1, 0);
    const resp = buildBlockedResponse(query, "nxdomain");
    expect((resp[8] << 8) | resp[9]).toBe(0); // NSCOUNT
  });
});

// ---------------------------------------------------------------------------
// buildBlockedResponse - nodata mode
// ---------------------------------------------------------------------------

describe("buildBlockedResponse - nodata mode", () => {
  it("returns NOERROR (rcode=0) with no answer", () => {
    const query = buildDnsQuery("example.com", 1, 0x1234);
    const resp = buildBlockedResponse(query, "nodata");
    const json = wireToJson(resp);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(0);
    expect(json.Answer).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// buildBlockedResponse - refused mode
// ---------------------------------------------------------------------------

describe("buildBlockedResponse - refused mode", () => {
  it("returns REFUSED (rcode=5)", () => {
    const query = buildDnsQuery("example.com", 1, 0x1234);
    const resp = buildBlockedResponse(query, "refused");
    const json = wireToJson(resp);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(5);
    expect(json.Answer).toBeUndefined();
  });
});

// ---------------------------------------------------------------------------
// buildBlockedResponse with EDE
// ---------------------------------------------------------------------------

describe("buildBlockedResponse with EDE", () => {
  it("injects EDE option when edeText is provided", () => {
    const query = buildDnsQuery("example.com", 1, 0x1234);
    const resp = buildBlockedResponse(query, "nxdomain", { edeText: "Blocked by proxy" });
    // Should have ARCOUNT >= 1 (OPT with EDE)
    expect((resp[10] << 8) | resp[11]).toBeGreaterThanOrEqual(1);
  });

  it("does not inject EDE when edeText is empty", () => {
    const query = buildDnsQuery("example.com", 1, 0x1234);
    const resp = buildBlockedResponse(query, "nxdomain", { edeText: "" });
    // No additional section
    expect((resp[10] << 8) | resp[11]).toBe(0);
  });
});

// ---------------------------------------------------------------------------
// DNAME type support
// ---------------------------------------------------------------------------

describe("DNAME type", () => {
  it("DNS_TYPE_TO_NUMBER includes DNAME as type 39", () => {
    expect(DNS_TYPE_TO_NUMBER.DNAME).toBe(39);
  });
});
