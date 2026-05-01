// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/rfc/rfc5001_nsid.test.js
// Tests for RFC 5001 NSID (Name Server Identifier) handling:
// strip, forward, and substitute modes.

import { describe, it, expect } from "vitest";
import {
  hasNsidRequest,
  injectNsidToResponse,
  processEdnsOutgoing,
  processEdnsIncoming,
  buildDnsQuery,
  buildDnsQueryWithDo,
  buildDnsResponse,
} from "../../src/dns.js";
import { getConfig } from "../../src/config.js";

// Helper: build a query with NSID request option (code 3, empty data)
function buildQueryWithNsid(name) {
  const base = buildDnsQueryWithDo(name, 1, 0, true);
  // The OPT from buildDnsQueryWithDo has no options; add NSID option
  // NSID request is code=3, data=empty
  const nsidOption = new Uint8Array(4);
  nsidOption[0] = 0x00; nsidOption[1] = 0x03; // code 3
  nsidOption[2] = 0x00; nsidOption[3] = 0x00; // length 0

  // Insert NSID option into the existing OPT record
  // Find OPT RR at the end of the base query and extend its RDLENGTH
  // OPT starts at base.length - 11 (the buildDnsQueryWithDo OPT is 11 bytes)
  const optStart = base.length - 11;
  const out = new Uint8Array(base.length + 4);
  out.set(base.subarray(0, base.length));
  out.set(nsidOption, base.length);
  // Update RDLENGTH (last 2 bytes of the OPT fixed header, at optStart+9 and optStart+10)
  const oldRdlen = (base[optStart + 9] << 8) | base[optStart + 10];
  const newRdlen = oldRdlen + 4;
  out[optStart + 9] = (newRdlen >> 8) & 0xff;
  out[optStart + 10] = newRdlen & 0xff;
  return out;
}

describe("RFC 5001 - NSID request detection", () => {
  it("detects NSID request in query with NSID option", () => {
    const query = buildQueryWithNsid("example.com");
    expect(hasNsidRequest(query)).toBe(true);
  });

  it("returns false for query without NSID option", () => {
    const query = buildDnsQueryWithDo("example.com", 1, 0, true);
    expect(hasNsidRequest(query)).toBe(false);
  });

  it("returns false for null input", () => {
    expect(hasNsidRequest(null)).toBe(false);
  });

  it("returns false for short buffer", () => {
    expect(hasNsidRequest(new Uint8Array(5))).toBe(false);
  });

  it("returns false for query without OPT record", () => {
    const query = buildDnsQuery("example.com", 1, 0);
    expect(hasNsidRequest(query)).toBe(false);
  });
});

describe("RFC 5001 - NSID response injection", () => {
  it("injects NSID into response without existing OPT", () => {
    const resp = buildDnsResponse("example.com", "1.2.3.4", 300);
    const withNsid = injectNsidToResponse(resp, "dnsieve-proxy-01");
    // ARCOUNT should be 1 (new OPT added)
    expect((withNsid[10] << 8) | withNsid[11]).toBe(1);
    expect(withNsid.length).toBeGreaterThan(resp.length);
  });

  it("returns original buffer for empty nsidValue", () => {
    const resp = buildDnsResponse("example.com", "1.2.3.4", 300);
    const result = injectNsidToResponse(resp, "");
    expect(result).toBe(resp);
  });

  it("returns original buffer for null nsidValue", () => {
    const resp = buildDnsResponse("example.com", "1.2.3.4", 300);
    const result = injectNsidToResponse(resp, null);
    expect(result).toBe(resp);
  });

  it("returns original for short buffer", () => {
    const short = new Uint8Array(5);
    const result = injectNsidToResponse(short, "test");
    expect(result).toBe(short);
  });

  it("NSID value is ASCII-encoded", () => {
    const resp = buildDnsResponse("example.com", "1.2.3.4", 300);
    const value = "my-proxy";
    const withNsid = injectNsidToResponse(resp, value);
    // The NSID value should appear as ASCII bytes somewhere in the response
    const valueBytes = new TextEncoder().encode(value);
    let found = false;
    for (let i = 0; i <= withNsid.length - valueBytes.length; i++) {
      let match = true;
      for (let j = 0; j < valueBytes.length; j++) {
        if (withNsid[i + j] !== valueBytes[j]) { match = false; break; }
      }
      if (match) { found = true; break; }
    }
    expect(found).toBe(true);
  });
});

describe("RFC 5001 - NSID privacy modes", () => {
  it("strip mode removes NSID from outgoing query", () => {
    const cfg = getConfig({ PRIVACY_NSID_MODE: "strip" });
    const query = buildQueryWithNsid("example.com");
    const processed = processEdnsOutgoing(query, cfg, null);
    const hasNsid = hasNsidRequest(processed);
    expect(hasNsid).toBe(false);
  });

  it("forward mode preserves NSID in outgoing query", () => {
    const cfg = getConfig({ PRIVACY_NSID_MODE: "forward" });
    const query = buildQueryWithNsid("example.com");
    const processed = processEdnsOutgoing(query, cfg, null);
    const hasNsid = hasNsidRequest(processed);
    expect(hasNsid).toBe(true);
  });

  it("substitute mode removes NSID from outgoing query (proxy handles it)", () => {
    const cfg = getConfig({
      PRIVACY_NSID_MODE: "substitute",
      PRIVACY_NSID_VALUE: "dnsieve-cfw-01",
    });
    const query = buildQueryWithNsid("example.com");
    const processed = processEdnsOutgoing(query, cfg, null);
    const hasNsid = hasNsidRequest(processed);
    expect(hasNsid).toBe(false);
  });
});
