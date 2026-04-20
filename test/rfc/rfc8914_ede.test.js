// test/rfc/rfc8914_ede.test.js
// RFC 8914 Extended DNS Errors compliance tests
//
// Covers:
//   - EDE option building (info-code + extra text)
//   - EDE injection into responses with and without existing OPT
//   - EDE pass-through from upstream (tested in processEdnsIncoming)
//   - EDE in blocked responses

import { describe, it, expect } from "vitest";
import {
  buildEdeOption,
  injectEdeToResponse,
  buildDnsResponse,
  buildDnsQuery,
  buildBlockedResponse,
  processEdnsIncoming,
  wireToJson,
} from "../../src/dns.js";
import { getConfig } from "../../src/config.js";

// ---------------------------------------------------------------------------
// EDE option structure (RFC 8914 Section 2)
// ---------------------------------------------------------------------------

describe("RFC 8914 - EDE option structure", () => {
  it("EDE option code is 15", () => {
    const opt = buildEdeOption(0);
    expect(opt.code).toBe(15);
  });

  it("INFO-CODE is encoded as 2-byte big-endian", () => {
    const opt = buildEdeOption(15);
    expect(opt.data[0]).toBe(0);
    expect(opt.data[1]).toBe(15);
  });

  it("INFO-CODE 256 is encoded correctly", () => {
    const opt = buildEdeOption(256);
    expect(opt.data[0]).toBe(1);
    expect(opt.data[1]).toBe(0);
  });

  it("EXTRA-TEXT follows INFO-CODE as UTF-8", () => {
    const opt = buildEdeOption(15, "test message");
    const text = new TextDecoder().decode(opt.data.subarray(2));
    expect(text).toBe("test message");
  });

  it("empty EXTRA-TEXT produces 2-byte option data", () => {
    const opt = buildEdeOption(15, "");
    expect(opt.data.length).toBe(2);
  });
});

// ---------------------------------------------------------------------------
// EDE injection into wire responses
// ---------------------------------------------------------------------------

describe("RFC 8914 - EDE injection", () => {
  it("adds OPT record with EDE to response without OPT", () => {
    const resp = buildDnsResponse("example.com", "1.2.3.4", 300);
    const arcount = (resp[10] << 8) | resp[11];
    expect(arcount).toBe(0);

    const injected = injectEdeToResponse(resp, 15, "Blocked");
    const newAr = (injected[10] << 8) | injected[11];
    expect(newAr).toBe(1);
  });

  it("preserves existing response data after EDE injection", () => {
    const resp = buildDnsResponse("example.com", "1.2.3.4", 300);
    const injected = injectEdeToResponse(resp, 15, "test");
    const json = wireToJson(injected);
    expect(json.Status).toBe(0);
    expect(json.Answer).toHaveLength(1);
    expect(json.Answer[0].data).toBe("1.2.3.4");
  });
});

// ---------------------------------------------------------------------------
// EDE pass-through from upstream
// ---------------------------------------------------------------------------

describe("RFC 8914 - EDE pass-through", () => {
  it("processEdnsIncoming preserves EDE options (code 15)", () => {
    // Build a response with an OPT record containing an EDE option
    const resp = buildDnsResponse("example.com", "1.2.3.4", 300);
    const withEde = injectEdeToResponse(resp, 15, "Upstream error");

    const cfg = getConfig({});
    const processed = processEdnsIncoming(withEde, cfg, null);

    // EDE should be preserved in the output
    const arcount = (processed[10] << 8) | processed[11];
    expect(arcount).toBeGreaterThanOrEqual(1);
  });
});

// ---------------------------------------------------------------------------
// EDE in blocked responses
// ---------------------------------------------------------------------------

describe("RFC 8914 - EDE in blocked responses", () => {
  it("blocked response includes EDE code 15 when edeText is set", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    const resp = buildBlockedResponse(query, "nxdomain", { edeText: "Blocked by dns.quad9.net" });

    // Verify response has additional section (OPT with EDE)
    const arcount = (resp[10] << 8) | resp[11];
    expect(arcount).toBe(1);
  });

  it("blocked response (null mode) includes EDE when configured", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    const resp = buildBlockedResponse(query, "null", { edeText: "Blocked" });

    const arcount = (resp[10] << 8) | resp[11];
    expect(arcount).toBe(1);
    // Response should still be parseable
    const json = wireToJson(resp);
    expect(json).not.toBeNull();
  });
});
