// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/unit/handler.test.js
// Unit tests for handler helpers: extractProfileId, buildResponse,
// computeClientTtl, and hardcoded blocking/DNSSEC behaviour.

import { describe, it, expect } from "vitest";
import { extractProfileId, buildResponse } from "../../src/handler.js";
import { computeClientTtl } from "../../src/cache.js";
import {
  buildDnsResponse,
  buildDnsQuery,
  buildBlockedResponse,
  buildEdeOption,
  injectEdeToResponse,
  hasDnssecData,
} from "../../src/dns.js";

// ---------------------------------------------------------------------------
// extractProfileId
// ---------------------------------------------------------------------------

describe("extractProfileId", () => {
  it("extracts 6-hex profile from /p-{hex}/ path", () => {
    const url = new URL("https://worker.example.com/p-000000/dns-query?name=example.com&type=A");
    expect(extractProfileId(url)).toBe("000000");
  });

  it("extracts profile from path with no trailing segment", () => {
    const url = new URL("https://worker.example.com/p-aabbcc");
    expect(extractProfileId(url)).toBe("aabbcc");
  });

  it("normalises profile ID to lowercase", () => {
    const url = new URL("https://worker.example.com/p-AABBCC/dns-query");
    expect(extractProfileId(url)).toBe("aabbcc");
  });

  it("falls back to GENERAL_PROFILE_ID for arbitrary paths", () => {
    const url = new URL("https://worker.example.com/dns-query?name=example.com");
    const result = extractProfileId(url);
    expect(result).toMatch(/^[0-9a-f]{6}$/);
  });

  it("falls back for path with only 5 hex chars", () => {
    const url = new URL("https://worker.example.com/p-aabbc/dns-query");
    const result = extractProfileId(url);
    // Should use default, not "aabbc"
    expect(result).not.toBe("aabbc");
  });

  it("falls back for non-hex characters in profile segment", () => {
    const url = new URL("https://worker.example.com/p-GGGGGG/dns-query");
    const result = extractProfileId(url);
    expect(result).toMatch(/^[0-9a-f]{6}$/);
  });

  it("does not match longer profile-like segments", () => {
    const url = new URL("https://worker.example.com/p-aabbccdd/dns-query");
    const result = extractProfileId(url);
    expect(result).not.toBe("aabbcc");
  });
});

// ---------------------------------------------------------------------------
// buildResponse
// ---------------------------------------------------------------------------

describe("buildResponse", () => {
  const fakeJsonResult = {
    index: 0,
    ok: true,
    blocked: false,
    wire: false,
    json: { Status: 0, Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "1.2.3.4" }] },
  };

  it("returns 200 for a clean JSON result", () => {
    const resp = buildResponse(fakeJsonResult, "aabbcc", false, true);
    expect(resp.status).toBe(200);
  });

  it("sets Content-Type application/dns-json for JSON result", () => {
    const resp = buildResponse(fakeJsonResult, "aabbcc", false, true);
    expect(resp.headers.get("content-type")).toContain("application/dns-json");
  });

  it("sets CORS header", () => {
    const resp = buildResponse(fakeJsonResult, "aabbcc", false, true);
    expect(resp.headers.get("access-control-allow-origin")).toBe("*");
  });

  it("sets X-Profile-Id header", () => {
    const resp = buildResponse(fakeJsonResult, "aabbcc", false, true);
    expect(resp.headers.get("x-profile-id")).toBe("aabbcc");
  });

  it("sets X-Blocked to false for clean result", () => {
    const resp = buildResponse(fakeJsonResult, "aabbcc", false, true);
    expect(resp.headers.get("x-blocked")).toBe("false");
  });

  it("sets X-Blocked to true for blocked result", () => {
    const blockedResult = { ...fakeJsonResult, blocked: true };
    const resp = buildResponse(blockedResult, "aabbcc", true, true);
    expect(resp.headers.get("x-blocked")).toBe("true");
  });

  it("sets X-Upstream-Index header", () => {
    const resp = buildResponse(fakeJsonResult, "aabbcc", false, true);
    expect(resp.headers.get("x-upstream-index")).toBe("0");
  });

  it("sets X-All-Responded to true", () => {
    const resp = buildResponse(fakeJsonResult, "aabbcc", false, true);
    expect(resp.headers.get("x-all-responded")).toBe("true");
  });

  it("sets X-All-Responded to false", () => {
    const resp = buildResponse(fakeJsonResult, "aabbcc", false, false);
    expect(resp.headers.get("x-all-responded")).toBe("false");
  });

  it("includes X-Worker-Version header in every successful response", () => {
    const resp = buildResponse(fakeJsonResult, "aabbcc", false, true);
    const ver = resp.headers.get("x-worker-version");
    expect(ver).toBeTruthy();
    // Must be a valid semver string (MAJOR.MINOR.PATCH)
    expect(ver).toMatch(/^\d+\.\d+\.\d+/);
  });

  it("includes Cache-Control with max-age", () => {
    const resp = buildResponse(fakeJsonResult, "aabbcc", false, true);
    expect(resp.headers.get("cache-control")).toMatch(/public, max-age=\d+/);
  });

  it("includes Vary: Accept for content negotiation safety", () => {
    const resp = buildResponse(fakeJsonResult, "aabbcc", false, true);
    expect(resp.headers.get("vary")).toBe("Accept");
  });

  it("returns wire format response with correct Content-Type", () => {
    const wireResult = {
      index: 1,
      ok: true,
      blocked: false,
      wire: true,
      raw: buildDnsResponse("example.com.", "1.2.3.4", 300),
    };
    const resp = buildResponse(wireResult, "aabbcc", false, true);
    expect(resp.headers.get("content-type")).toContain("dns-message");
  });

  it("uses blocked TTL config for blocked response (capped by record TTL)", () => {
    // fakeJsonResult has TTL=300; blocked config is 86400, so min(86400,300)=300
    const blockedResult = { ...fakeJsonResult, blocked: true };
    const resp = buildResponse(blockedResult, "aabbcc", true, true);
    const cc = resp.headers.get("cache-control");
    const maxAge = parseInt(cc.replace("public, max-age=", ""), 10);
    // TTL is capped at the DNS record TTL (300), but respects MIN_CACHE_TTL_FLOOR
    expect(maxAge).toBeGreaterThanOrEqual(60);
    expect(maxAge).toBeLessThanOrEqual(86400);

    // Verify a result with a very high record TTL uses the blocked config ceiling
    const highTtlResult = {
      ...fakeJsonResult,
      json: { Status: 0, Answer: [{ name: "x.", type: 1, TTL: 999999, data: "0.0.0.0" }] },
    };
    const respHigh = buildResponse(highTtlResult, "aabbcc", true, true);
    const ccHigh = respHigh.headers.get("cache-control");
    const maxAgeHigh = parseInt(ccHigh.replace("public, max-age=", ""), 10);
    // Blocked ceiling is CLIENT_BLOCKED_CACHE_TTL_SECONDS = 86400
    expect(maxAgeHigh).toBeLessThanOrEqual(86400);
    expect(maxAgeHigh).toBeGreaterThan(1800);
  });
});

// ---------------------------------------------------------------------------
// computeClientTtl
// ---------------------------------------------------------------------------

describe("computeClientTtl", () => {
  it("respects MIN_CACHE_TTL_FLOOR for very short DNS TTL", () => {
    const result = {
      wire: false,
      json: { Answer: [{ TTL: 1 }] },
    };
    const ttl = computeClientTtl(result, false);
    expect(ttl).toBeGreaterThanOrEqual(60);
  });

  it("caps normal TTL at CLIENT_CACHE_TTL_SECONDS", () => {
    const result = {
      wire: false,
      json: { Answer: [{ TTL: 999999 }] },
    };
    const ttl = computeClientTtl(result, false);
    expect(ttl).toBeLessThanOrEqual(1800);
  });

  it("uses blocked TTL config for blocked result", () => {
    const result = {
      wire: false,
      json: { Status: 0, Answer: [{ TTL: 999999 }] },
    };
    const ttl = computeClientTtl(result, true);
    // Default CLIENT_BLOCKED_CACHE_TTL_SECONDS is 86400
    expect(ttl).toBeLessThanOrEqual(86400);
    expect(ttl).toBeGreaterThan(1800);
  });

  it("falls back to configured TTL when no DNS records", () => {
    const result = { wire: false, json: null };
    const ttl = computeClientTtl(result, false);
    expect(ttl).toBe(1800);
  });

  it("works for wire results", () => {
    const raw = buildDnsResponse("example.com.", "1.2.3.4", 60);
    const result = { wire: true, raw };
    const ttl = computeClientTtl(result, false);
    expect(ttl).toBe(60);
  });
});

// ---------------------------------------------------------------------------
// Security & Edge Cases (Handler)
// ---------------------------------------------------------------------------

describe("Handler - Security & Malformed Inputs", () => {
  it("buildResponse handles null json payload without throwing", () => {
    // buildResponse is only called with valid upstream results in normal flow,
    // but null json must not crash the worker - JSON.stringify(null) = "null".
    const errorResult = { index: 0, ok: false, wire: false, blocked: false, json: null };
    let resp;
    expect(() => {
      resp = buildResponse(errorResult, "aabbcc", false, true);
    }).not.toThrow();
    expect(resp).toBeInstanceOf(Response);
    expect(resp.status).toBe(200);
  });

  it("extractProfileId resists prototype pollution via URL", () => {
    const url = new URL("https://worker.example.com/p-__proto__/dns-query");
    const result = extractProfileId(url);
    // Should fallback to GENERAL_PROFILE_ID, not __proto__
    expect(result).not.toBe("__proto__");
    expect(result).toMatch(/^[0-9a-f]{6}$/);
  });
});

// ---------------------------------------------------------------------------
// extractProfileId - additional coverage
// ---------------------------------------------------------------------------

describe("extractProfileId - additional coverage", () => {
  it("extracts profile from path with query string", () => {
    const url = new URL("https://worker.example.com/p-ff0011?name=example.com&type=A");
    expect(extractProfileId(url)).toBe("ff0011");
  });

  it("extracts profile from path with fragment", () => {
    const url = new URL("https://worker.example.com/p-123abc#frag");
    expect(extractProfileId(url)).toBe("123abc");
  });

  it("does not match when profile segment is in query string", () => {
    // Profile must be a path segment, not a query param
    const url = new URL("https://worker.example.com/dns-query?profile=aabbcc");
    const result = extractProfileId(url);
    expect(result).toMatch(/^[0-9a-f]{6}$/);
    expect(result).not.toBe("aabbcc");
  });

  it("returns GENERAL_PROFILE_ID for root path", () => {
    const url = new URL("https://worker.example.com/");
    const result = extractProfileId(url);
    expect(result).toMatch(/^[0-9a-f]{6}$/);
  });
});

// ---------------------------------------------------------------------------
// buildResponse - security headers
// ---------------------------------------------------------------------------

describe("buildResponse - security headers", () => {
  const fakeResult = {
    index: 0, ok: true, blocked: false, wire: false,
    json: { Status: 0, Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "1.2.3.4" }] },
  };

  it("X-Client-Cache-TTL header is a numeric string", () => {
    const resp = buildResponse(fakeResult, "aabbcc", false, true);
    const ttl = resp.headers.get("x-client-cache-ttl");
    expect(ttl).toMatch(/^\d+$/);
    expect(parseInt(ttl, 10)).toBeGreaterThanOrEqual(60);
  });

  it("Cache-Control does not include no-store for successful responses", () => {
    const resp = buildResponse(fakeResult, "aabbcc", false, true);
    expect(resp.headers.get("cache-control")).not.toContain("no-store");
  });

  it("CORS header is exactly '*' (no wildcards or domain restrictions)", () => {
    const resp = buildResponse(fakeResult, "aabbcc", false, true);
    expect(resp.headers.get("access-control-allow-origin")).toBe("*");
  });

  it("upstream index 1 is reflected in X-Upstream-Index", () => {
    const result1 = { ...fakeResult, index: 1 };
    const resp = buildResponse(result1, "aabbcc", false, true);
    expect(resp.headers.get("x-upstream-index")).toBe("1");
  });
});

// ---------------------------------------------------------------------------
// Hardcoded EDE behaviour - EDE is always auto-derived from upstream URL
// ---------------------------------------------------------------------------

describe("Hardcoded EDE - buildBlockedResponse always produces Blocked (url) text", () => {
  const query = buildDnsQuery("blocked.example", 1);

  it("buildBlockedResponse with edeText produces an OPT record (ARCOUNT=1)", () => {
    const url = "https://dns.quad9.net/dns-query";
    const buf = buildBlockedResponse(query, "null", { edeText: `Blocked (${url})` });
    // ARCOUNT is bytes 10-11; must be 1 for the OPT record
    expect((buf[10] << 8) | buf[11]).toBe(1);
  });

  it("EDE text in blocked response contains the upstream URL hostname", () => {
    const url = "https://security.cloudflare-dns.com/dns-query";
    const buf = buildBlockedResponse(query, "nxdomain", { edeText: `Blocked (${url})` });
    const text = new TextDecoder().decode(buf);
    expect(text).toContain("security.cloudflare-dns.com");
  });

  it("EDE text in blocked response contains 'Blocked ('", () => {
    const url = "https://dns.quad9.net/dns-query";
    const buf = buildBlockedResponse(query, "nxdomain", { edeText: `Blocked (${url})` });
    const text = new TextDecoder().decode(buf);
    expect(text).toContain("Blocked (");
  });

  it("EDE text matches exact 'Blocked (url)' format with closing parenthesis", () => {
    const url = "https://dns.quad9.net/dns-query";
    const edeText = `Blocked (${url})`;
    const buf = buildBlockedResponse(query, "nxdomain", { edeText });
    const text = new TextDecoder().decode(buf);
    // Verify the closing parenthesis is also present
    expect(text).toContain(url + ")");
  });

  it("blocked response without edeText has ARCOUNT=0", () => {
    const buf = buildBlockedResponse(query, "nxdomain", { edeText: "" });
    expect((buf[10] << 8) | buf[11]).toBe(0);
  });

  it("all four blocking modes produce EDE when url text is provided", () => {
    const url = "https://dns.example.com/dns-query";
    const edeText = `Blocked (${url})`;
    for (const mode of ["null", "nxdomain", "nodata", "refused"]) {
      const buf = buildBlockedResponse(query, mode, { edeText });
      expect((buf[10] << 8) | buf[11]).toBe(1);
      const text = new TextDecoder().decode(buf);
      expect(text).toContain("dns.example.com");
    }
  });

  it("EDE option for info code 15 (Blocked) is correctly encoded by buildEdeOption", () => {
    const extraText = "Blocked (https://test.example.net/dns-query)";
    const opt = buildEdeOption(15, extraText);
    // buildEdeOption returns { code: 15, data: Uint8Array }
    expect(opt.code).toBe(15);
    // EDE data: 2-byte info code + UTF-8 extra text
    const infoCode = (opt.data[0] << 8) | opt.data[1];
    expect(infoCode).toBe(15);
    const encodedText = new TextDecoder().decode(opt.data.slice(2));
    expect(encodedText).toBe(extraText);
  });

  it("injectEdeToResponse adds OPT record to a plain wire response", () => {
    const plain = buildDnsResponse("blocked.example.", "0.0.0.0", 300);
    const withEde = injectEdeToResponse(plain, 15, "Blocked (https://dns.example.com/dns-query)");
    // ARCOUNT should be 1 after injection
    expect((withEde[10] << 8) | withEde[11]).toBe(1);
    // Response must grow (OPT record added)
    expect(withEde.length).toBeGreaterThan(plain.length);
  });
});

// ---------------------------------------------------------------------------
// Hardcoded DNSSEC preference - always prefer signed upstream responses
// ---------------------------------------------------------------------------

describe("Hardcoded DNSSEC preference - hasDnssecData detection", () => {
  it("unsigned response is not detected as having DNSSEC data", () => {
    const plain = buildDnsResponse("example.com.", "1.2.3.4", 300);
    expect(hasDnssecData(plain)).toBe(false);
  });

  it("response with AD bit set is detected as having DNSSEC data", () => {
    const resp = buildDnsResponse("example.com.", "1.2.3.4", 300);
    resp[3] |= 0x20; // set AD bit
    expect(hasDnssecData(resp)).toBe(true);
  });

  it("DNSSEC detection is consistent regardless of rcode", () => {
    // NXDOMAIN (rcode=3) with AD bit still counts as DNSSEC-signed
    const nxResp = buildDnsResponse("example.com.", "0.0.0.0", 300, 3);
    nxResp[3] |= 0x20;
    expect(hasDnssecData(nxResp)).toBe(true);
    // NXDOMAIN without AD bit does not
    const nxPlain = buildDnsResponse("example.com.", "0.0.0.0", 300, 3);
    expect(hasDnssecData(nxPlain)).toBe(false);
  });

  it("null/too-short buffer returns false (no crash)", () => {
    expect(hasDnssecData(null)).toBe(false);
    expect(hasDnssecData(new Uint8Array(3))).toBe(false);
  });
});
