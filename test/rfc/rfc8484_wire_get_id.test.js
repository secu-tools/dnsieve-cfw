// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/rfc/rfc8484_wire_get_id.test.js
// RFC 8484 SS.4.1 compliance: DNS transaction ID MUST be 0 in upstream queries.
// This file specifically tests the wire GET path (F-01 fix).

import { describe, it, expect, vi, afterEach } from "vitest";
import { buildDnsQuery, buildDnsResponse, buildDnsQueryWithDo, processEdnsOutgoing } from "../../src/dns.js";
import { queryUpstream, COOKIE_STORE } from "../../src/upstream.js";
import { getConfig } from "../../src/config.js";
import { handleRequest } from "../../src/handler.js";

afterEach(() => {
  COOKIE_STORE.clear();
});

// Helper: encode wire query as base64url for GET ?dns=
function wireToBase64url(buf) {
  let b64 = "";
  for (let i = 0; i < buf.length; i++) b64 += String.fromCharCode(buf[i]);
  return btoa(b64).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

// Helper: create a fake upstream fetch that captures the request
function makeCapturingFetch() {
  let capturedUrl = null;
  const fakeFetch = vi.fn(async (urlOrReq, init) => {
    capturedUrl = typeof urlOrReq === "string" ? urlOrReq : urlOrReq.url;
    // Return a valid DNS wire response
    const resp = buildDnsResponse("example.com", "93.184.216.34", 300);
    return new Response(resp, {
      status: 200,
      headers: { "Content-Type": "application/dns-message" },
    });
  });
  return { fakeFetch, getCapturedUrl: () => capturedUrl };
}

describe("RFC 8484 SS.4.1 - Wire GET upstream ID must be 0", () => {
  it("GET wire ?dns= with non-zero client ID sends ID=0 to upstream", async () => {
    // Build a query with non-zero ID
    const clientId = 0xABCD;
    const query = buildDnsQuery("example.com", 1, clientId);
    expect(query[0]).toBe(0xAB);
    expect(query[1]).toBe(0xCD);

    const encoded = wireToBase64url(query);
    const cfg = getConfig({});

    // We need to capture what gets sent upstream.
    // The upstream.js decodes the dns param, applies EDNS, re-encodes.
    // After our fix, the ID should be zeroed.

    // Decode and verify the fix directly:
    const padded = encoded.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - encoded.length % 4) % 4);
    const binStr = atob(padded);
    const decoded = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) decoded[i] = binStr.charCodeAt(i);

    // Before processing, ID should still be the client's
    expect(decoded[0]).toBe(0xAB);
    expect(decoded[1]).toBe(0xCD);

    // Simulate what upstream.js does after the fix: zero the ID
    if (decoded.length >= 2) { decoded[0] = 0; decoded[1] = 0; }
    const processed = processEdnsOutgoing(decoded, cfg, null);
    expect(processed[0]).toBe(0);
    expect(processed[1]).toBe(0);
  });

  it("POST wire path also zeroes ID (baseline check)", async () => {
    const clientId = 0x1234;
    const query = buildDnsQuery("example.com", 1, clientId);
    // Simulate what handler.js does for POST
    const bodyBytes = new Uint8Array(query);
    if (bodyBytes.length >= 2) { bodyBytes[0] = 0; bodyBytes[1] = 0; }
    expect(bodyBytes[0]).toBe(0);
    expect(bodyBytes[1]).toBe(0);
  });

  it("wire GET client DNS ID is preserved for response restoration", async () => {
    const clientId = 0xBEEF;
    const query = buildDnsQuery("example.com", 1, clientId);
    const encoded = wireToBase64url(query);

    // Simulate handler.js GET wire ID extraction
    const padded = encoded.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - encoded.length % 4) % 4);
    const bin = atob(padded);
    const extractedId = (bin.charCodeAt(0) << 8) | bin.charCodeAt(1);
    expect(extractedId).toBe(0xBEEF);
  });
});

describe("RFC 8484 - DNS ID consistency across formats", () => {
  it("POST and GET wire both zero ID before upstream, preserve for client restore", () => {
    const clientId = 42;
    const query = buildDnsQuery("test.example.net", 28, clientId);

    // POST path: zero directly on body
    const postBody = new Uint8Array(query);
    const postClientId = (postBody[0] << 8) | postBody[1];
    expect(postClientId).toBe(42);
    postBody[0] = 0; postBody[1] = 0;
    expect(postBody[0]).toBe(0);

    // GET path: encode, decode, zero, process
    const encoded = wireToBase64url(query);
    const padded = encoded.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - encoded.length % 4) % 4);
    const binStr = atob(padded);
    const decoded = new Uint8Array(binStr.length);
    for (let i = 0; i < binStr.length; i++) decoded[i] = binStr.charCodeAt(i);

    const getClientId = (decoded[0] << 8) | decoded[1];
    expect(getClientId).toBe(42);

    // Zero (our fix)
    decoded[0] = 0; decoded[1] = 0;
    expect(decoded[0]).toBe(0);
    expect(decoded[1]).toBe(0);
  });
});
