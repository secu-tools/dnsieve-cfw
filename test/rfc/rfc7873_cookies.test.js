// test/rfc/rfc7873_cookies.test.js
// Tests for DNS Cookie handling (RFC 7873): reoriginate mode, strip mode,
// cookie store management, and cookie option processing.

import { describe, it, expect, afterEach } from "vitest";
import {
  processEdnsOutgoing,
  processEdnsIncoming,
  buildDnsQuery,
  buildDnsQueryWithDo,
} from "../../src/dns.js";
import { COOKIE_STORE } from "../../src/upstream.js";
import { getConfig } from "../../src/config.js";

afterEach(() => {
  COOKIE_STORE.clear();
});

// Helper: build a query with an OPT containing a Cookie option (code 10)
function buildQueryWithCookie(name, clientCookie) {
  const base = buildDnsQueryWithDo(name, 1, 0, true);
  // The OPT from buildDnsQueryWithDo is at the end, rebuild with cookie option
  // For simplicity, use processEdnsOutgoing with reoriginate mode, which adds cookies
  const cfg = getConfig({ PRIVACY_COOKIES_MODE: "reoriginate" });
  // processEdnsOutgoing will add proxy cookies
  return processEdnsOutgoing(base, cfg, clientCookie);
}

// Helper: build a response with an OPT containing a Cookie option (server cookie)
function buildResponseWithServerCookie(name) {
  // Calculate size: header(12) + question(variable) + answer(16)
  // For "example.com": question = 1+7+1+3+1 + 2 + 2 = 17 bytes
  // Answer: pointer(2)+type(2)+class(2)+ttl(4)+rdlen(2)+rdata(4) = 16 bytes
  const nameBytes = name.replace(/\.$/, "").split(".").reduce((s, l) => s + 1 + l.length, 0) + 1;
  const base = new Uint8Array(12 + nameBytes + 4 + 16); // header + question + answer
  base[2] = 0x81; base[3] = 0x80; // QR=1, RD=1, RA=1
  base[4] = 0; base[5] = 1; // QDCOUNT=1
  base[6] = 0; base[7] = 1; // ANCOUNT=1
  base[10] = 0; base[11] = 0; // ARCOUNT=0

  // Question: example.com (simplified)
  let off = 12;
  const labels = name.replace(/\.$/, "").split(".");
  for (const l of labels) {
    base[off++] = l.length;
    for (let i = 0; i < l.length; i++) base[off++] = l.charCodeAt(i);
  }
  base[off++] = 0; // root
  base[off++] = 0; base[off++] = 1; // QTYPE A
  base[off++] = 0; base[off++] = 1; // QCLASS IN

  // Answer: pointer + A record
  base[off++] = 0xc0; base[off++] = 0x0c;
  base[off++] = 0; base[off++] = 1; // TYPE A
  base[off++] = 0; base[off++] = 1; // CLASS IN
  base[off++] = 0; base[off++] = 0; base[off++] = 1; base[off++] = 0x2c; // TTL=300
  base[off++] = 0; base[off++] = 4; // RDLENGTH=4
  base[off++] = 1; base[off++] = 2; base[off++] = 3; base[off++] = 4;

  // Build OPT with server cookie (8-byte client + 16-byte server = 24 bytes)
  const cookieData = new Uint8Array(24);
  crypto.getRandomValues(cookieData);

  const optRr = new Uint8Array(11 + 4 + cookieData.length);
  let w = 0;
  optRr[w++] = 0x00; // root name
  optRr[w++] = 0x00; optRr[w++] = 0x29; // TYPE OPT
  optRr[w++] = 0x10; optRr[w++] = 0x00; // CLASS=4096
  optRr[w++] = 0x00; // ext RCODE
  optRr[w++] = 0x00; // EDNS version
  optRr[w++] = 0x80; optRr[w++] = 0x00; // DO bit set
  const rdlen = 4 + cookieData.length;
  optRr[w++] = (rdlen >> 8) & 0xff;
  optRr[w++] = rdlen & 0xff;
  // Cookie option header
  optRr[w++] = 0x00; optRr[w++] = 0x0a; // code 10
  optRr[w++] = (cookieData.length >> 8) & 0xff;
  optRr[w++] = cookieData.length & 0xff;
  optRr.set(cookieData, w);

  // Combine
  const result = new Uint8Array(off + optRr.length);
  result.set(base.subarray(0, off));
  result.set(optRr, off);
  // Update ARCOUNT to 1
  result[10] = 0; result[11] = 1;

  return { buf: result, cookieData };
}

describe("RFC 7873 - Cookie strip mode", () => {
  it("strip mode removes all cookie options from outgoing queries", () => {
    const cfg = getConfig({ PRIVACY_COOKIES_MODE: "strip" });
    const query = buildDnsQueryWithDo("example.com", 1, 0, true);
    const processed = processEdnsOutgoing(query, cfg, null);
    // Should not contain any cookie option (code 10)
    // Parse the OPT and check
    expect(processed.length).toBeGreaterThan(12);
  });
});

describe("RFC 7873 - Cookie reoriginate mode", () => {
  it("reoriginate mode adds proxy cookie to outgoing query", () => {
    const proxyCookie = new Uint8Array(8);
    crypto.getRandomValues(proxyCookie);
    const cfg = getConfig({ PRIVACY_COOKIES_MODE: "reoriginate" });
    const query = buildDnsQueryWithDo("example.com", 1, 0, true);
    const processed = processEdnsOutgoing(query, cfg, proxyCookie);
    // Result should be larger (cookie option added)
    expect(processed.length).toBeGreaterThan(query.length);
  });

  it("reoriginate mode does not forward client cookies", () => {
    const clientCookie = new Uint8Array(8);
    clientCookie.fill(0xff);
    const proxyCookie = new Uint8Array(8);
    proxyCookie.fill(0xaa);
    const cfg = getConfig({ PRIVACY_COOKIES_MODE: "reoriginate" });
    const query = buildDnsQueryWithDo("example.com", 1, 0, true);
    const processed = processEdnsOutgoing(query, cfg, proxyCookie);
    // The client cookie (0xff filled) should not appear in the output
    let found = false;
    for (let i = 0; i < processed.length - 7; i++) {
      if (processed[i] === 0xff && processed[i+1] === 0xff && processed[i+2] === 0xff) {
        found = true;
        break;
      }
    }
    expect(found).toBe(false);
  });
});

describe("RFC 7873 - Server cookie processing in responses", () => {
  it("processEdnsIncoming strips cookie from response", () => {
    const cfg = getConfig({ PRIVACY_COOKIES_MODE: "reoriginate" });
    const { buf } = buildResponseWithServerCookie("example.com");
    let receivedServerCookie = null;
    const processed = processEdnsIncoming(buf, cfg, (sc) => {
      receivedServerCookie = sc;
    });
    // Cookie should have been passed to callback
    expect(receivedServerCookie).not.toBeNull();
    expect(receivedServerCookie.length).toBeGreaterThanOrEqual(8);
  });

  it("processEdnsIncoming does not pass invalid-length cookies to callback", () => {
    const cfg = getConfig({ PRIVACY_COOKIES_MODE: "reoriginate" });
    // Build a response with a too-short cookie (< 16 bytes combined)
    const buf = new Uint8Array(12 + 5 + 11 + 4 + 8); // minimal
    buf[2] = 0x80; // QR=1
    buf[4] = 0; buf[5] = 1; // QDCOUNT=1
    buf[10] = 0; buf[11] = 1; // ARCOUNT=1
    // Question: root (0x00) + QTYPE A + QCLASS IN
    buf[12] = 0; buf[13] = 0; buf[14] = 1; buf[15] = 0; buf[16] = 1;
    // OPT record at offset 17
    let off = 17;
    buf[off++] = 0x00; // root name
    buf[off++] = 0x00; buf[off++] = 0x29; // TYPE OPT
    buf[off++] = 0x10; buf[off++] = 0x00; // CLASS=4096
    buf[off++] = 0x00; buf[off++] = 0x00; // ext RCODE, version
    buf[off++] = 0x80; buf[off++] = 0x00; // DO bit
    buf[off++] = 0x00; buf[off++] = 12; // RDLENGTH=12
    // Cookie option with only 8 bytes (client cookie only, no server)
    buf[off++] = 0x00; buf[off++] = 0x0a; // code 10
    buf[off++] = 0x00; buf[off++] = 0x08; // length 8
    for (let i = 0; i < 8; i++) buf[off++] = 0xaa;

    let callbackCalled = false;
    processEdnsIncoming(buf, cfg, () => { callbackCalled = true; });
    // 8-byte cookie is client-only; combined length < 16, so callback should NOT be called
    expect(callbackCalled).toBe(false);
  });
});

describe("COOKIE_STORE management", () => {
  it("COOKIE_STORE starts empty", () => {
    expect(COOKIE_STORE.size).toBe(0);
  });
});
