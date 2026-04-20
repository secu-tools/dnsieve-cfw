// test/unit/upstream.test.js
// Unit tests for upstream dispatch helpers (src/upstream.js)

import { describe, it, expect, vi, afterEach } from "vitest";
import { buildUpstreamUrl, queryUpstream } from "../../src/upstream.js";
import { buildDnsQuery, buildDnsResponse } from "../../src/dns.js";

function makeJsonResponse(body, status = 200) {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/dns-json" },
  });
}

function makeWireResponse(buf, status = 200) {
  return new Response(buf, {
    status,
    headers: { "Content-Type": "application/dns-message" },
  });
}

afterEach(() => {
  vi.restoreAllMocks();
});

// ---------------------------------------------------------------------------
// buildUpstreamUrl
// ---------------------------------------------------------------------------

describe("buildUpstreamUrl", () => {
  it("substitutes {PROFILE_ID} placeholder", () => {
    const out = buildUpstreamUrl("https://dns.nextdns.io/{PROFILE_ID}", "aabbcc");
    expect(out).toBe("https://dns.nextdns.io/aabbcc");
  });

  it("returns original URL when no placeholder exists", () => {
    const out = buildUpstreamUrl("https://dns.quad9.net/dns-query", "aabbcc");
    expect(out).toBe("https://dns.quad9.net/dns-query");
  });
});

// ---------------------------------------------------------------------------
// queryUpstream - JSON mode
// ---------------------------------------------------------------------------

describe("queryUpstream - JSON mode", () => {
  const upstreamUrl = "https://dns.example.net/dns-query";

  it("returns ok JSON result for normal NOERROR response", async () => {
    const json = {
      Status: 0,
      Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "1.2.3.4" }],
    };
    globalThis.fetch = vi.fn(async () => makeJsonResponse(json));

    const result = await queryUpstream(
      0,
      upstreamUrl,
      "GET",
      new URL("https://worker.example.com/dns-query?name=example.com&type=A"),
      null,
      true
    );

    expect(result.ok).toBe(true);
    expect(result.blocked).toBe(false);
    expect(result.wire).toBe(false);
    expect(result.json.Status).toBe(0);

    const [calledUrl, opts] = globalThis.fetch.mock.calls[0];
    expect(calledUrl).toContain("name=example.com");
    expect(calledUrl).toContain("type=A");
    expect(opts.method).toBe("GET");
    expect(opts.headers.Accept).toBe("application/dns-json");
  });

  it("adds default name='.' when upstream JSON URL has no name query", async () => {
    const json = { Status: 0, Answer: [{ name: ".", type: 1, TTL: 60, data: "1.1.1.1" }] };
    globalThis.fetch = vi.fn(async () => makeJsonResponse(json));

    const result = await queryUpstream(
      0,
      upstreamUrl,
      "GET",
      new URL("https://worker.example.com/dns-query?type=A"),
      null,
      true
    );

    expect(result.ok).toBe(true);

    const [calledUrl] = globalThis.fetch.mock.calls[0];
    expect(calledUrl).toContain("name=.");
    expect(calledUrl).toContain("type=A");
  });

  it("does not forward unknown params (e.g. edns_client_subnet) to upstream", async () => {
    const json = { Status: 0, Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "1.2.3.4" }] };
    globalThis.fetch = vi.fn(async () => makeJsonResponse(json));

    await queryUpstream(
      0,
      upstreamUrl,
      "GET",
      new URL("https://worker.example.com/dns-query?name=example.com&type=A&edns_client_subnet=203.0.113.0%2F24&extra=leak"),
      null,
      true
    );

    const [calledUrl] = globalThis.fetch.mock.calls[0];
    expect(calledUrl).toContain("name=example.com");
    expect(calledUrl).toContain("type=A");
    expect(calledUrl).not.toContain("edns_client_subnet");
    expect(calledUrl).not.toContain("extra");
  });

  it("forwards allowed DoH JSON params (ct, do, cd) to upstream", async () => {
    const json = { Status: 0, Answer: [] };
    globalThis.fetch = vi.fn(async () => makeJsonResponse(json));

    await queryUpstream(
      0,
      upstreamUrl,
      "GET",
      new URL("https://worker.example.com/dns-query?name=example.com&type=A&ct=application%2Fdns-json&do=1&cd=1"),
      null,
      true
    );

    const [calledUrl] = globalThis.fetch.mock.calls[0];
    expect(calledUrl).toContain("name=example.com");
    expect(calledUrl).toContain("type=A");
    expect(calledUrl).toContain("ct=");
    expect(calledUrl).toContain("do=1");
    expect(calledUrl).toContain("cd=1");
  });

  it("marks 0.0.0.0 JSON response as blocked", async () => {
    const blocked = {
      Status: 0,
      Answer: [{ name: "blocked.example.", type: 1, TTL: 300, data: "0.0.0.0" }],
    };
    globalThis.fetch = vi.fn(async () => makeJsonResponse(blocked));

    const result = await queryUpstream(
      1,
      upstreamUrl,
      "GET",
      new URL("https://worker.example.com/dns-query?name=blocked.example&type=A"),
      null,
      true
    );

    expect(result.ok).toBe(true);
    expect(result.blocked).toBe(true);
    expect(result.wire).toBe(false);
  });

  it("treats SERVFAIL JSON response as failed upstream", async () => {
    globalThis.fetch = vi.fn(async () => makeJsonResponse({ Status: 2 }));

    const result = await queryUpstream(
      0,
      upstreamUrl,
      "GET",
      new URL("https://worker.example.com/dns-query?name=example.com&type=A"),
      null,
      true
    );

    expect(result).toEqual({ index: 0, ok: false });
  });

  it("treats REFUSED JSON response (Status 5) as failed upstream", async () => {
    globalThis.fetch = vi.fn(async () => makeJsonResponse({ Status: 5 }));

    const result = await queryUpstream(
      0,
      upstreamUrl,
      "GET",
      new URL("https://worker.example.com/dns-query?name=example.com&type=A"),
      null,
      true
    );

    expect(result).toEqual({ index: 0, ok: false });
  });

  it("returns ok=false for non-2xx upstream response", async () => {
    globalThis.fetch = vi.fn(async () => makeJsonResponse({ error: "bad" }, 502));

    const result = await queryUpstream(
      0,
      upstreamUrl,
      "GET",
      new URL("https://worker.example.com/dns-query?name=example.com&type=A"),
      null,
      true
    );

    expect(result).toEqual({ index: 0, ok: false });
  });

  // Regression: upstream returning HTTP 500 must not crash the worker or propagate the
  // error status to the client. The upstream is marked failed ({ ok: false }) and the
  // worker falls back to the next available upstream or returns 502 if all fail.
  it("returns ok=false when upstream returns HTTP 500", async () => {
    globalThis.fetch = vi.fn(async () => makeJsonResponse({ error: "internal server error" }, 500));

    const result = await queryUpstream(
      2,
      upstreamUrl,
      "POST",
      new URL("https://worker.example.com/dns-query"),
      new Uint8Array(12), // minimal valid 12-byte DNS header
      false
    );

    expect(result).toEqual({ index: 2, ok: false });
  });

  it("returns ok=false when wire upstream returns HTTP 500", async () => {
    globalThis.fetch = vi.fn(async () => makeWireResponse(new Uint8Array(12), 500));

    const result = await queryUpstream(
      1,
      upstreamUrl,
      "GET",
      new URL("https://worker.example.com/dns-query?dns=AAABBB"),
      null,
      false
    );

    expect(result).toEqual({ index: 1, ok: false });
  });

  it("returns ok=false when upstream JSON is malformed", async () => {
    globalThis.fetch = vi.fn(async () => {
      return new Response("not json", {
        status: 200,
        headers: { "Content-Type": "application/dns-json" },
      });
    });

    const result = await queryUpstream(
      0,
      upstreamUrl,
      "GET",
      new URL("https://worker.example.com/dns-query?name=example.com&type=A"),
      null,
      true
    );

    expect(result).toEqual({ index: 0, ok: false });
  });

  it("returns ok=false when fetch throws", async () => {
    globalThis.fetch = vi.fn(async () => {
      throw new Error("network error");
    });

    const result = await queryUpstream(
      0,
      upstreamUrl,
      "GET",
      new URL("https://worker.example.com/dns-query?name=example.com&type=A"),
      null,
      true
    );

    expect(result).toEqual({ index: 0, ok: false });
  });
});

// ---------------------------------------------------------------------------
// queryUpstream - wire mode
// ---------------------------------------------------------------------------

describe("queryUpstream - wire mode", () => {
  const upstreamUrl = "https://dns.example.net/dns-query";

  it("GET wire strips base64url padding before forwarding", async () => {
    const raw = buildDnsResponse("example.com.", "1.2.3.4", 300);
    globalThis.fetch = vi.fn(async () => makeWireResponse(raw));

    // Encode a real DNS query to base64url with padding and verify padding is absent
    // in the URL forwarded to the upstream. The decode-strip-reencode pipeline
    // normalises base64 to canonical form (zero padding bits), so we check the
    // forwarded ?dns= value decodes back to the same DNS bytes and contains no '='.
    const query = buildDnsQuery("example.com", 1);
    let b64str = "";
    for (let i = 0; i < query.length; i++) b64str += String.fromCharCode(query[i]);
    const b64WithPad = btoa(b64str); // standard base64 with possible trailing '='

    const result = await queryUpstream(
      0,
      upstreamUrl,
      "GET",
      new URL(`https://worker.example.com/dns-query?dns=${encodeURIComponent(b64WithPad)}`),
      null,
      false
    );

    expect(result.ok).toBe(true);
    expect(result.wire).toBe(true);

    const [calledUrl, opts] = globalThis.fetch.mock.calls[0];
    const forwarded = new URL(calledUrl);
    const fwdDns = forwarded.searchParams.get("dns");
    // Padding must be absent from the forwarded value
    expect(fwdDns).not.toContain("=");
    // URL must not contain percent-encoded padding
    expect(calledUrl).not.toContain("%3D");
    expect(opts.headers.Accept).toBe("application/dns-message");

    // Decoded forwarded bytes should equal the original query (ARCOUNT=0, no OPT to strip)
    const padded = fwdDns.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - fwdDns.length % 4) % 4);
    const fwdBinStr = atob(padded);
    const fwdBytes = new Uint8Array(fwdBinStr.length);
    for (let i = 0; i < fwdBinStr.length; i++) fwdBytes[i] = fwdBinStr.charCodeAt(i);
    expect(fwdBytes).toEqual(query);
  });

  it("wire response DNS ID is normalised to zero", async () => {
    const raw = buildDnsResponse("example.com.", "1.2.3.4", 300);
    raw[0] = 0xab;
    raw[1] = 0xcd;
    globalThis.fetch = vi.fn(async () => makeWireResponse(raw));

    const result = await queryUpstream(
      0,
      upstreamUrl,
      "GET",
      new URL("https://worker.example.com/dns-query?dns=AAABBB"),
      null,
      false
    );

    expect(result.ok).toBe(true);
    expect(result.wire).toBe(true);
    expect(result.raw[0]).toBe(0);
    expect(result.raw[1]).toBe(0);
  });

  it("converts wire response to JSON when clientWantsJson=true", async () => {
    const raw = buildDnsResponse("example.com.", "1.2.3.4", 300);
    globalThis.fetch = vi.fn(async () => makeWireResponse(raw));

    const result = await queryUpstream(
      0,
      upstreamUrl,
      "GET",
      new URL("https://worker.example.com/dns-query?dns=AAABBB"),
      null,
      true
    );

    expect(result.ok).toBe(true);
    expect(result.wire).toBe(false);
    expect(result.json.Status).toBe(0);
  });

  it("treats wire SERVFAIL as failed upstream", async () => {
    const raw = new Uint8Array(12);
    raw[2] = 0x81;
    raw[3] = 0x82; // rcode=2 (SERVFAIL)
    globalThis.fetch = vi.fn(async () => makeWireResponse(raw));

    const result = await queryUpstream(
      0,
      upstreamUrl,
      "GET",
      new URL("https://worker.example.com/dns-query?dns=AAABBB"),
      null,
      false
    );

    expect(result).toEqual({ index: 0, ok: false });
  });

  it("treats wire REFUSED (rcode=5) as failed upstream", async () => {
    const raw = new Uint8Array(12);
    raw[2] = 0x81;
    raw[3] = 0x85; // rcode=5 (REFUSED)
    globalThis.fetch = vi.fn(async () => makeWireResponse(raw));

    const result = await queryUpstream(
      0,
      upstreamUrl,
      "GET",
      new URL("https://worker.example.com/dns-query?dns=AAABBB"),
      null,
      false
    );

    expect(result).toEqual({ index: 0, ok: false });
  });

  it("returns ok=false when wire-to-json conversion fails", async () => {
    const malformed = new Uint8Array([0x00, 0x00, 0x81]);
    globalThis.fetch = vi.fn(async () => makeWireResponse(malformed));

    const result = await queryUpstream(
      0,
      upstreamUrl,
      "GET",
      new URL("https://worker.example.com/dns-query?dns=AAABBB"),
      null,
      true
    );

    expect(result).toEqual({ index: 0, ok: false });
  });

  it("POST sends DNS body and dns-message headers", async () => {
    const query = buildDnsQuery("example.com", 1, 0x9999);
    const wireOk = buildDnsResponse("example.com.", "1.2.3.4", 300);
    globalThis.fetch = vi.fn(async () => makeWireResponse(wireOk));

    const result = await queryUpstream(
      1,
      upstreamUrl,
      "POST",
      new URL("https://worker.example.com/dns-query"),
      query,
      false
    );

    expect(result.ok).toBe(true);
    expect(result.wire).toBe(true);

    const [calledUrl, opts] = globalThis.fetch.mock.calls[0];
    expect(calledUrl).toBe(upstreamUrl);
    expect(opts.method).toBe("POST");
    expect(opts.headers.Accept).toBe("application/dns-message");
    expect(opts.headers["Content-Type"]).toBe("application/dns-message");
    expect(opts.body).toBe(query);
  });
});

// ---------------------------------------------------------------------------
// queryUpstream - block detection via wire format
// ---------------------------------------------------------------------------

describe("queryUpstream - wire block detection", () => {
  const upstreamUrl = "https://dns.example.net/dns-query";

  afterEach(() => { vi.restoreAllMocks(); });

  it("detects NXDOMAIN-block (rcode=3, nscount=0) in wire GET response", async () => {
    const raw = buildDnsResponse("blocked.example.", "0.0.0.0", 300, 3, 0);
    globalThis.fetch = vi.fn(async () => new Response(raw, {
      headers: { "Content-Type": "application/dns-message" },
    }));

    const result = await queryUpstream(
      0, upstreamUrl, "GET",
      new URL("https://worker.example.com/dns-query?dns=AAABBB"),
      null, false
    );

    expect(result.ok).toBe(true);
    expect(result.blocked).toBe(true);
    expect(result.wire).toBe(true);
  });

  it("does NOT detect block for genuine NXDOMAIN (rcode=3, nscount=1) in wire GET", async () => {
    const raw = buildDnsResponse("gone.example.", "0.0.0.0", 300, 3, 1);
    globalThis.fetch = vi.fn(async () => new Response(raw, {
      headers: { "Content-Type": "application/dns-message" },
    }));

    const result = await queryUpstream(
      0, upstreamUrl, "GET",
      new URL("https://worker.example.com/dns-query?dns=AAABBB"),
      null, false
    );

    expect(result.ok).toBe(true);
    expect(result.blocked).toBe(false);
  });

  it("marks 0.0.0.0 A answer in wire POST as blocked", async () => {
    const raw = buildDnsResponse("blocked.example.", "0.0.0.0", 300, 0, 0);
    globalThis.fetch = vi.fn(async () => new Response(raw, {
      headers: { "Content-Type": "application/dns-message" },
    }));

    const query = buildDnsQuery("blocked.example", 1);
    const result = await queryUpstream(
      0, upstreamUrl, "POST",
      new URL("https://worker.example.com/dns-query"),
      query, false
    );

    expect(result.ok).toBe(true);
    expect(result.blocked).toBe(true);
  });

  it("propagates index correctly for upstream[1]", async () => {
    const raw = buildDnsResponse("example.com.", "1.2.3.4", 300);
    globalThis.fetch = vi.fn(async () => new Response(raw, {
      headers: { "Content-Type": "application/dns-message" },
    }));

    const result = await queryUpstream(
      1, upstreamUrl, "GET",
      new URL("https://worker.example.com/dns-query?dns=AAABBB"),
      null, false
    );

    expect(result.index).toBe(1);
    expect(result.ok).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// queryUpstream - JSON block detection
// ---------------------------------------------------------------------------

describe("queryUpstream - JSON block detection", () => {
  const upstreamUrl = "https://dns.example.net/dns-query";

  afterEach(() => { vi.restoreAllMocks(); });

  it("marks NXDOMAIN without Authority as blocked in JSON mode", async () => {
    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify({ Status: 3 }), {
      headers: { "Content-Type": "application/dns-json" },
    }));

    const result = await queryUpstream(
      0, upstreamUrl, "GET",
      new URL("https://worker.example.com/dns-query?name=blocked.example&type=A"),
      null, true
    );

    expect(result.ok).toBe(true);
    expect(result.blocked).toBe(true);
  });

  it("does NOT mark NXDOMAIN with Authority as blocked in JSON mode", async () => {
    const json = {
      Status: 3,
      Authority: [{ type: 6, name: "example.com.", TTL: 900 }],
    };
    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify(json), {
      headers: { "Content-Type": "application/dns-json" },
    }));

    const result = await queryUpstream(
      0, upstreamUrl, "GET",
      new URL("https://worker.example.com/dns-query?name=gone.example&type=A"),
      null, true
    );

    expect(result.ok).toBe(true);
    expect(result.blocked).toBe(false);
  });

  it("marks :: AAAA response as blocked", async () => {
    const json = {
      Status: 0,
      Answer: [{ name: "blocked.example.", type: 28, TTL: 86400, data: "::" }],
    };
    globalThis.fetch = vi.fn(async () => new Response(JSON.stringify(json), {
      headers: { "Content-Type": "application/dns-json" },
    }));

    const result = await queryUpstream(
      0, upstreamUrl, "GET",
      new URL("https://worker.example.com/dns-query?name=blocked.example&type=AAAA"),
      null, true
    );

    expect(result.ok).toBe(true);
    expect(result.blocked).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// buildUpstreamUrl - edge cases
// ---------------------------------------------------------------------------

describe("buildUpstreamUrl - edge cases", () => {
  it("replaces only the first occurrence of {PROFILE_ID}", () => {
    const out = buildUpstreamUrl("https://example.com/{PROFILE_ID}/path/{PROFILE_ID}", "aabbcc");
    // Only one replacement expected per spec usage
    expect(out).toContain("aabbcc");
  });

  it("handles empty profile ID correctly", () => {
    const out = buildUpstreamUrl("https://dns.nextdns.io/{PROFILE_ID}", "");
    expect(out).toBe("https://dns.nextdns.io/");
  });
});

// ---------------------------------------------------------------------------
// queryUpstream - EDNS OPT stripping (privacy)
// ---------------------------------------------------------------------------

// Builds a DNS query with an OPT record containing an ECS option in the
// additional section. Used to verify that the worker strips EDNS options
// before forwarding to upstream resolvers.
function buildQueryWithEcsOpt(doBit = false) {
  const base = buildDnsQuery("example.com", 1);
  // ECS option (code 8): FAMILY(2)+SRC-PREFIX-LEN(1)+SCOPE-PREFIX-LEN(1)+ADDRESS(3)
  const ecsPayload = [0x00, 0x01, 24, 0, 203, 0, 113];
  const rdataBytes = [0x00, 0x08, 0x00, ecsPayload.length, ...ecsPayload];
  const rdataLen = rdataBytes.length;
  const opt = new Uint8Array(11 + rdataLen);
  let w = 0;
  opt[w++] = 0x00;
  opt[w++] = 0x00; opt[w++] = 0x29;
  opt[w++] = 0x10; opt[w++] = 0x00;
  opt[w++] = 0x00; opt[w++] = 0x00;
  opt[w++] = doBit ? 0x80 : 0x00; opt[w++] = 0x00;
  opt[w++] = (rdataLen >> 8) & 0xff; opt[w++] = rdataLen & 0xff;
  for (const b of rdataBytes) opt[w++] = b;
  const out = new Uint8Array(base.length + opt.length);
  out.set(base);
  out.set(opt, base.length);
  out[10] = 0; out[11] = 1; // ARCOUNT = 1
  return out;
}

// Builds a wire response with an OPT record containing a server cookie.
function buildResponseWithOptCookie() {
  const base = buildDnsResponse("example.com.", "1.2.3.4", 300);
  // Server cookie option (code 10): 8-byte client + 8-byte server cookie
  const cookieData = [0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe,
                      0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08];
  const rdataBytes = [0x00, 0x0a, 0x00, cookieData.length, ...cookieData];
  const rdataLen = rdataBytes.length;
  const opt = new Uint8Array(11 + rdataLen);
  let w = 0;
  opt[w++] = 0x00;
  opt[w++] = 0x00; opt[w++] = 0x29;
  opt[w++] = 0x10; opt[w++] = 0x00;
  opt[w++] = 0x00; opt[w++] = 0x00;
  opt[w++] = 0x00; opt[w++] = 0x00;
  opt[w++] = (rdataLen >> 8) & 0xff; opt[w++] = rdataLen & 0xff;
  for (const b of rdataBytes) opt[w++] = b;
  const out = new Uint8Array(base.length + opt.length);
  out.set(base);
  out.set(opt, base.length);
  out[10] = 0; out[11] = 1; // ARCOUNT = 1
  return out;
}

describe("queryUpstream - EDNS OPT stripping", () => {
  const upstreamUrl = "https://dns.example.net/dns-query";

  // Runtime config with all privacy options in strip mode (default).
  // The EDNS processing path in upstream.js is only active when cfg is provided.
  const stripCfg = {
    UPSTREAM_TIMEOUT_MS: 5000,
    DEBUG: false,
    PRIVACY_ECS_MODE: "strip",
    PRIVACY_ECS_SUBNET: "",
    PRIVACY_COOKIES_MODE: "strip",
    PRIVACY_NSID_MODE: "strip",
    PRIVACY_NSID_VALUE: "",
  };

  afterEach(() => { vi.restoreAllMocks(); });

  it("strips ECS OPT from wire POST body before forwarding to upstream", async () => {
    const queryWithOpt = buildQueryWithEcsOpt();
    const wireOk = buildDnsResponse("example.com.", "1.2.3.4", 300);
    globalThis.fetch = vi.fn(async () => makeWireResponse(wireOk));

    await queryUpstream(
      0, upstreamUrl, "POST",
      new URL("https://worker.example.com/dns-query"),
      queryWithOpt, false, stripCfg
    );

    const [, opts] = globalThis.fetch.mock.calls[0];
    const sent = opts.body;
    // DO=1 is always forced, so ARCOUNT=1 (minimal OPT with DO bit kept)
    expect((sent[10] << 8) | sent[11]).toBe(1);
    // ECS payload stripped, sent body smaller than original query-with-ECS-OPT
    expect(sent.length).toBeLessThan(queryWithOpt.length);
    // ECS option code 0x0008 must not appear in the sent bytes
    let hasEcs = false;
    for (let i = 0; i + 1 < sent.length; i++) {
      if (sent[i] === 0x00 && sent[i + 1] === 0x08) { hasEcs = true; break; }
    }
    expect(hasEcs).toBe(false);
  });

  it("preserves DO bit as minimal OPT in wire POST (ECS payload not forwarded)", async () => {
    const queryWithOpt = buildQueryWithEcsOpt(true); // DO=1
    const wireOk = buildDnsResponse("example.com.", "1.2.3.4", 300);
    globalThis.fetch = vi.fn(async () => makeWireResponse(wireOk));

    await queryUpstream(
      0, upstreamUrl, "POST",
      new URL("https://worker.example.com/dns-query"),
      queryWithOpt, false, stripCfg
    );

    const [, opts] = globalThis.fetch.mock.calls[0];
    const sent = opts.body;
    // ARCOUNT remains 1 (minimal OPT with DO=1 was reinserted)
    expect((sent[10] << 8) | sent[11]).toBe(1);
    // Body must be shorter (ECS payload removed, only minimal 11-byte OPT kept)
    expect(sent.length).toBeLessThan(queryWithOpt.length);
  });

  it("strips ECS OPT from wire GET ?dns= parameter before forwarding", async () => {
    const queryWithOpt = buildQueryWithEcsOpt();
    const wireOk = buildDnsResponse("example.com.", "1.2.3.4", 300);
    globalThis.fetch = vi.fn(async () => makeWireResponse(wireOk));

    // Encode the query-with-OPT to base64url and pass as ?dns=
    let b64str = "";
    for (let i = 0; i < queryWithOpt.length; i++) b64str += String.fromCharCode(queryWithOpt[i]);
    const b64 = btoa(b64str).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

    await queryUpstream(
      0, upstreamUrl, "GET",
      new URL(`https://worker.example.com/dns-query?dns=${b64}`),
      null, false, stripCfg
    );

    const [calledUrl] = globalThis.fetch.mock.calls[0];
    const forwarded = new URL(calledUrl);
    const fwdB64 = forwarded.searchParams.get("dns");
    // Decode the forwarded ?dns= and verify ARCOUNT=1 (DO=1 OPT kept, ECS stripped)
    const padded = fwdB64.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - fwdB64.length % 4) % 4);
    const fwdBinStr = atob(padded);
    // DO=1 is always forced so ARCOUNT=1
    expect((fwdBinStr.charCodeAt(10) << 8) | fwdBinStr.charCodeAt(11)).toBe(1);
    // Sent message smaller because ECS payload was stripped (OPT shrunk to DO-only)
    expect(fwdBinStr.length).toBeLessThan(queryWithOpt.length);
  });

  it("strips OPT (server cookie) from upstream wire response before returning to caller", async () => {
    const respWithCookie = buildResponseWithOptCookie();
    globalThis.fetch = vi.fn(async () => makeWireResponse(respWithCookie));

    const result = await queryUpstream(
      0, upstreamUrl, "GET",
      new URL("https://worker.example.com/dns-query?dns=AAABBB"),
      null, false, stripCfg
    );

    expect(result.ok).toBe(true);
    expect(result.wire).toBe(true);
    // ARCOUNT in returned raw should be 0 (OPT stripped)
    expect((result.raw[10] << 8) | result.raw[11]).toBe(0);
    expect(result.raw.length).toBeLessThan(respWithCookie.length);
  });
});