// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// The cache key and the forwarded upstream query must derive from the same
// parameter values. buildCacheKey reads them with get() (first occurrence);
// forwarding once iterated the client's params with set() (last occurrence
// wins), so a repeated key made the two disagree and let any client bind an
// arbitrary answer to any name for every client sharing the profile.

import { describe, it, expect, vi, afterEach } from "vitest";
import { makeFakeCache, dispatch } from "../helpers/worker.js";

const TWO_UPSTREAMS = JSON.stringify([
  "https://u1.example.com/dns-query",
  "https://u2.example.com/dns-query",
]);

// Answers whatever name it was actually asked for.
function honestJsonUpstream(seen) {
  return vi.fn(async (u) => {
    const href = u.toString();
    seen.push(href);
    const name = new URL(href).searchParams.get("name");
    return new Response(JSON.stringify({
      Status: 0,
      Question: [{ name: `${name}.`, type: 1 }],
      Answer: [{ name: `${name}.`, type: 1, TTL: 300, data: name === "attacker.example" ? "6.6.6.6" : "1.1.1.1" }],
    }), { headers: { "Content-Type": "application/dns-json" } });
  });
}

const jsonGet = (qs) =>
  new Request(`https://w.example.com/dns-query?${qs}`, { headers: { Accept: "application/dns-json" } });

afterEach(() => vi.restoreAllMocks());

describe("duplicate query parameters cannot poison another name's cache entry", () => {
  it("forwards the same name the cache key is built from", async () => {
    const seen = [];
    globalThis.fetch = honestJsonUpstream(seen);
    const cache = makeFakeCache();

    await dispatch(jsonGet("name=victim.example&type=A&name=attacker.example"), {
      cache, env: { UPSTREAM_SERVERS: TWO_UPSTREAMS },
    });

    const forwarded = new URL(seen[0]).searchParams.get("name");
    const key = [...cache.store.keys()][0];
    expect(forwarded).toBe("victim.example");
    expect(key).toContain("victim.example");
  });

  it("does not serve an attacker-chosen answer to a later victim query", async () => {
    const seen = [];
    globalThis.fetch = honestJsonUpstream(seen);
    const cache = makeFakeCache();
    const env = { UPSTREAM_SERVERS: TWO_UPSTREAMS };

    await dispatch(jsonGet("name=victim.example&type=A&name=attacker.example"), { cache, env });
    const { response } = await dispatch(jsonGet("name=victim.example&type=A"), { cache, env });

    const body = await response.json();
    expect(body.Answer[0].data).toBe("1.1.1.1");
    expect(body.Answer[0].name).toBe("victim.example.");
  });

  it("cannot smuggle cd=1 into the cd=0 cache namespace", async () => {
    // queryFlagsVariant partitions CD=1 into its own namespace; a duplicate cd
    // must not let a CD=1 upstream query land in the standard entry.
    const seen = [];
    globalThis.fetch = honestJsonUpstream(seen);
    const cache = makeFakeCache();

    await dispatch(jsonGet("name=victim.example&type=A&cd=0&cd=1"), {
      cache, env: { UPSTREAM_SERVERS: TWO_UPSTREAMS },
    });

    const forwardedCd = new URL(seen[0]).searchParams.get("cd");
    const key = [...cache.store.keys()][0];
    // The key carries no CD variant, so the upstream query must not have cd=1.
    expect(key).not.toContain("c1");
    expect(forwardedCd).not.toBe("1");
  });
});

describe("blocked responses do not disclose the upstream URL path", () => {
  // An upstream template such as https://dns.nextdns.io/{PROFILE_ID} carries
  // the operator's profile id in its path. That id is effectively a bearer
  // secret, and the RFC 8914 EDE extra-text field goes to every client that
  // trips a block.
  it("names the upstream by host only", async () => {
    const { buildDnsQuery, buildDnsResponse } = await import("../../src/dns.js");
    globalThis.fetch = vi.fn(async () => new Response(
      buildDnsResponse("ads.example.com", "0.0.0.0", 60),
      { headers: { "Content-Type": "application/dns-message" } }));

    const { response } = await dispatch(new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: buildDnsQuery("ads.example.com", 1, 0),
    }), {
      cache: makeFakeCache(),
      env: {
        UPSTREAM_SERVERS: JSON.stringify(["https://dns.nextdns.io/{PROFILE_ID}"]),
        GENERAL_PROFILE_ID: "a1b2c3",
        BLOCKING_MODE: "null",
      },
    });

    const text = new TextDecoder().decode(new Uint8Array(await response.arrayBuffer()));
    expect(text).toContain("dns.nextdns.io");
    expect(text).not.toContain("a1b2c3");
  });
});

describe("wire and JSON clients never receive each other's body format", () => {
  // A cache hit is replayed without format conversion, so a shared entry hands
  // a wire stub a JSON body (or the reverse) -- unparseable, for the whole
  // entry lifetime. An OS-level DoH profile is a wire client, so a single JSON
  // GET for the same name would break it until the TTL expired.
  const ONE = JSON.stringify(["https://u1.example.com/dns-query"]);
  // Answers in whatever format the request asked for, as a conforming DoH
  // endpoint does.
  const formatAwareUpstream = async () => {
    const { buildDnsResponse } = await import("../../src/dns.js");
    return vi.fn(async (u) => {
      const wantsJson = u.toString().includes("name=");
      return wantsJson
        ? new Response(JSON.stringify({
            Status: 0,
            Question: [{ name: "example.com.", type: 1 }],
            Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "1.2.3.4" }],
          }), { headers: { "Content-Type": "application/dns-json" } })
        : new Response(buildDnsResponse("example.com", "1.2.3.4", 300),
            { headers: { "Content-Type": "application/dns-message" } });
    });
  };

  it("a wire POST after a JSON GET still gets wire format", async () => {
    globalThis.fetch = await formatAwareUpstream();
    const cache = makeFakeCache();
    const env = { UPSTREAM_SERVERS: ONE };

    await dispatch(new Request("https://w.example.com/dns-query?name=example.com&type=A",
      { headers: { Accept: "application/dns-json" } }), { cache, env });

    const { buildDnsQuery } = await import("../../src/dns.js");
    const { response } = await dispatch(new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: buildDnsQuery("example.com", 1, 0),
    }), { cache, env });

    expect(response.headers.get("content-type")).toContain("dns-message");
    const body = await response.text();
    expect(body.startsWith("{")).toBe(false);
  });

  it("a JSON GET after a wire POST still gets JSON", async () => {
    const { buildDnsQuery, buildDnsResponse } = await import("../../src/dns.js");
    globalThis.fetch = vi.fn(async () => new Response(
      buildDnsResponse("example.com", "1.2.3.4", 300),
      { headers: { "Content-Type": "application/dns-message" } }));
    const cache = makeFakeCache();
    const env = { UPSTREAM_SERVERS: ONE };

    await dispatch(new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: buildDnsQuery("example.com", 1, 0),
    }), { cache, env });

    const { response } = await dispatch(
      new Request("https://w.example.com/dns-query?name=example.com&type=A",
        { headers: { Accept: "application/dns-json" } }), { cache, env });

    expect(response.headers.get("content-type")).toContain("dns-json");
    expect(JSON.parse(await response.text()).Status).toBe(0);
  });
});

describe("CD is recognised in every spelling the upstream accepts", () => {
  // upstream.js forwards ?cd verbatim. If the key only recognises "1", then
  // ?cd=true reaches the upstream with DNSSEC validation disabled while the
  // answer is keyed as a standard query -- the partition queryFlagsVariant
  // exists to enforce is bypassed.
  it.each(["1", "true", "TRUE", "t", "yes"])("?cd=%s partitions the cache key", async (v) => {
    const { buildCacheKey } = await import("../../src/cache.js");
    const key = buildCacheKey("000000",
      new URL(`https://w.example.com/dns-query?name=x.com&type=A&cd=${v}`), null);
    expect(key.url).toContain("c1");
  });

  it("a falsey cd does not partition", async () => {
    const { buildCacheKey } = await import("../../src/cache.js");
    for (const v of ["0", "false", ""]) {
      const key = buildCacheKey("000000",
        new URL(`https://w.example.com/dns-query?name=x.com&type=A&cd=${v}`), null);
      expect(key.url).not.toContain("!o");
    }
  });
});
