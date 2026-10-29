// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// The edge cache is shared by every client on a profile, so any input that
// changes what an upstream answers must either appear in the cache key or keep
// the answer out of the shared cache. Two ways that failed:
//
//   - UTS-46 mapping is many-to-one. It deletes ignorable code points and maps
//     compatibility forms onto ".", so distinct DNS names folded onto one key
//     while the upstream was queried with the unmapped bytes.
//   - In ECS forward mode the client's subnet changes the answer but never
//     reached the key.

import { describe, it, expect, vi, afterEach } from "vitest";
import { buildCacheKey } from "../../src/cache.js";
import { makeFakeCache, dispatch } from "../helpers/worker.js";

const ONE = JSON.stringify(["https://u1.example.com/dns-query"]);
const jsonGet = (qs) => new Request(`https://w.example.com/dns-query?${qs}`,
  { headers: { Accept: "application/dns-json" } });
const keyFor = (name) => buildCacheKey("000000",
  new URL(`https://w.example.com/dns-query?name=${encodeURIComponent(name)}&type=A`), null).url;

afterEach(() => vi.restoreAllMocks());

describe("lossy Unicode folding cannot collapse distinct names onto one key", () => {
  it.each([
    ["soft hyphen U+00AD", "exam\u00ADple.com"],
    ["zero-width space U+200B", "exam\u200Bple.com"],
    ["BOM U+FEFF", "exam\uFEFFple.com"],
    ["word joiner U+2060", "exam\u2060ple.com"],
    ["ideographic full stop U+3002", "example\u3002com"],
    ["fullwidth full stop U+FF0E", "example\uFF0Ecom"],
  ])("%s does not share example.com's key", (_label, mutated) => {
    expect(keyFor(mutated)).not.toBe(keyFor("example.com"));
  });

  it("still folds a genuine IDN to punycode", () => {
    // This is what the normalisation exists for and must keep working. It is
    // safe because the upstream is sent the same punycode name (see below).
    expect(keyFor("m\u00FCnchen.de")).toContain("xn--");
    expect(keyFor("m\u00FCnchen.de")).toBe(keyFor("xn--mnchen-3ya.de"));
  });

  it("leaves plain ASCII names alone", () => {
    expect(keyFor("example.com")).toContain("example.com");
    expect(keyFor("EXAMPLE.COM")).toBe(keyFor("example.com"));
  });

  it("U+212A KELVIN SIGN does not share the key of the ASCII letter k", () => {
    // String.toLowerCase maps U+212A to "k"; DNS folds ASCII case only.
    expect(keyFor("faceboo\u212A.com")).not.toBe(keyFor("facebook.com"));
  });

  it("a mutated name does not answer for the real one end to end", async () => {
    const asked = [];
    globalThis.fetch = vi.fn(async (u) => {
      const n = new URL(u.toString()).searchParams.get("name");
      asked.push(n);
      return new Response(JSON.stringify({
        Status: 0, Question: [{ name: `${n}.`, type: 1 }],
        Answer: [{ name: `${n}.`, type: 1, TTL: 300, data: n.includes("\u00AD") ? "6.6.6.6" : "1.1.1.1" }],
      }), { headers: { "Content-Type": "application/dns-json" } });
    });
    const cache = makeFakeCache();
    const env = { UPSTREAM_SERVERS: ONE };

    await dispatch(jsonGet("name=exam%C2%ADple.com&type=A"), { cache, env });
    const { response } = await dispatch(jsonGet("name=example.com&type=A"), { cache, env });

    const body = await response.json();
    expect(body.Answer[0].data).toBe("1.1.1.1");
    expect(asked).toContain("example.com");
  });
});

describe("the upstream is asked exactly what the JSON key records", () => {
  const jsonUpstream = (body) => vi.fn(async () => new Response(JSON.stringify(body),
    { headers: { "Content-Type": "application/dns-json" } }));

  it("forwards the canonical name, type and cd rather than the client's spelling", async () => {
    globalThis.fetch = jsonUpstream({ Status: 0, Answer: [] });
    // "M" + U+00DC + "nchen.DE." with a lower-case type and a spelled-out cd.
    await dispatch(jsonGet("name=M%C3%9Cnchen.DE.&type=aaaa&cd=true"), { env: { UPSTREAM_SERVERS: ONE } });

    const p = new URL(globalThis.fetch.mock.calls[0][0].toString()).searchParams;
    expect([p.get("name"), p.get("type"), p.get("cd")]).toEqual(["xn--mnchen-3ya.de", "AAAA", "1"]);
  });

  it("?cd=true is mirrored into a synthesised response like ?cd=1", async () => {
    globalThis.fetch = jsonUpstream({
      Status: 0, Question: [{ name: "ads.example.", type: 1 }],
      Answer: [{ name: "ads.example.", type: 1, TTL: 60, data: "0.0.0.0" }],
    });
    const { response } = await dispatch(jsonGet("name=ads.example&type=A&cd=true"),
      { env: { UPSTREAM_SERVERS: ONE } });

    expect(response.headers.get("X-Blocked")).toBe("true");
    expect((await response.json()).CD).toBe(true);
  });
});

describe("forwarded ECS answers stay out of the shared cache", () => {
  const ecsUpstream = () => vi.fn(async (u) => {
    const sub = new URL(u.toString()).searchParams.get("edns_client_subnet");
    return new Response(JSON.stringify({
      Status: 0, Question: [{ name: "cdn.example.com.", type: 1 }],
      Answer: [{ name: "cdn.example.com.", type: 1, TTL: 300, data: sub ? "203.0.113.9" : "9.9.9.9" }],
    }), { headers: { "Content-Type": "application/dns-json" } });
  });

  it("does not cache an answer produced for one client's subnet", async () => {
    globalThis.fetch = ecsUpstream();
    const cache = makeFakeCache();
    const env = { UPSTREAM_SERVERS: ONE, PRIVACY_ECS_MODE: "forward" };

    await dispatch(jsonGet("name=cdn.example.com&type=A&edns_client_subnet=203.0.113.0/24"),
      { cache, env });

    expect(cache.store.size).toBe(0);
  });

  it("a later client without ECS is not served the first client's subnet answer", async () => {
    globalThis.fetch = ecsUpstream();
    const cache = makeFakeCache();
    const env = { UPSTREAM_SERVERS: ONE, PRIVACY_ECS_MODE: "forward" };

    await dispatch(jsonGet("name=cdn.example.com&type=A&edns_client_subnet=203.0.113.0/24"),
      { cache, env });
    const { response } = await dispatch(jsonGet("name=cdn.example.com&type=A"), { cache, env });

    expect((await response.json()).Answer[0].data).toBe("9.9.9.9");
  });

  it("strip mode (the default) still caches normally", async () => {
    globalThis.fetch = ecsUpstream();
    const cache = makeFakeCache();

    await dispatch(jsonGet("name=cdn.example.com&type=A"), {
      cache, env: { UPSTREAM_SERVERS: ONE },
    });

    expect(cache.store.size).toBe(1);
  });
});
