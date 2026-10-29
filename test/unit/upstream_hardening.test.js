// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// Upstream responses are attacker-adjacent: a compromised or broken resolver
// must not be able to have its output served, cached, or hang the fan-out.

import { describe, it, expect, vi, afterEach } from "vitest";
import { makeFakeCache, dispatch } from "../helpers/worker.js";
import { buildDnsQuery, buildDnsResponse } from "../../src/dns.js";
import { queryUpstream, COOKIE_STORE } from "../../src/upstream.js";
import { getConfig } from "../../src/config.js";

const TWO_UPSTREAMS = JSON.stringify([
  "https://u1.example.com/dns-query",
  "https://u2.example.com/dns-query",
]);

const wirePost = (name) => new Request("https://w.example.com/dns-query", {
  method: "POST",
  headers: { "Content-Type": "application/dns-message" },
  body: buildDnsQuery(name, 1, 0),
});

const wireResp = (body) => new Response(body, {
  status: 200, headers: { "Content-Type": "application/dns-message" },
});

afterEach(() => vi.restoreAllMocks());

describe("upstream responses are validated before use", () => {
  it("a 200 with a body too short to be a DNS message does not win", async () => {
    // Upstream 0 answers first with an empty body; upstream 1 answers properly.
    // pickBestResult prefers the lowest index, so an unvalidated empty body
    // would be served to the client and written to the shared cache.
    globalThis.fetch = vi.fn(async (u) =>
      u.toString().includes("u1.")
        ? wireResp(new Uint8Array(0))
        : wireResp(buildDnsResponse("ok.example.com", "1.2.3.4", 300)));

    const cache = makeFakeCache();
    const { response } = await dispatch(wirePost("ok.example.com"), {
      cache, env: { UPSTREAM_SERVERS: TWO_UPSTREAMS },
    });

    const body = new Uint8Array(await response.arrayBuffer());
    expect(body.length).toBeGreaterThanOrEqual(12);
    expect(response.headers.get("X-Upstream-Index")).toBe("1");
  });

  it("a truncated 3-byte body is rejected rather than cached", async () => {
    globalThis.fetch = vi.fn(async () => wireResp(new Uint8Array([1, 2, 3])));
    const cache = makeFakeCache();

    await dispatch(wirePost("short.example.com"), {
      cache, env: { UPSTREAM_SERVERS: TWO_UPSTREAMS },
    });

    expect(cache.store.size).toBe(0);
  });

  it("an oversized upstream body is refused", async () => {
    const huge = new Uint8Array(200000);
    huge.set(buildDnsResponse("big.example.com", "1.2.3.4", 300));
    globalThis.fetch = vi.fn(async () => wireResp(huge));
    const cache = makeFakeCache();

    await dispatch(wirePost("big.example.com"), {
      cache, env: { UPSTREAM_SERVERS: TWO_UPSTREAMS, MAX_DNS_MESSAGE_SIZE: "65535" },
    });

    expect(cache.store.size).toBe(0);
  });
});

describe("background refresh honours the all-responded rule", () => {
  it("does not cache a partial fan-out", async () => {
    // The main path only caches when every upstream answered. If the refresh
    // ignored that, a transient failure of the blocking upstream would replace
    // a blocked verdict with the surviving upstream's clean answer.
    const env = {
      UPSTREAM_SERVERS: TWO_UPSTREAMS,
      WORKER_CACHE_TTL_SECONDS: "100",
      CACHE_RENEW_PERCENT: "90",
      MIN_CACHE_TTL_FLOOR: "60",
    };
    const cache = makeFakeCache();

    globalThis.fetch = vi.fn(async () => wireResp(buildDnsResponse("p.example.com", "1.1.1.1", 300)));
    await dispatch(wirePost("p.example.com"), { cache, env });

    // Age the entry into the renewal window.
    const key = [...cache.store.keys()][0];
    const stored = cache.store.get(key);
    const ab = await stored.arrayBuffer();
    const h = new Headers(stored.headers);
    h.set("x-cache-inserted-at", String(Math.floor(Date.now() / 1000) - 95));
    cache.store.set(key, new Response(ab, { status: 200, headers: h }));

    // Only the first upstream answers on the refresh.
    let call = 0;
    globalThis.fetch = vi.fn(async () => {
      if (call++ === 0) return wireResp(buildDnsResponse("p.example.com", "9.9.9.9", 300));
      throw new Error("upstream down");
    });

    await dispatch(wirePost("p.example.com"), { cache, env });

    const after = new Uint8Array(await cache.store.get(key).clone().arrayBuffer());
    const rdata = Array.from(after.slice(after.length - 4)).join(".");
    expect(rdata).toBe("1.1.1.1"); // original entry retained, not the partial result
  });
});

describe("upstream bodies are bounded while they are read", () => {
  const CLIENT_URL = new URL("https://w.example.com/dns-query");

  it("a body without Content-Length is abandoned once it passes the cap", async () => {
    // A chunked stream declares no size, so only reading it incrementally can
    // stop it; buffering it whole first would hold it all in the isolate.
    let sent = 0;
    globalThis.fetch = vi.fn(async () => new Response(new ReadableStream({
      pull(controller) {
        if (sent >= 1_000_000) { controller.close(); return; }
        controller.enqueue(new Uint8Array(10_000));
        sent += 10_000;
      },
    }), { status: 200, headers: { "Content-Type": "application/dns-message" } }));

    const res = await queryUpstream(0, "https://u1.example.com/dns-query", "POST", CLIENT_URL,
      buildDnsQuery("a.example", 1), false, getConfig({}));
    expect(res.ok).toBe(false);
    expect(sent).toBeLessThan(1_000_000);
  });

  it("a JSON answer larger than the wire limit is still accepted", async () => {
    // JSON spells out every owner name, so it outgrows the same answer on the
    // wire; capping it at MAX_DNS_MESSAGE_SIZE turned it into SERVFAIL.
    const Answer = [];
    for (let i = 0; i < 1500; i++) Answer.push({ name: "big.example.", type: 1, TTL: 300, data: `10.0.${i >> 8}.${i & 255}` });
    const body = JSON.stringify({ Status: 0, Question: [{ name: "big.example.", type: 1 }], Answer });
    expect(body.length).toBeGreaterThan(65535);
    globalThis.fetch = vi.fn(async () => new Response(body, { headers: { "Content-Type": "application/dns-json" } }));

    const res = await queryUpstream(0, "https://u1.example.com/dns-query", "GET",
      new URL("https://w.example.com/dns-query?name=big.example&type=A"), null, true, getConfig({}));
    expect(res.ok).toBe(true);
    expect(res.json.Answer.length).toBe(1500);
  });
});

describe("per-upstream cookie state is bounded", () => {
  afterEach(() => COOKIE_STORE.clear());

  it("stays capped when a {PROFILE_ID} template yields one upstream URL per profile", async () => {
    // Any client can name any of 16.7M profile ids, so an uncapped store keyed
    // by resolved URL grows until the isolate runs out of memory.
    COOKIE_STORE.clear();
    globalThis.fetch = vi.fn(async () => wireResp(buildDnsResponse("a.example", "1.2.3.4")));
    const cfg = getConfig({});
    const url = new URL("https://w.example.com/dns-query");
    const q = buildDnsQuery("a.example", 1);
    for (let i = 0; i < 1100; i++) {
      await queryUpstream(0, `https://u.example.com/${i.toString(16).padStart(6, "0")}`, "POST", url, q, false, cfg);
    }
    expect(COOKIE_STORE.size).toBe(1024);
    // The newest profiles survive eviction; the oldest were dropped first.
    expect(COOKIE_STORE.has("https://u.example.com/00044b")).toBe(true);
    expect(COOKIE_STORE.has("https://u.example.com/000000")).toBe(false);
  });
});
