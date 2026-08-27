// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// This proxy is used from mobile and IoT clients on metered links, where the
// per-response overhead dominates: a DNS answer is well under 100 bytes, so
// diagnostic headers no client reads were roughly 44% of every response. They
// are emitted only under DEBUG.
//
// The shared test dispatch() defaults DEBUG on so other tests can observe
// behaviour through those headers; these use handleRequest directly to check
// what a real client receives.

import { describe, it, expect, vi, afterEach } from "vitest";
import { handleRequest } from "../../src/handler.js";
import { makeFakeCache } from "../helpers/worker.js";
import { buildDnsQuery, buildDnsResponse } from "../../src/dns.js";

const ONE = JSON.stringify(["https://u1.example.com/dns-query"]);
const DIAGNOSTIC = [
  "X-Blocked", "X-Blocking-Mode", "X-Upstream-Index", "X-All-Responded",
  "X-Client-Cache-TTL", "X-Profile-Id", "X-Worker-Version",
];

async function send(env, ip = "1.2.3.4") {
  globalThis.fetch = vi.fn(async () => new Response(
    buildDnsResponse("a.example.com", ip, 300),
    { headers: { "Content-Type": "application/dns-message" } }));
  const cache = makeFakeCache();
  const originalCaches = globalThis.caches;
  globalThis.caches = { default: cache };
  try {
    return await handleRequest(new Request("https://w.example.com/dns-query", {
      method: "POST",
      headers: { "Content-Type": "application/dns-message" },
      body: buildDnsQuery("a.example.com", 1, 0),
    }), env, { waitUntil: () => {} });
  } finally {
    globalThis.caches = originalCaches;
  }
}

const headerBytes = (resp) => {
  let n = 0;
  for (const [k, v] of resp.headers) n += k.length + v.length + 4;
  return n;
};

afterEach(() => vi.restoreAllMocks());

describe("responses carry no diagnostic headers by default", () => {
  it("omits every diagnostic header", async () => {
    const resp = await send({ UPSTREAM_SERVERS: ONE });
    for (const h of DIAGNOSTIC) expect(resp.headers.get(h), h).toBe(null);
  });

  it("still carries the headers a client acts on", async () => {
    const resp = await send({ UPSTREAM_SERVERS: ONE });
    expect(resp.headers.get("content-type")).toContain("dns-message");
    expect(resp.headers.get("cache-control")).toMatch(/max-age=\d+/);
    expect(resp.headers.get("access-control-allow-origin")).toBe("*");
  });

  it("keeps the answer itself intact", async () => {
    const resp = await send({ UPSTREAM_SERVERS: ONE });
    const body = new Uint8Array(await resp.arrayBuffer());
    expect(body.length).toBeGreaterThan(12);
    expect(Array.from(body.slice(-4))).toEqual([1, 2, 3, 4]);
  });

  it("blocked answers keep their EDE record and TTL", async () => {
    // EDE is a protocol signal, not diagnostics, and a blocked answer is client
    // cached for a day, so its bytes are paid once rather than per query.
    const resp = await send({ UPSTREAM_SERVERS: ONE, BLOCKING_MODE: "null" }, "0.0.0.0");
    const body = new Uint8Array(await resp.arrayBuffer());
    expect((body[10] << 8) | body[11]).toBeGreaterThanOrEqual(1); // ARCOUNT: OPT present
    expect(resp.headers.get("cache-control")).toMatch(/max-age=\d+/);
  });

  it("DEBUG restores the diagnostic headers", async () => {
    const resp = await send({ UPSTREAM_SERVERS: ONE, DEBUG: "true" });
    expect(resp.headers.get("X-Blocked")).toBe("false");
    expect(resp.headers.get("X-Worker-Version")).toBeTruthy();
  });

  it("cuts response header bytes by a third or more", async () => {
    const lean = headerBytes(await send({ UPSTREAM_SERVERS: ONE }));
    const debug = headerBytes(await send({ UPSTREAM_SERVERS: ONE, DEBUG: "true" }));
    expect(lean).toBeLessThan(debug * 0.67);
  });
});
