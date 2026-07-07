// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/unit/cache_key_hardening.test.js
// Cache key security hardening tests:
//   1. Query header flags (opcode / RD / CD) partition the cache so that
//      non-standard queries (CD=1 unvalidated, RD=0 non-recursive, non-QUERY
//      opcodes) cannot poison the shared entry served to standard queries.
//   2. The client-supplied ?type= value is percent-encoded in the cache key
//      so path separators cannot traverse into another record's key.
//   3. buildCacheKey accepts pre-decoded wire GET bytes and produces the same
//      key as the internal base64url decode path.

import { describe, it, expect } from "vitest";
import { buildCacheKey } from "../../src/cache.js";
import { buildDnsQuery } from "../../src/dns.js";

function makeJsonUrl(search) {
  return new URL(`https://worker.example.com/dns-query${search}`);
}

function toBase64url(buf) {
  let b = "";
  for (let i = 0; i < buf.length; i++) b += String.fromCharCode(buf[i]);
  return btoa(b).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

const POST_URL = new URL("https://worker.example.com/dns-query");

// ---------------------------------------------------------------------------
// Flags partitioning - JSON GET ?cd=
// ---------------------------------------------------------------------------

describe("cache key partitioning - JSON GET ?cd=", () => {
  it("?cd=1 produces a different cache key than the same query without cd", () => {
    const plain = buildCacheKey("aabbcc", makeJsonUrl("?name=example.com&type=A"), null);
    const cd = buildCacheKey("aabbcc", makeJsonUrl("?name=example.com&type=A&cd=1"), null);
    expect(cd.url).not.toBe(plain.url);
  });

  it("?cd=0 shares the cache key with the same query without cd", () => {
    const plain = buildCacheKey("aabbcc", makeJsonUrl("?name=example.com&type=A"), null);
    const cd0 = buildCacheKey("aabbcc", makeJsonUrl("?name=example.com&type=A&cd=0"), null);
    expect(cd0.url).toBe(plain.url);
  });

  it("standard JSON GET key has no flags suffix", () => {
    const key = buildCacheKey("aabbcc", makeJsonUrl("?name=example.com&type=A"), null);
    expect(key.url).not.toContain("!o");
  });
});

// ---------------------------------------------------------------------------
// Flags partitioning - wire POST header bits
// ---------------------------------------------------------------------------

describe("cache key partitioning - wire query header flags", () => {
  it("CD=1 wire POST produces a different cache key than CD=0", () => {
    const std = buildDnsQuery("example.com", 1);
    const cd = buildDnsQuery("example.com", 1);
    cd[3] |= 0x10; // set CD bit
    const kStd = buildCacheKey("aabbcc", POST_URL, std);
    const kCd = buildCacheKey("aabbcc", POST_URL, cd);
    expect(kCd.url).not.toBe(kStd.url);
    expect(kCd.url).toContain("!o0r1c1");
  });

  it("RD=0 wire POST produces a different cache key than RD=1", () => {
    const std = buildDnsQuery("example.com", 1);
    const noRd = buildDnsQuery("example.com", 1);
    noRd[2] &= ~0x01; // clear RD bit
    const kStd = buildCacheKey("aabbcc", POST_URL, std);
    const kNoRd = buildCacheKey("aabbcc", POST_URL, noRd);
    expect(kNoRd.url).not.toBe(kStd.url);
    expect(kNoRd.url).toContain("!o0r0c0");
  });

  it("non-QUERY opcode produces a different cache key than opcode QUERY", () => {
    const std = buildDnsQuery("example.com", 1);
    const iquery = buildDnsQuery("example.com", 1);
    iquery[2] |= 0x08; // opcode = 1 (IQUERY)
    const kStd = buildCacheKey("aabbcc", POST_URL, std);
    const kIq = buildCacheKey("aabbcc", POST_URL, iquery);
    expect(kIq.url).not.toBe(kStd.url);
    expect(kIq.url).toContain("!o1r1c0");
  });

  it("standard wire POST key has no flags suffix and still matches JSON GET key", () => {
    const q = buildDnsQuery("example.com", 1);
    const wireKey = buildCacheKey("aabbcc", POST_URL, q);
    const jsonKey = buildCacheKey("aabbcc", makeJsonUrl("?name=example.com&type=A"), null);
    expect(wireKey.url).not.toContain("!o");
    expect(wireKey.url).toBe(jsonKey.url);
  });

  it("CD=1 wire GET produces a different cache key than CD=0 wire GET", () => {
    const std = buildDnsQuery("example.com", 1);
    const cd = buildDnsQuery("example.com", 1);
    cd[3] |= 0x10;
    const kStd = buildCacheKey("aabbcc", makeJsonUrl(`?dns=${toBase64url(std)}`), null);
    const kCd = buildCacheKey("aabbcc", makeJsonUrl(`?dns=${toBase64url(cd)}`), null);
    expect(kCd.url).not.toBe(kStd.url);
  });

  it("wire CD=1 and JSON ?cd=1 share the same cache key", () => {
    const cd = buildDnsQuery("example.com", 1);
    cd[3] |= 0x10;
    const wireKey = buildCacheKey("aabbcc", POST_URL, cd);
    const jsonKey = buildCacheKey("aabbcc", makeJsonUrl("?name=example.com&type=A&cd=1"), null);
    expect(wireKey.url).toBe(jsonKey.url);
  });
});

// ---------------------------------------------------------------------------
// ?type= percent-encoding (path traversal prevention)
// ---------------------------------------------------------------------------

describe("cache key hardening - ?type= is percent-encoded", () => {
  it("slashes in ?type= are percent-encoded and cannot collide with another key", () => {
    const crafted = buildCacheKey("aabbcc", makeJsonUrl("?name=example.com&type=A/../B"), null);
    const target = buildCacheKey("aabbcc", makeJsonUrl("?name=example.com&type=B"), null);
    expect(crafted.url).toContain("%2F");
    expect(crafted.url).not.toBe(target.url);
    expect(crafted.url.startsWith("https://doh-cache.internal/aabbcc/json/")).toBe(true);
  });

  it("?type= traversal cannot escape into another profile's namespace", () => {
    const crafted = buildCacheKey(
      "aabbcc",
      makeJsonUrl("?name=example.com&type=A/../../112233/json/example.com/A"),
      null
    );
    const victim = buildCacheKey("112233", makeJsonUrl("?name=example.com&type=A"), null);
    expect(crafted.url).not.toBe(victim.url);
    expect(new URL(crafted.url).pathname.startsWith("/aabbcc/")).toBe(true);
  });

  it("normal type strings are unaffected by encoding", () => {
    const a = buildCacheKey("aabbcc", makeJsonUrl("?name=example.com&type=AAAA"), null);
    expect(a.url).toContain("/AAAA");
  });
});

// ---------------------------------------------------------------------------
// Pre-decoded wire GET bytes (efficiency path)
// ---------------------------------------------------------------------------

describe("buildCacheKey - pre-decoded wire GET bytes", () => {
  it("produces the same key with and without pre-decoded bytes", () => {
    const q = buildDnsQuery("example.com", 1);
    const url = makeJsonUrl(`?dns=${toBase64url(q)}`);
    const fromUrl = buildCacheKey("aabbcc", url, null);
    const fromBytes = buildCacheKey("aabbcc", url, null, q);
    expect(fromBytes.url).toBe(fromUrl.url);
  });

  it("pre-decoded bytes with CD=1 carry the flags suffix", () => {
    const q = buildDnsQuery("example.com", 1);
    q[3] |= 0x10;
    const url = makeJsonUrl(`?dns=${toBase64url(q)}`);
    const key = buildCacheKey("aabbcc", url, null, q);
    expect(key.url).toContain("!o0r1c1");
  });

  it("unparseable pre-decoded bytes fall back to the base64url wire key", () => {
    const junk = new Uint8Array(12); // QDCOUNT=0, no question to extract
    const url = makeJsonUrl(`?dns=${toBase64url(junk)}`);
    const key = buildCacheKey("aabbcc", url, null, junk);
    expect(key.url).toContain("/wire/");
  });
});
