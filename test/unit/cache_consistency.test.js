// test/unit/cache_consistency.test.js
// Tests for cache key consistency: trailing dot normalization, wire/JSON key
// unification, malformed query fallback, and canonicalization.

import { describe, it, expect } from "vitest";
import { buildCacheKey } from "../../src/cache.js";
import { buildDnsQuery } from "../../src/dns.js";

// ---------------------------------------------------------------------------
// Trailing-dot FQDN consistency (F-11 fix)
// ---------------------------------------------------------------------------

describe("Cache key trailing-dot canonicalization", () => {
  it("JSON GET: example.com and example.com. produce the same cache key", () => {
    const url1 = new URL("https://worker.example.com/dns-query?name=example.com&type=A");
    const url2 = new URL("https://worker.example.com/dns-query?name=example.com.&type=A");
    const key1 = buildCacheKey("000000", url1, null);
    const key2 = buildCacheKey("000000", url2, null);
    expect(key1.url).toBe(key2.url);
  });

  it("JSON GET: trailing dot is stripped before cache key construction", () => {
    const url = new URL("https://worker.example.com/dns-query?name=example.com.&type=A");
    const key = buildCacheKey("000000", url, null);
    expect(key.url).not.toContain("example.com.");
    expect(key.url).toContain("example.com");
  });

  it("wire POST: name with trailing dot produces same key as without", () => {
    // Wire format always produces trailing dot from readDnsName
    const query = buildDnsQuery("example.com", 1);
    const url = new URL("https://worker.example.com/dns-query");
    const key = buildCacheKey("000000", url, query);
    // Should strip trailing dot from the wire-extracted name
    expect(key.url).not.toMatch(/example\.com\.\//);
  });
});

// ---------------------------------------------------------------------------
// Wire GET and POST produce same cache key for same query
// ---------------------------------------------------------------------------

describe("Cache key unification across request formats", () => {
  it("wire POST and JSON GET for same query produce same key", () => {
    const query = buildDnsQuery("example.com", 1);
    const urlPost = new URL("https://worker.example.com/dns-query");
    const keyPost = buildCacheKey("000000", urlPost, query);

    const urlJson = new URL("https://worker.example.com/dns-query?name=example.com&type=A");
    const keyJson = buildCacheKey("000000", urlJson, null);

    expect(keyPost.url).toBe(keyJson.url);
  });

  it("wire GET and JSON GET for same query produce same key", () => {
    const query = buildDnsQuery("example.com", 1);
    // Encode as base64url
    let b64 = "";
    for (let i = 0; i < query.length; i++) b64 += String.fromCharCode(query[i]);
    const encoded = btoa(b64).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

    const urlWire = new URL(`https://worker.example.com/dns-query?dns=${encoded}`);
    const keyWire = buildCacheKey("000000", urlWire, null);

    const urlJson = new URL("https://worker.example.com/dns-query?name=example.com&type=A");
    const keyJson = buildCacheKey("000000", urlJson, null);

    expect(keyWire.url).toBe(keyJson.url);
  });
});

// ---------------------------------------------------------------------------
// Cache key case-insensitivity
// ---------------------------------------------------------------------------

describe("Cache key case insensitivity", () => {
  it("EXAMPLE.COM and example.com use same cache key", () => {
    const url1 = new URL("https://worker.example.com/dns-query?name=EXAMPLE.COM&type=A");
    const url2 = new URL("https://worker.example.com/dns-query?name=example.com&type=A");
    const key1 = buildCacheKey("000000", url1, null);
    const key2 = buildCacheKey("000000", url2, null);
    expect(key1.url).toBe(key2.url);
  });

  it("mixed case produces same key", () => {
    const url1 = new URL("https://worker.example.com/dns-query?name=Example.COM&type=a");
    const url2 = new URL("https://worker.example.com/dns-query?name=example.com&type=A");
    const key1 = buildCacheKey("000000", url1, null);
    const key2 = buildCacheKey("000000", url2, null);
    expect(key1.url).toBe(key2.url);
  });
});

// ---------------------------------------------------------------------------
// Profile isolation in cache keys
// ---------------------------------------------------------------------------

describe("Cache key profile isolation", () => {
  it("different profiles produce different cache keys", () => {
    const url = new URL("https://worker.example.com/dns-query?name=example.com&type=A");
    const key1 = buildCacheKey("000000", url, null);
    const key2 = buildCacheKey("aabbcc", url, null);
    expect(key1.url).not.toBe(key2.url);
  });
});

// ---------------------------------------------------------------------------
// Malformed wire inputs
// ---------------------------------------------------------------------------

describe("Cache key for malformed wire queries", () => {
  it("wire POST with unreadable query uses SHA-256 fallback", async () => {
    const malformed = new Uint8Array(12);
    // QDCOUNT=1 but no actual question section
    malformed[4] = 0; malformed[5] = 1;
    const url = new URL("https://worker.example.com/dns-query");
    const key = buildCacheKey("000000", url, malformed);
    // May be a Promise (SHA-256 fallback)
    const resolved = await key;
    expect(resolved.url).toContain("wire/");
  });

  it("wire GET with invalid base64 uses raw fallback", () => {
    const url = new URL("https://worker.example.com/dns-query?dns=!!invalid!!");
    const key = buildCacheKey("000000", url, null);
    // Should not throw, uses fallback
    expect(key.url).toContain("wire/");
  });
});
