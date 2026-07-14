// SPDX-License-Identifier: MIT
// dnsieve-cfw - Cache key construction and response caching
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// Cache key design - unified name+type format for all request types:
//   https://doh-cache.internal/{profileId}/json/{name}/{type}
//
// JSON GET, wire GET (?dns=), and wire POST share the same key format, so
// DO=0/DO=1 clients and different request formats for the same query all hit
// one cache entry (the proxy always requests DO=1 upstream, so cached
// responses always contain DNSSEC records). For wire requests the question
// name and type are extracted from the decoded message and normalised
// (toASCII / normalizeType); malformed queries fall back to a SHA-256 hash
// key. DNS transaction ID is always 0 in cached messages (RFC 8484 SS.4.1).

import { HEX_TABLE, toASCII, normalizeType, stripBase64Padding, extractMinTtlWire, extractMinTtl, extractQueryNameType, DNS_NUMBER_TO_TYPE } from "./dns.js";
import {
  MIN_CACHE_TTL_FLOOR,
  WORKER_CACHE_TTL_SECONDS,
  WORKER_BLOCKED_CACHE_TTL_SECONDS,
  CLIENT_CACHE_TTL_SECONDS,
  CLIENT_BLOCKED_CACHE_TTL_SECONDS,
  CACHE_RENEW_PERCENT,
} from "./config.js";

// Build the canonical cache key URL from extracted query name and numeric type.
// The type segment is percent-encoded: for JSON GET requests it can contain an
// arbitrary client-supplied string, and a raw "/" or "../" inside it would let
// a crafted ?type= value collide with (and poison) another record's cache key.
// flagsVariant namespaces non-standard queries (see queryFlagsVariant).
function metaToCacheKey(profileId, rawName, qtype, flagsVariant = "") {
  const name = toASCII(rawName.replace(/\.$/, "") || ".");
  const type = DNS_NUMBER_TO_TYPE[qtype] ? normalizeType(DNS_NUMBER_TO_TYPE[qtype]) : String(qtype);
  return new Request(
    `https://doh-cache.internal/${profileId}/json/${encodeURIComponent(name)}/${encodeURIComponent(type)}${flagsVariant}`,
    { method: "GET" }
  );
}

// Cache-key suffix isolating non-standard queries in their own namespace.
//
// The cache key is deliberately shared across request formats and DO values,
// but header flags that change what the upstream returns MUST partition the
// cache: a CD=1 query bypasses upstream DNSSEC validation (RFC 4035 S3.2.2),
// an RD=0 query is answered without recursion, and a non-QUERY opcode yields
// NOTIMP. Without this, an attacker could poison the shared entry that
// standard queries for the same name/type are served from.
//
// Standard queries (opcode QUERY, RD=1, CD=0) return "" so the established
// key format - and cross-format cache sharing - is unchanged for them.
// The suffix cannot collide with the type segment: normalizeType upper-cases
// client-supplied types, while this suffix contains lower-case letters.
function queryFlagsVariant(opcode, rd, cd) {
  if (opcode === 0 && rd && !cd) return "";
  return `!o${opcode}r${rd ? 1 : 0}c${cd ? 1 : 0}`;
}

// Extracts the flags variant from a wire-format query header.
function wireFlagsVariant(buf) {
  if (!buf || buf.length < 4) return "";
  const opcode = (buf[2] >> 3) & 0x0f;
  const rd = !!(buf[2] & 0x01);
  const cd = !!(buf[3] & 0x10);
  return queryFlagsVariant(opcode, rd, cd);
}

// Builds the cache lookup key for a request.
// wireGetBytes: optional pre-decoded ?dns= payload (the handler already
// base64url-decodes wire GET requests; passing it here avoids a second decode).
// Returns a Request for synchronous paths (JSON GET and valid wire GET/POST)
// or a Promise<Request> for wire POST when name extraction fails (SHA-256 fallback).
export function buildCacheKey(profileId, url, bodyBytes, wireGetBytes = null) {
  // Wire POST: extract name+type from body (synchronous for well-formed queries)
  if (bodyBytes) {
    const meta = extractQueryNameType(bodyBytes);
    if (meta) return metaToCacheKey(profileId, meta.name, meta.qtype, wireFlagsVariant(bodyBytes));
    // Fallback for malformed queries: SHA-256 hash of the body bytes
    return buildCacheKeyAsync(profileId, bodyBytes);
  }

  // Wire GET: use pre-decoded bytes when supplied, otherwise decode base64url
  if (url.searchParams.has("dns")) {
    let buf = wireGetBytes;
    if (!buf) {
      try {
        const b64 = url.searchParams.get("dns") || "";
        const clean = b64.replace(/-/g, "+").replace(/_/g, "/");
        const padded = clean + "=".repeat((4 - clean.length % 4) % 4);
        const binStr = atob(padded);
        buf = new Uint8Array(binStr.length);
        for (let i = 0; i < binStr.length; i++) buf[i] = binStr.charCodeAt(i);
      } catch { buf = null; }
    }
    if (buf) {
      const meta = extractQueryNameType(buf);
      if (meta) return metaToCacheKey(profileId, meta.name, meta.qtype, wireFlagsVariant(buf));
    }
    // Fallback: use stripped base64url directly as the key segment
    return new Request(
      `https://doh-cache.internal/${profileId}/wire/${encodeURIComponent(stripBase64Padding(url.searchParams.get("dns") || ""))}`,
      { method: "GET" }
    );
  }

  // JSON GET: name and type are already in the URL parameters.
  // The JSON API has no opcode/RD equivalent (always QUERY with recursion),
  // but ?cd=1 is forwarded upstream and must partition the cache like the
  // wire-format CD bit does.
  const rawName = url.searchParams.get("name") || ".";
  const name = toASCII(rawName.replace(/\.$/, "") || ".");
  const type = normalizeType(url.searchParams.get("type"));
  const flagsVariant = queryFlagsVariant(0, true, url.searchParams.get("cd") === "1");
  return new Request(
    `https://doh-cache.internal/${profileId}/json/${encodeURIComponent(name)}/${encodeURIComponent(type)}${flagsVariant}`,
    { method: "GET" }
  );
}

async function buildCacheKeyAsync(profileId, bodyBytes) {
  const hashBuf = await crypto.subtle.digest("SHA-256", bodyBytes);
  const hb = new Uint8Array(hashBuf);
  let hex = "";
  for (let i = 0; i < hb.length; i++) hex += HEX_TABLE[hb[i]];
  return new Request(`https://doh-cache.internal/${profileId}/wire/${hex}`, { method: "GET" });
}

// Writes a response clone to the edge cache with the worker-side TTL header applied.
export async function putCache(cache, key, response, isBlocked, cfg) {
  try {
    const wTtl = Math.max(
      isBlocked
        ? (cfg ? cfg.WORKER_BLOCKED_CACHE_TTL_SECONDS : WORKER_BLOCKED_CACHE_TTL_SECONDS)
        : (cfg ? cfg.WORKER_CACHE_TTL_SECONDS         : WORKER_CACHE_TTL_SECONDS),
      cfg ? cfg.MIN_CACHE_TTL_FLOOR : MIN_CACHE_TTL_FLOOR
    );
    const headers = new Headers(response.headers);
    headers.set("Cache-Control", `public, max-age=${wTtl}`);
    headers.set("X-Worker-Cache-TTL", String(wTtl));
    headers.set("X-Cache-Inserted-At", String(Math.floor(Date.now() / 1000)));
    await cache.put(key, new Response(response.body, { status: response.status, headers }));
  } catch {}
}

// Returns true when the cached response should trigger a background upstream refresh.
// The check compares remaining TTL against CACHE_RENEW_PERCENT of the total worker TTL.
// Returns false when the feature is disabled (CACHE_RENEW_PERCENT = 0) or when the
// required timing headers are absent (e.g. entries cached before this feature was added).
export function shouldRenewCache(response, cfg) {
  const renewPercent = cfg ? cfg.CACHE_RENEW_PERCENT : CACHE_RENEW_PERCENT;
  if (!renewPercent || renewPercent <= 0) return false;
  const insertedAt = Number(response.headers.get("x-cache-inserted-at") || "0");
  const totalTtl   = Number(response.headers.get("x-worker-cache-ttl")   || "0");
  if (!insertedAt || !totalTtl) return false;
  const now       = Math.floor(Date.now() / 1000);
  const remaining = totalTtl - (now - insertedAt);
  if (remaining <= 0) return false;
  return remaining < totalTtl * renewPercent / 100;
}

// Returns the effective client-side TTL: min(configured, dns_record_ttl) floored at MIN_CACHE_TTL_FLOOR.
export function computeClientTtl(result, isBlocked, cfg) {
  const c = isBlocked
    ? (cfg ? cfg.CLIENT_BLOCKED_CACHE_TTL_SECONDS : CLIENT_BLOCKED_CACHE_TTL_SECONDS)
    : (cfg ? cfg.CLIENT_CACHE_TTL_SECONDS         : CLIENT_CACHE_TTL_SECONDS);
  const floor = cfg ? cfg.MIN_CACHE_TTL_FLOOR : MIN_CACHE_TTL_FLOOR;
  const dns = result.wire ? extractMinTtlWire(result.raw) : (result.json ? extractMinTtl(result.json) : null);
  return Math.max(dns != null ? Math.min(c, dns) : c, floor);
}
