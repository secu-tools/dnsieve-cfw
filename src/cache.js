// SPDX-License-Identifier: MIT
// dnsieve-cfw - Cache key construction and response caching
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// Cache key design - unified name+type format for all request types:
//   https://doh-cache.internal/{profileId}/json/{name}/{type}
//
// Wire GET (?dns=) and wire POST share one key, so DO=0/DO=1 clients and both
// wire request forms for the same query hit one entry (the proxy always
// requests DO=1 upstream, so cached responses always contain DNSSEC records).
//
// JSON GET is keyed separately. The stored body is whatever format the first
// requester asked for, and a cache hit is replayed without conversion, so a
// shared entry hands a wire stub a JSON body (or the reverse) -- unparseable,
// for the whole entry lifetime. Cross-format sharing only ever worked when
// every client used the same format, in which case this partition costs
// nothing. For wire requests the question
// name and type are extracted from the decoded message and normalised
// (toASCII / normalizeType); malformed queries fall back to a SHA-256 hash
// key. DNS transaction ID is always 0 in cached messages (RFC 8484 SS.4.1).

import { HEX_TABLE, toASCII, normalizeType, stripBase64Padding, extractMinTtlWire, extractMinTtl, extractQueryNameType, extractHeaderFlags, base64urlToBytes, DNS_NUMBER_TO_TYPE } from "./dns.js";
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
// Canonical name segment for a cache key.
//
// toASCII resolves IDNs via URL parsing, which truncates at "/", "?", "#" and
// discards everything before "@" -- so distinct DNS names could map onto one
// key. A label may legally contain any octet, so anything that does not round
// trip is kept verbatim (already escaped per RFC 4343 by readDnsName) rather
// than being silently rewritten.
function canonicalName(rawName) {
  const stripped = rawName.replace(/\.$/, "") || ".";
  if (/[/?#@%\\:]/.test(stripped)) return stripped.toLowerCase();
  const folded = toASCII(stripped);
  return isLosslessFold(stripped, folded) ? folded : stripped.toLowerCase();
}

// True when `folded` is a faithful IDNA encoding of `name` rather than a lossy
// rewrite of it.
//
// toASCII runs the name through URL parsing, and UTS-46 mapping is many-to-one:
// it deletes ignorable code points (U+00AD, U+200B, U+FEFF ...) and maps
// compatibility forms (U+3002, U+FF0E) onto ".". Those are distinct DNS names
// on the wire, and the upstream is queried with the unmapped bytes, so folding
// them together lets one name's answer be cached under another's key.
//
// A genuine IDN label always comes back punycode-encoded, so require that: same
// label count, and each label either unchanged ASCII or an "xn--" encoding.
// Anything else is keyed verbatim.
function isLosslessFold(name, folded) {
  const a = name.split(".");
  const b = folded.split(".");
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (ASCII_LABEL_RE.test(a[i])) {
      if (b[i] !== a[i].toLowerCase()) return false;
    } else if (!b[i].startsWith("xn--")) {
      return false;
    }
  }
  return true;
}

const ASCII_LABEL_RE = /^[\x00-\x7f]*$/;

function metaToCacheKey(profileId, rawName, qtype, flagsVariant = "") {
  const name = canonicalName(rawName);
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
// Suffix separating JSON-format entries from wire-format ones. Lower-case, so
// it cannot collide with the upper-cased type segment, and empty for wire so
// existing wire keys are unchanged.
const JSON_FORMAT_VARIANT = "!fjson";

// True for every spelling of CD that an upstream JSON API accepts. Matching only
// "1" would let ?cd=true reach the upstream with validation disabled while the
// answer is keyed as a standard query -- the exact partition this exists to
// enforce.
function isCdSet(value) {
  if (value === null || value === undefined) return false;
  const v = String(value).trim().toLowerCase();
  return v === "1" || v === "true" || v === "t" || v === "yes";
}

function queryFlagsVariant(opcode, rd, cd) {
  if (opcode === 0 && rd && !cd) return "";
  return `!o${opcode}r${rd ? 1 : 0}c${cd ? 1 : 0}`;
}

// Extracts the flags variant from a wire-format query header.
function wireFlagsVariant(buf) {
  const flags = extractHeaderFlags(buf);
  return flags ? queryFlagsVariant(flags.opcode, flags.rd, flags.cd) : "";
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
        buf = base64urlToBytes(url.searchParams.get("dns") || "");
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
  const name = canonicalName(rawName);
  const type = normalizeType(url.searchParams.get("type"));
  const flagsVariant = queryFlagsVariant(0, true, isCdSet(url.searchParams.get("cd")));
  return new Request(
    `https://doh-cache.internal/${profileId}/json/${encodeURIComponent(name)}/${encodeURIComponent(type)}${flagsVariant}${JSON_FORMAT_VARIANT}`,
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

// Remaining client TTL, in seconds: the budget recorded at build time
// (X-Client-Cache-TTL) minus the entry's age in the edge cache
// (X-Cache-Inserted-At, absent on a fresh response). Without the subtraction a
// nearly expired entry would hand out a full-length TTL, letting total
// staleness reach the worker TTL plus the client TTL.
//
// Returns null when no budget is recorded, meaning "leave the body alone".
export function remainingClientTtl(headers, cfg) {
  // Values come from headers or bare Number(env.X) config, so each is coerced:
  // a NaN reaching setTtlWire is written to the wire as TTL=0, which silently
  // reinstates the "never cache" behaviour this function exists to prevent.
  const budget = Number(headers.get("x-client-cache-ttl"));
  if (!Number.isFinite(budget) || budget <= 0) return null;

  const floor = Number(cfg?.MIN_CACHE_TTL_FLOOR);
  const safeFloor = Number.isFinite(floor) && floor > 0 ? floor : 0;

  const insertedAt = Number(headers.get("x-cache-inserted-at"));
  if (!Number.isFinite(insertedAt) || insertedAt <= 0) return budget;

  const age = Math.floor(Date.now() / 1000) - insertedAt;
  if (age <= 0) return budget;
  return Math.max(safeFloor, budget - age);
}

// Removes the bookkeeping headers putCache adds. They describe the edge cache,
// which is shared by every client on a profile, so an insertion timestamp would
// reveal when somebody else first looked up that domain.
export function stripCacheBookkeeping(headers) {
  headers.delete("X-Cache-Inserted-At");
  headers.delete("X-Worker-Cache-TTL");
}

// Returns the effective client-side TTL, floored at MIN_CACHE_TTL_FLOOR.
//
// Normal answers are capped by the upstream record TTL, so a client is never
// told to hold an answer longer than its origin considers valid.
//
// Blocked answers ignore that cap: a block is a policy verdict, not a property
// of the record, and blocking upstreams return one with a short TTL. The worker
// serves the verdict from its edge cache for WORKER_BLOCKED_CACHE_TTL_SECONDS
// anyway, so re-asking sooner costs a round trip for identical bytes. See the
// Cache TTLs section of README.md for the staleness trade-off.
export function computeClientTtl(result, isBlocked, cfg) {
  const floor = cfg ? cfg.MIN_CACHE_TTL_FLOOR : MIN_CACHE_TTL_FLOOR;

  if (isBlocked) {
    const b = cfg ? cfg.CLIENT_BLOCKED_CACHE_TTL_SECONDS : CLIENT_BLOCKED_CACHE_TTL_SECONDS;
    return Math.max(b, floor);
  }

  const c = cfg ? cfg.CLIENT_CACHE_TTL_SECONDS : CLIENT_CACHE_TTL_SECONDS;
  const dns = result.wire ? extractMinTtlWire(result.raw) : (result.json ? extractMinTtl(result.json) : null);
  return Math.max(dns != null ? Math.min(c, dns) : c, floor);
}
