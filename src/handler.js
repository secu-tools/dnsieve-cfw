// SPDX-License-Identifier: MIT
// dnsieve-cfw - Core request handler
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// Implements:
//   - RFC 8484  (DNS Queries over HTTPS)
//   - RFC 8484 SS.4.1 (DNS ID MUST be 0; client ID preserved and restored on reply)
//   - RFC 8484 SS.4.2.1 (HTTP status codes; SERVFAIL returned as HTTP 200 per spec)
//   - RFC 8484 SS.4.2.1 (Content-Type, cache headers)
//   - RFC 5891 / IDNA 2008 (IDN normalisation via toASCII)
//   - WHATWG URL Standard SS.3.3 (IDN toASCII)
//   - Google/Cloudflare JSON DoH API convention

import {
  GENERAL_PROFILE_ID,
  getConfig,
} from "./config.js";
import { HEX_TABLE, hasNsidRequest, injectNsidToResponse, hasDoBit, stripDnssecFromWire, stripDnssecFromJson, clearDoBitInResponse, DNS_TYPE_TO_NUMBER, normalizeType, extractQueryNameType, buildBlockedResponse, injectEdeToResponse, buildServfailResponse } from "./dns.js";
import { buildUpstreamUrl, queryUpstream } from "./upstream.js";
import { buildCacheKey, putCache, computeClientTtl, shouldRenewCache } from "./cache.js";
import { extractMinTtlWire, extractMinTtl } from "./dns.js";
import { VERSION } from "./version.js";

// ---------------------------------------------------------------------------
// Profile ID extraction
// ---------------------------------------------------------------------------

const PROFILE_RE = /\/p-([0-9a-fA-F]{6})(?:[/?#]|$)/;

export function extractProfileId(url, defaultProfileId = GENERAL_PROFILE_ID) {
  const m = url.pathname.match(PROFILE_RE);
  return m ? m[1].toLowerCase() : defaultProfileId;
}

// ---------------------------------------------------------------------------
// Response header helpers
// ---------------------------------------------------------------------------

function dohJsonHeaders(extra) {
  return { "Content-Type": "application/dns-json", "Access-Control-Allow-Origin": "*", "Vary": "Accept", ...extra };
}

function dohWireHeaders(extra) {
  return { "Content-Type": "application/dns-message", "Access-Control-Allow-Origin": "*", "Vary": "Accept", ...extra };
}

// ---------------------------------------------------------------------------
// Response builder
// ---------------------------------------------------------------------------

export function buildResponse(result, profileId, isBlocked, allResponded, cfg) {
  const ttl = computeClientTtl(result, isBlocked, cfg);
  const extra = {
    "Cache-Control": `public, max-age=${ttl}`,
    "X-Profile-Id": profileId,
    "X-Client-Cache-TTL": String(ttl),
    "X-Blocked": String(isBlocked),
    "X-Upstream-Index": String(result.index),
    "X-All-Responded": String(allResponded),
    "X-Worker-Version": VERSION,
  };

  if (result.wire) {
    return new Response(result.raw, { status: 200, headers: dohWireHeaders(extra) });
  }
  return new Response(JSON.stringify(result.json), { status: 200, headers: dohJsonHeaders(extra) });
}

/**
 * Restore the client's original DNS transaction ID into a wire response.
 * The cached copy retains ID=0 (RFC 8484 SS.4.1); only the copy sent to the
 * client is patched with the original ID.
 *
 * @param {Response} response
 * @param {number} dnsId - Original 16-bit DNS transaction ID
 * @returns {Promise<Response>}
 */
export async function restoreWireId(response, dnsId) {
  const ct = response.headers.get("content-type") || "";
  if (!ct.includes("dns-message")) return response;
  const buf = new Uint8Array(await response.arrayBuffer());
  if (buf.length >= 2) {
    buf[0] = (dnsId >> 8) & 0xff;
    buf[1] = dnsId & 0xff;
  }
  return new Response(buf, { status: response.status, headers: response.headers });
}

/**
 * Apply client-specific per-response EDNS patching: optional DNSSEC stripping
 * for non-DO clients, optional NSID injection (substitute mode), and DNS
 * transaction ID restore.  A single body-read covers all wire-format operations.
 *
 * Stripping rules (RFC 4035 Section 3.1.4.1):
 *   When clientWantsDo is false, RRSIG/NSEC/DNSKEY/NSEC3 records are removed
 *   from the Answer and Authority sections before the response is sent.
 *   Exception: a DNSSEC type is kept in the Answer when it equals queryQtype
 *   (the client explicitly queried for that type).
 *
 * nsidValue is null when no injection is needed.
 *
 * @param {Response} response
 * @param {number} dnsId
 * @param {string|null} nsidValue
 * @param {boolean} clientWantsDo
 * @param {number} queryQtype
 * @returns {Promise<Response>}
 */
async function applyClientEdns(response, dnsId, nsidValue, clientWantsDo, queryQtype) {
  const ct = response.headers.get("content-type") || "";
  if (ct.includes("dns-message")) {
    if (dnsId === 0 && nsidValue === null && clientWantsDo) return response;
    let buf = new Uint8Array(await response.arrayBuffer());
    if (!clientWantsDo) {
      buf = stripDnssecFromWire(buf, queryQtype);
      // RFC 6891 S.6.1.4 / RFC 3225: mirror the DO bit from the client query.
      // Cached copies always carry DO=1; clear it before returning to non-DO clients.
      buf = clearDoBitInResponse(buf);
    }
    if (nsidValue !== null) buf = injectNsidToResponse(buf, nsidValue);
    if (dnsId !== 0 && buf.length >= 2) { buf[0] = (dnsId >> 8) & 0xff; buf[1] = dnsId & 0xff; }
    return new Response(buf, { status: response.status, headers: response.headers });
  }
  if (ct.includes("dns-json") && !clientWantsDo) {
    // JSON path: strip DNSSEC records for non-DO clients.
    // We must always rebuild the Response here because response.json() consumes
    // the body stream regardless of whether any records are actually removed.
    const json = await response.json();
    const stripped = stripDnssecFromJson(json, queryQtype);
    return new Response(JSON.stringify(stripped), { status: response.status, headers: response.headers });
  }
  return response;
}

// ---------------------------------------------------------------------------
// DNSSEC preference - upstream result selection (hardcoded, always enabled)
// ---------------------------------------------------------------------------

/**
 * Pick the best non-blocked upstream result.
 * A DNSSEC-signed response (AD flag or RRSIG records) from any upstream is
 * always preferred over an unsigned response from a higher-priority upstream.
 * Falls back to the highest-priority (lowest index) clean result.
 *
 * @param {Array} results - Array of upstream results
 * @returns {object|null} Best result, or null if none are ok
 */
function pickBestResult(results) {
  let bestDnssec = null;
  let bestPlain = null;
  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    if (!r || !r.ok || r.blocked) continue;
    if (r.hasDnssec && !bestDnssec) bestDnssec = r;
    if (!bestPlain) bestPlain = r;
  }
  if (bestDnssec) return bestDnssec;
  return bestPlain;
}

// ---------------------------------------------------------------------------
// Blocked response builder (with configurable blocking mode)
// ---------------------------------------------------------------------------

/**
 * Build a client-facing response for a blocked domain using the configured
 * blocking mode. For wire-format clients, generates a local DNS response.
 * For JSON clients, builds a JSON response matching the blocking mode.
 *
 * @param {object} blockedResult - The upstream result that detected the block
 * @param {string} profileId
 * @param {string[]} upstreamUrls - Resolved upstream URLs
 * @param {Uint8Array|null} bodyBytes - Original wire query (for wire response building)
 * @param {boolean} isJsonGet - Whether the client wants JSON
 * @param {object} cfg - Runtime config
 * @returns {Response}
 */
function buildBlockedResponseForClient(blockedResult, profileId, upstreamUrls, bodyBytes, isJsonGet, cfg, clientCd = false) {
  const mode = cfg.BLOCKING_MODE || "null";
  // EDE text is always derived from the blocking upstream URL (RFC 8914 info code 15).
  const edeText = `Blocked (${upstreamUrls[blockedResult.index] || ""})`;

  if (isJsonGet) {
    // JSON blocking response
    const json = buildBlockedJson(blockedResult, mode, edeText, clientCd);
    const ttl = computeClientTtl(blockedResult, true, cfg);
    return new Response(JSON.stringify(json), {
      status: 200,
      headers: dohJsonHeaders({
        "Cache-Control": `public, max-age=${ttl}`,
        "X-Profile-Id": profileId,
        "X-Client-Cache-TTL": String(ttl),
        "X-Blocked": "true",
        "X-Upstream-Index": String(blockedResult.index),
        "X-Blocking-Mode": mode,
        "X-Worker-Version": VERSION,
      }),
    });
  }

  // Wire blocking response
  if (bodyBytes && bodyBytes.length >= 12) {
    const wireResp = buildBlockedResponse(bodyBytes, mode, { edeText });
    const ttl = computeClientTtl(blockedResult, true, cfg);
    return new Response(wireResp, {
      status: 200,
      headers: dohWireHeaders({
        "Cache-Control": `public, max-age=${ttl}`,
        "X-Profile-Id": profileId,
        "X-Client-Cache-TTL": String(ttl),
        "X-Blocked": "true",
        "X-Upstream-Index": String(blockedResult.index),
        "X-Blocking-Mode": mode,
        "X-Worker-Version": VERSION,
      }),
    });
  }

  // Fallback: return the upstream response as-is (e.g. GET wire where we don't have bodyBytes)
  return buildResponse(blockedResult, profileId, true, false, cfg);
}

/**
 * Build a JSON blocked response matching the configured blocking mode.
 */
function buildBlockedJson(blockedResult, mode, edeText, clientCd = false) {
  // Start from upstream JSON if available, otherwise build minimal
  const base = blockedResult.json ? { ...blockedResult.json } : {};
  const question = base.Question || [];

  switch (mode) {
    case "nxdomain":
      return { Status: 3, TC: false, RD: true, RA: true, AD: false, CD: clientCd, Question: question };
    case "nodata":
      return { Status: 0, TC: false, RD: true, RA: true, AD: false, CD: clientCd, Question: question };
    case "refused":
      return { Status: 5, TC: false, RD: true, RA: true, AD: false, CD: clientCd, Question: question };
    case "null":
    default: {
      // Determine query type for appropriate null answer
      const answers = [];
      if (question.length > 0) {
        const qtype = question[0].type;
        if (qtype === 28) {
          answers.push({ name: question[0].name, type: 28, TTL: 0, data: "::" });
        } else if (qtype === 1 || !qtype) {
          answers.push({ name: question[0].name, type: 1, TTL: 0, data: "0.0.0.0" });
        }
      }
      return { Status: 0, TC: false, RD: true, RA: true, AD: false, CD: clientCd, Question: question, Answer: answers.length ? answers : undefined };
    }
  }
}

// ---------------------------------------------------------------------------
// Background cache refresh (stale-while-revalidate)
// ---------------------------------------------------------------------------

// Re-queries all upstreams and writes the freshest result back to the edge
// cache.  Called via ctx.waitUntil() after a stale-but-valid cached response
// has already been returned to the client, so errors here are silent.
async function backgroundRefreshCache(cache, cacheKeyReq, request, url, bodyBytes, wireQueryBytes, isJsonGet, profileId, upstreamUrls, cfg) {
  try {
    const promises = upstreamUrls.map((u, i) => queryUpstream(i, u, request.method, url, bodyBytes, isJsonGet, cfg));
    const settlements = await Promise.allSettled(promises);
    const results = settlements.map((s, i) => s.status === "fulfilled" ? s.value : { index: i, ok: false });

    // Blocked result takes priority: cache it first if any upstream confirms.
    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      if (r && r.ok && r.blocked) {
        const resp = buildBlockedResponseForClient(r, profileId, upstreamUrls, bodyBytes || wireQueryBytes, isJsonGet, cfg);
        await putCache(cache, cacheKeyReq, resp, true, cfg);
        return;
      }
    }

    // Otherwise cache the best clean result.
    const best = pickBestResult(results);
    if (best) {
      const resp = buildResponse(best, profileId, false, true, cfg);
      await putCache(cache, cacheKeyReq, resp, false, cfg);
    }
  } catch {}
}

// ---------------------------------------------------------------------------
// Main handler
// ---------------------------------------------------------------------------

export async function handleRequest(request, env, ctx) {
  const cfg = getConfig(env);
  const url = new URL(request.url);

  // CORS preflight
  if (request.method === "OPTIONS") {
    return new Response(null, {
      headers: {
        "Access-Control-Allow-Origin": "*",
        "Access-Control-Allow-Methods": "GET, POST, OPTIONS",
        "Access-Control-Allow-Headers": "Content-Type, Accept",
        "Access-Control-Max-Age": "86400",
      },
    });
  }

  if (request.method !== "GET" && request.method !== "POST") {
    return new Response("Method not allowed. DoH supports GET and POST only.", {
      status: 405,
      headers: { "Content-Type": "text/plain", "Allow": "GET, POST, OPTIONS", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" },
    });
  }

  const profileId = extractProfileId(url, cfg.GENERAL_PROFILE_ID);

  const ct = (request.headers.get("content-type") || "").toLowerCase();
  if (request.method === "POST" && !ct.includes("application/dns-message")) {
    return new Response(
      "Unsupported Media Type. POST must use Content-Type: application/dns-message.",
      { status: 415, headers: { "Content-Type": "text/plain", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" } }
    );
  }

  const isWirePost = request.method === "POST" && ct.includes("application/dns-message");
  const isWireGet  = request.method === "GET" && url.searchParams.has("dns");
  // Wire GET takes priority over JSON GET when both ?dns and ?name are present (RFC 8484 SS.4.2).
  const isJsonGet  = request.method === "GET" && url.searchParams.has("name") && !isWireGet;

  if (cfg.DEBUG) {
    const qinfo = isJsonGet
      ? ` name=${url.searchParams.get("name")} type=${url.searchParams.get("type") || "A"}`
      : isWireGet ? " dns=<base64url>" : "";
    console.log(`[DoH] ${request.method} profileId=${profileId} isWirePost=${isWirePost} isWireGet=${isWireGet} isJsonGet=${isJsonGet}${qinfo}`);
  }

  if (!isWirePost && !isWireGet && !isJsonGet) {
    return new Response(
      JSON.stringify({ error: "Invalid DoH request. Use ?name=&type= (JSON), ?dns= (wire GET), or POST with application/dns-message." }),
      { status: 400, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" } }
    );
  }

  let bodyBytes = null;
  let clientDnsId = 0;
  // wireGetQueryBytes: decoded wire bytes from a GET ?dns= request. Kept
  // separate from bodyBytes to avoid affecting buildCacheKey (which derives
  // the wire GET cache key directly from the URL parameter, not the body).
  // Used only in the all-fail SERVFAIL response builder (RFC 8484 s4.2.1).
  let wireGetQueryBytes = null;
  // clientWantsDo: whether the originating client requested DNSSEC records.
  // When false, DNSSEC RRs are stripped from responses before returning
  // (RFC 4035 Section 3.1.4.1). Upstreams always receive DO=1 regardless.
  let clientWantsDo = false;
  // clientCd: whether the client requested Checking Disabled (RFC 4035 S3.1.6).
  // For wire requests the CD bit is preserved directly in the wire bytes;
  // for JSON DoH it is sourced from the ?cd=1 query parameter.
  let clientCd = false;
  // queryQtype: numeric DNS type from the first question. Used as the DNSSEC
  // strip exception -- a type is kept in Answer even for non-DO clients when it
  // equals the explicitly queried type (e.g. ?type=RRSIG keeps RRSIG answers).
  let queryQtype = 1; // default A

  if (isWirePost) {
    bodyBytes = new Uint8Array(await request.arrayBuffer());
    if (bodyBytes.length > cfg.MAX_DNS_MESSAGE_SIZE) {
      return new Response("Content Too Large.", { status: 413, headers: { "Content-Type": "text/plain", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" } });
    }
    // A valid DNS message requires at least a 12-byte header; a shorter body is always
    // malformed and will cause upstream servers to return HTTP 4xx/5xx errors.
    if (bodyBytes.length < 12) {
      return new Response("Bad Request. DNS message body too short.", { status: 400, headers: { "Content-Type": "text/plain", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" } });
    }
    if (bodyBytes.length >= 2) {
      clientDnsId = (bodyBytes[0] << 8) | bodyBytes[1];
    }
    // Extract DO bit and query type from client's original wire message.
    clientWantsDo = hasDoBit(bodyBytes);
    const postMeta = extractQueryNameType(bodyBytes);
    if (postMeta) queryQtype = postMeta.qtype;
    // RFC 8484 SS.4.1: zero the DNS ID for upstream and cache key
    if (bodyBytes.length >= 2 && (bodyBytes[0] !== 0 || bodyBytes[1] !== 0)) {
      bodyBytes[0] = 0; bodyBytes[1] = 0;
    }
    if (cfg.DEBUG) {
      let hex = ""; const n = Math.min(bodyBytes.length, 40);
      for (let i = 0; i < n; i++) hex += HEX_TABLE[bodyBytes[i]];
      console.log(`[DoH] POST body: ${bodyBytes.length}B  hex[0:${n}]=${hex}  clientDnsId=${clientDnsId}  clientWantsDo=${clientWantsDo}  queryQtype=${queryQtype}`);
    }
  } else if (isWireGet) {
    const b64 = url.searchParams.get("dns") || "";
    let decoded;
    try {
      const padded = b64.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - b64.length % 4) % 4);
      const bin = atob(padded);
      // Size gate: decoded wire GET payload must not exceed MAX_DNS_MESSAGE_SIZE (same as POST)
      if (bin.length > cfg.MAX_DNS_MESSAGE_SIZE) {
        return new Response("Content Too Large.", { status: 413, headers: { "Content-Type": "text/plain", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" } });
      }
      decoded = new Uint8Array(bin.length);
      for (let i = 0; i < bin.length; i++) decoded[i] = bin.charCodeAt(i);
    } catch {
      // RFC 8484 S.4.1: the ?dns= value MUST be a valid non-padding base64url string.
      return new Response("Bad Request. Invalid base64url encoding in ?dns= parameter.", { status: 400, headers: { "Content-Type": "text/plain", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" } });
    }
    // RFC 8484 S.4.1: a valid DNS message requires at least a 12-byte header.
    if (decoded.length < 12) {
      return new Response("Bad Request. DNS message in ?dns= parameter is too short.", { status: 400, headers: { "Content-Type": "text/plain", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" } });
    }
    if (decoded.length >= 2) clientDnsId = (decoded[0] << 8) | decoded[1];
    // Save decoded bytes so the all-fail path can build a SERVFAIL response
    // mirroring the question section (RFC 8484 s4.2.1). Not assigned to
    // bodyBytes to avoid interfering with buildCacheKey, which uses the URL
    // ?dns= param directly for wire GET cache keys.
    wireGetQueryBytes = decoded;
    clientWantsDo = hasDoBit(decoded);
    const getMeta = extractQueryNameType(decoded);
    if (getMeta) queryQtype = getMeta.qtype;
  } else if (isJsonGet) {
    // For JSON DoH, the DO bit equivalent is the ?do=1 query parameter.
    clientWantsDo = url.searchParams.get("do") === "1";
    // CD bit equivalent: ?cd=1 (mirrored to synthetic responses per RFC 4035 S3.1.6).
    clientCd = url.searchParams.get("cd") === "1";
    const typeStr = url.searchParams.get("type") || "A";
    const normType = normalizeType(typeStr);
    queryQtype = DNS_TYPE_TO_NUMBER[normType] !== undefined
      ? DNS_TYPE_TO_NUMBER[normType]
      : (parseInt(typeStr, 10) || 1);
  }

  // Detect whether client is requesting NSID (RFC 5001) for substitute mode.
  // Only meaningful for wire-format requests (JSON mode has no EDNS OPT record).
  let clientWantsNsid = false;
  if (cfg.PRIVACY_NSID_MODE === "substitute") {
    if (isWirePost && bodyBytes) {
      clientWantsNsid = hasNsidRequest(bodyBytes);
    } else if (isWireGet && wireGetQueryBytes) {
      // wireGetQueryBytes is already decoded and validated above.
      clientWantsNsid = hasNsidRequest(wireGetQueryBytes);
    }
  }

  // Cache lookup
  const cache = caches.default;
  const cacheKey = await buildCacheKey(profileId, url, bodyBytes);
  const cached = await cache.match(cacheKey);
  if (cached) {
    if (cfg.DEBUG) console.log(`[DoH] Cache HIT  profileId=${profileId}`);
    // Stale-while-revalidate: refresh in the background when remaining TTL is low.
    if (cfg.CACHE_RENEW_PERCENT > 0 && shouldRenewCache(cached, cfg)) {
      if (cfg.DEBUG) console.log(`[DoH] Cache renew triggered  profileId=${profileId}`);
      const renewUrls = cfg.UPSTREAM_SERVERS.map(t => buildUpstreamUrl(t, profileId));
      ctx.waitUntil(backgroundRefreshCache(cache, cacheKey, request, url, bodyBytes, wireGetQueryBytes, isJsonGet, profileId, renewUrls, cfg));
    }
    return applyClientEdns(cached, clientDnsId, clientWantsNsid ? cfg.PRIVACY_NSID_VALUE : null, clientWantsDo, queryQtype);
  }
  if (cfg.DEBUG) console.log(`[DoH] Cache MISS - querying ${cfg.UPSTREAM_COUNT} upstreams`);

  // Fan out to all upstreams concurrently
  const upstreamUrls = cfg.UPSTREAM_SERVERS.map(t => buildUpstreamUrl(t, profileId));
  const promises = upstreamUrls.map((u, i) => queryUpstream(i, u, request.method, url, bodyBytes, isJsonGet, cfg));

  const results = new Array(cfg.UPSTREAM_COUNT);
  let settledCount = 0;
  let blocked = null;

  const collection = new Promise(resolve => {
    for (let i = 0; i < promises.length; i++) {
      promises[i].then(r => {
        results[r.index] = r;
        settledCount++;
        if (r.ok && r.blocked && !blocked) { blocked = r; resolve(); }
        if (settledCount === cfg.UPSTREAM_COUNT) resolve();
      }).catch(() => {
        settledCount++;
        if (settledCount === cfg.UPSTREAM_COUNT) resolve();
      });
    }
  });

  const minWait = new Promise(r => setTimeout(r, cfg.MIN_WAIT_MS));

  // Phase 1: wait for first block confirmation OR minimum wait window
  await Promise.race([collection, minWait]);

  // Early block return - don't cache (other upstreams may not have responded yet)
  if (blocked) {
    if (cfg.DEBUG) console.log(`[DoH] Early BLOCKED from upstream[${blocked.index}] (${upstreamUrls[blocked.index]})`);
    const resp = buildBlockedResponseForClient(blocked, profileId, upstreamUrls, bodyBytes || wireGetQueryBytes, isJsonGet, cfg, clientCd);
    ctx.waitUntil(Promise.allSettled(promises));
    return applyClientEdns(resp, clientDnsId, clientWantsNsid ? cfg.PRIVACY_NSID_VALUE : null, clientWantsDo, queryQtype);
  }

  // Phase 2: wait for all upstreams to finish
  const settlements = await Promise.allSettled(promises);
  for (let i = 0; i < settlements.length; i++) {
    if (!results[i]) {
      const s = settlements[i];
      results[i] = s.status === "fulfilled" ? s.value : { index: i, ok: false };
    }
  }

  let okCount = 0;
  for (let i = 0; i < cfg.UPSTREAM_COUNT; i++) if (results[i] && results[i].ok) okCount++;
  const allResponded = okCount === cfg.UPSTREAM_COUNT;

  // Check for blocked responses after all are settled
  for (let i = 0; i < cfg.UPSTREAM_COUNT; i++) {
    const r = results[i];
    if (r && r.ok && r.blocked) {
      if (cfg.DEBUG) console.log(`[DoH] BLOCKED by upstream[${r.index}] (${upstreamUrls[r.index]})  allResponded=${allResponded}`);
      const resp = buildBlockedResponseForClient(r, profileId, upstreamUrls, bodyBytes || wireGetQueryBytes, isJsonGet, cfg, clientCd);
      if (allResponded) ctx.waitUntil(putCache(cache, cacheKey, resp.clone(), true, cfg));
      return applyClientEdns(resp, clientDnsId, clientWantsNsid ? cfg.PRIVACY_NSID_VALUE : null, clientWantsDo, queryQtype);
    }
  }

  // Pick the best clean result with DNSSEC preference
  const best = pickBestResult(results);
  if (best) {
    if (cfg.DEBUG) console.log(`[DoH] OK from upstream[${best.index}] (${upstreamUrls[best.index]})  hasDnssec=${!!best.hasDnssec}  allResponded=${allResponded}`);
    const resp = buildResponse(best, profileId, false, allResponded, cfg);
    if (allResponded) ctx.waitUntil(putCache(cache, cacheKey, resp.clone(), false, cfg));
    return applyClientEdns(resp, clientDnsId, clientWantsNsid ? cfg.PRIVACY_NSID_VALUE : null, clientWantsDo, queryQtype);
  }

  // All upstreams failed.
  // RFC 8484 s4.2.1: a valid DNS response -- even SERVFAIL -- MUST be returned
  // with HTTP 200. Build a synthetic SERVFAIL reply from the original query so
  // the client can correlate the response with its question. Cache-Control is
  // set to no-store so neither the edge cache nor the client caches the error
  // (RFC 2308: SERVFAIL SHOULD NOT be cached; RFC 8484 s5.1: freshness lifetime
  // must not exceed the smallest TTL in the Answer section -- SERVFAIL has none).
  if (cfg.DEBUG) console.log(`[DoH] All ${cfg.UPSTREAM_COUNT} upstreams failed (SERVFAIL) profileId=${profileId}`);

  const servfailHeaders = { "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*", "Vary": "Accept", "X-Profile-Id": profileId, "X-Worker-Version": VERSION };

  if (isJsonGet) {
    // JSON DoH: return SERVFAIL as application/dns-json (Status=2)
    const qname = url.searchParams.get("name") || ".";
    const qtypeNum = queryQtype;
    const servfailJson = { Status: 2, TC: false, RD: true, RA: true, AD: false, CD: clientCd, Question: [{ name: qname, type: qtypeNum }] };
    return new Response(JSON.stringify(servfailJson), { status: 200, headers: { ...servfailHeaders, "Content-Type": "application/dns-json" } });
  }

  // Wire DoH (POST or GET): build SERVFAIL from original query bytes.
  const queryBytesForServfail = bodyBytes || wireGetQueryBytes || null;
  const servfailWire = buildServfailResponse(queryBytesForServfail);
  const servfailResp = new Response(servfailWire, { status: 200, headers: { ...servfailHeaders, "Content-Type": "application/dns-message" } });
  return applyClientEdns(servfailResp, clientDnsId, null, clientWantsDo, queryQtype);
}
