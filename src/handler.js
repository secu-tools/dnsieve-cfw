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
import { HEX_TABLE, hasNsidRequest, injectNsidToResponse, hasDoBit, stripDnssecFromWire, stripDnssecFromJson, clearDoBitInResponse, DNS_TYPE_TO_NUMBER, normalizeType, extractQueryNameType, buildBlockedResponse, buildServfailResponse, setTtlWire, setTtlJson, base64urlToBytes, hasEcsOption } from "./dns.js";
import { buildUpstreamUrl, queryUpstream } from "./upstream.js";
import { buildCacheKey, putCache, computeClientTtl, shouldRenewCache, remainingClientTtl, stripCacheBookkeeping } from "./cache.js";
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

// Errors are never cached and always carry CORS, so they share one shape.
function errorResponse(status, message, extra) {
  return new Response(message, {
    status,
    headers: { "Content-Type": "text/plain", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*", ...extra },
  });
}

// ---------------------------------------------------------------------------
// Response builder
// ---------------------------------------------------------------------------

export function buildResponse(result, profileId, isBlocked, allResponded, cfg) {
  const ttl = computeClientTtl(result, isBlocked, cfg);
  // X-Client-Cache-TTL is the client's cache budget from the moment this
  // response was produced. The body keeps the upstream record TTLs: the same
  // message is also stored in the edge cache and replayed, and a record TTL is
  // a countdown from now. applyClientEdns stamps the body at egress instead.
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
 * Apply client-specific per-response EDNS patching: DNSSEC stripping for
 * non-DO clients (RFC 4035 Section 3.1.4.1, see stripDnssecFromWire), NSID
 * injection (substitute mode; nsidValue is null when not needed), and DNS
 * transaction ID restore. A single body-read covers all wire operations.
 *
 * @param {Response} response
 * @param {number} dnsId
 * @param {string|null} nsidValue
 * @param {boolean} clientWantsDo
 * @param {number} queryQtype
 * @returns {Promise<Response>}
 */
async function applyClientEdns(response, dnsId, nsidValue, clientWantsDo, queryQtype, cfg) {
  const ct = response.headers.get("content-type") || "";
  const ttl = remainingClientTtl(response.headers, cfg);

  if (ct.includes("dns-message")) {
    if (dnsId === 0 && nsidValue === null && clientWantsDo && ttl === null) {
      return new Response(response.body, { status: response.status, headers: clientHeaders(response.headers, null, cfg && cfg.DEBUG) });
    }
    let buf = new Uint8Array(await response.arrayBuffer());
    if (!clientWantsDo) {
      buf = stripDnssecFromWire(buf, queryQtype);
      // RFC 6891 S.6.1.4 / RFC 3225: mirror the DO bit from the client query.
      // Cached copies always carry DO=1; clear it before returning to non-DO clients.
      buf = clearDoBitInResponse(buf);
    }
    if (nsidValue !== null) buf = injectNsidToResponse(buf, nsidValue);
    if (ttl !== null) buf = setTtlWire(buf, ttl);
    if (dnsId !== 0 && buf.length >= 2) { buf[0] = (dnsId >> 8) & 0xff; buf[1] = dnsId & 0xff; }
    return new Response(buf, { status: response.status, headers: clientHeaders(response.headers, ttl, cfg && cfg.DEBUG) });
  }

  if (ct.includes("dns-json") && (!clientWantsDo || ttl !== null)) {
    // JSON path: strip DNSSEC records for non-DO clients.
    // We must always rebuild the Response here because response.json() consumes
    // the body stream regardless of whether any records are actually removed.
    let json = await response.json();
    if (!clientWantsDo) json = stripDnssecFromJson(json, queryQtype);
    if (ttl !== null) json = setTtlJson(json, ttl);
    return new Response(JSON.stringify(json), { status: response.status, headers: clientHeaders(response.headers, ttl, cfg && cfg.DEBUG) });
  }
  return new Response(response.body, { status: response.status, headers: clientHeaders(response.headers, ttl, cfg && cfg.DEBUG) });
}

// Headers for a response leaving the worker. putCache stores entries with the
// worker-side Cache-Control, so a cache hit must re-derive the client value
// from the same TTL stamped into the body, keeping header and records in step.
function clientHeaders(headers, ttl, debug) {
  const out = new Headers(headers);

  stripCacheBookkeeping(out);

  // Diagnostic headers are ~44% of a response on the wire, against a DNS answer
  // of well under 100 bytes. Clients never read them, and this proxy is used on
  // metered mobile and IoT links, so they are emitted only under DEBUG. They are
  // still written to the cached copy, which is where remainingClientTtl reads
  // the TTL budget back from.
  if (!debug) {
    for (const name of DIAGNOSTIC_HEADERS) out.delete(name);
  }

  if (ttl !== null) {
    out.set("Cache-Control", `public, max-age=${ttl}`);
    if (debug) out.set("X-Client-Cache-TTL", String(ttl));
  }
  return out;
}

// Response headers that carry diagnostics rather than protocol meaning.
const DIAGNOSTIC_HEADERS = [
  "X-Blocked",
  "X-Blocking-Mode",
  "X-Upstream-Index",
  "X-All-Responded",
  "X-Client-Cache-TTL",
  "X-Profile-Id",
  "X-Worker-Version",
];

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
// Hostname of an upstream URL, for client-facing diagnostics. Falls back to
// the empty string rather than echoing an unparseable value.
function upstreamHost(rawUrl) {
  if (!rawUrl) return "";
  try {
    return new URL(rawUrl).hostname;
  } catch {
    return "";
  }
}

function buildBlockedResponseForClient(blockedResult, profileId, upstreamUrls, bodyBytes, isJsonGet, cfg, clientCd = false) {
  const mode = cfg.BLOCKING_MODE || "null";
  // EDE text names the blocking upstream by host only (RFC 8914 info code 15).
  // The full URL would disclose its path to every client that trips a block,
  // and an upstream template such as https://dns.nextdns.io/{PROFILE_ID} puts
  // the operator's profile id -- effectively a bearer secret -- in that path.
  const edeText = `Blocked (${upstreamHost(upstreamUrls[blockedResult.index])})`;

  if (isJsonGet) {
    // JSON blocking response
    const ttl = computeClientTtl(blockedResult, true, cfg);
    // Stamped once at egress, so the cached copy holds no time-relative value.
    const json = buildBlockedJson(blockedResult, mode, edeText, clientCd);
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
    const ttl = computeClientTtl(blockedResult, true, cfg);
    // As above: TTL=0 here, stamped at egress where the entry's age is known.
    const wireResp = buildBlockedResponse(bodyBytes, mode, { edeText });
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

// Cache keys with a background refresh already running in this isolate.
//
// Without this guard every request served from cache during the renewal window
// (the last CACHE_RENEW_PERCENT of the worker TTL) starts its own full upstream
// fan-out. A domain queried even a few times per second therefore produces
// hundreds of redundant refreshes -- and N times that many upstream
// subrequests -- where one would do.
// Scope note: this is per-isolate, and a colo runs many isolates, so a very hot
// key can still produce one refresh per isolate rather than one globally. That
// is a large constant-factor win over one per request and needs no coordination;
// cross-isolate coalescing would require a cache-backed sentinel.
//
// Exported so tests can inspect and reset it between cases, matching
// COOKIE_STORE in upstream.js.
export const INFLIGHT_REFRESH = new Set();

// Starts a background refresh for the given cache key unless one is already
// running. Returns true when a refresh was started.
function startBackgroundRefresh(ctx, key, run) {
  if (INFLIGHT_REFRESH.has(key)) return false;
  INFLIGHT_REFRESH.add(key);
  ctx.waitUntil((async () => {
    // run() builds its upstream list eagerly and so can throw synchronously.
    try { await run(); } catch { /* best-effort */ }
    finally { INFLIGHT_REFRESH.delete(key); }
  })());
  return true;
}

// Re-queries all upstreams and writes the freshest result back to the edge
// cache.  Called via ctx.waitUntil() after a stale-but-valid cached response
// has already been returned to the client, so errors here are silent.
async function backgroundRefreshCache(cache, cacheKeyReq, request, url, bodyBytes, wireQueryBytes, isJsonGet, profileId, upstreamUrls, cfg, clientCd) {
  try {
    const promises = upstreamUrls.map((u, i) => queryUpstream(i, u, request.method, url, bodyBytes, isJsonGet, cfg, wireQueryBytes));
    const settlements = await Promise.allSettled(promises);
    const results = settlements.map((s, i) => s.status === "fulfilled" ? s.value : { index: i, ok: false });

    // Same rule as the main path: only write to the shared cache once every
    // upstream has answered. Caching a partial fan-out would let a transient
    // upstream failure replace a blocked verdict with the surviving upstream's
    // clean answer, un-blocking the domain for every client on this profile.
    let okCount = 0;
    for (let i = 0; i < results.length; i++) if (results[i] && results[i].ok) okCount++;
    if (okCount !== results.length) return;

    // Blocked result takes priority: cache it first if any upstream confirms.
    for (let i = 0; i < results.length; i++) {
      const r = results[i];
      if (r && r.ok && r.blocked) {
        const resp = buildBlockedResponseForClient(r, profileId, upstreamUrls, bodyBytes || wireQueryBytes, isJsonGet, cfg, clientCd);
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

// True when the client supplied its own EDNS Client Subnet, in whichever request
// format it used.
function clientSuppliedEcs(url, bodyBytes, wireGetBytes) {
  if (url.searchParams.has("edns_client_subnet")) return true;
  const wire = bodyBytes || wireGetBytes;
  return !!wire && hasEcsOption(wire);
}

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
    return errorResponse(405, "Method not allowed. DoH supports GET and POST only.", { "Allow": "GET, POST, OPTIONS" });
  }

  const profileId = extractProfileId(url, cfg.GENERAL_PROFILE_ID);

  const ct = (request.headers.get("content-type") || "").toLowerCase();
  if (request.method === "POST" && !ct.includes("application/dns-message")) {
    return errorResponse(415, "Unsupported Media Type. POST must use Content-Type: application/dns-message.");
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
  // Decoded wire bytes from a GET ?dns= request. Kept separate from bodyBytes
  // so buildCacheKey (which keys wire GET off these decoded bytes) is not
  // confused with the POST path.
  let wireGetQueryBytes = null;
  // Whether the client requested DNSSEC records; when false, DNSSEC RRs are
  // stripped from responses (RFC 4035 S3.1.4.1). Upstreams always get DO=1.
  let clientWantsDo = false;
  // Checking Disabled (RFC 4035 S3.1.6): preserved in the wire bytes for wire
  // requests; sourced from ?cd=1 for JSON DoH.
  let clientCd = false;
  // Numeric DNS type of the first question: the DNSSEC strip exception keeps
  // this type in Answer even for non-DO clients (e.g. ?type=RRSIG).
  let queryQtype = 1; // default A

  if (isWirePost) {
    bodyBytes = new Uint8Array(await request.arrayBuffer());
    if (bodyBytes.length > cfg.MAX_DNS_MESSAGE_SIZE) {
      return errorResponse(413, "Content Too Large.");
    }
    // A valid DNS message requires at least a 12-byte header; a shorter body is always
    // malformed and will cause upstream servers to return HTTP 4xx/5xx errors.
    if (bodyBytes.length < 12) {
      return errorResponse(400, "Bad Request. DNS message body too short.");
    }
    clientDnsId = (bodyBytes[0] << 8) | bodyBytes[1];
    // Extract DO bit and query type from client's original wire message.
    clientWantsDo = hasDoBit(bodyBytes);
    const postMeta = extractQueryNameType(bodyBytes);
    if (postMeta) queryQtype = postMeta.qtype;
    // RFC 8484 SS.4.1: zero the DNS ID for upstream and cache key
    if (bodyBytes[0] !== 0 || bodyBytes[1] !== 0) {
      bodyBytes[0] = 0; bodyBytes[1] = 0;
    }
    if (cfg.DEBUG) {
      let hex = ""; const n = Math.min(bodyBytes.length, 40);
      for (let i = 0; i < n; i++) hex += HEX_TABLE[bodyBytes[i]];
      console.log(`[DoH] POST body: ${bodyBytes.length}B  hex[0:${n}]=${hex}  clientDnsId=${clientDnsId}  clientWantsDo=${clientWantsDo}  queryQtype=${queryQtype}`);
    }
  } else if (isWireGet) {
    let decoded;
    try {
      // Same size gate as POST, applied before the output buffer is allocated.
      decoded = base64urlToBytes(url.searchParams.get("dns") || "", cfg.MAX_DNS_MESSAGE_SIZE);
    } catch (e) {
      if (e instanceof RangeError) return errorResponse(413, "Content Too Large.");
      // RFC 8484 S.4.1: the ?dns= value MUST be a valid non-padding base64url string.
      return errorResponse(400, "Bad Request. Invalid base64url encoding in ?dns= parameter.");
    }
    // RFC 8484 S.4.1: a valid DNS message requires at least a 12-byte header.
    if (decoded.length < 12) {
      return errorResponse(400, "Bad Request. DNS message in ?dns= parameter is too short.");
    }
    clientDnsId = (decoded[0] << 8) | decoded[1];
    // RFC 8484 SS.4.1: zero the DNS ID (same as the POST path) -- cached
    // messages must never carry one client's transaction ID; applyClientEdns
    // restores the original ID on the direct reply.
    if (decoded[0] !== 0 || decoded[1] !== 0) {
      decoded[0] = 0; decoded[1] = 0;
    }
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
  // In ECS forward mode the client's own subnet is sent upstream and changes the
  // answer, but the edge cache is shared by every client on the profile and its
  // key does not include the subnet. Sharing such an answer would both leak one
  // client's network to others and let the first requester steer everyone to its
  // CDN edge, so these requests bypass the shared cache in both directions.
  // strip (the default) and substitute are unaffected: neither varies by client.
  const ecsForwarded = cfg.PRIVACY_ECS_MODE === "forward" && clientSuppliedEcs(url, bodyBytes, wireGetQueryBytes);

  const cache = caches.default;
  const cacheKey = await buildCacheKey(profileId, url, bodyBytes, wireGetQueryBytes);
  const cached = ecsForwarded ? null : await cache.match(cacheKey);
  if (cached) {
    if (cfg.DEBUG) console.log(`[DoH] Cache HIT  profileId=${profileId}`);
    // Stale-while-revalidate: refresh in the background when remaining TTL is low.
    if (cfg.CACHE_RENEW_PERCENT > 0 && shouldRenewCache(cached, cfg)) {
      // Built inside the callback so it is only materialised when a refresh
      // actually starts; most hits in the renewal window are deduplicated.
      const started = startBackgroundRefresh(ctx, cacheKey.url, () =>
        backgroundRefreshCache(cache, cacheKey, request, url, bodyBytes, wireGetQueryBytes, isJsonGet, profileId,
          cfg.UPSTREAM_SERVERS.map(t => buildUpstreamUrl(t, profileId)), cfg, clientCd));
      if (cfg.DEBUG) console.log(`[DoH] Cache renew ${started ? "triggered" : "skipped (already in flight)"}  profileId=${profileId}`);
    }
    return applyClientEdns(cached, clientDnsId, clientWantsNsid ? cfg.PRIVACY_NSID_VALUE : null, clientWantsDo, queryQtype, cfg);
  }
  if (cfg.DEBUG) console.log(`[DoH] Cache MISS - querying ${cfg.UPSTREAM_COUNT} upstreams`);

  // Fan out to all upstreams concurrently
  const upstreamUrls = cfg.UPSTREAM_SERVERS.map(t => buildUpstreamUrl(t, profileId));
  const promises = upstreamUrls.map((u, i) => queryUpstream(i, u, request.method, url, bodyBytes, isJsonGet, cfg, wireGetQueryBytes));

  const results = new Array(upstreamUrls.length);
  let settledCount = 0;
  let blocked = null;

  const collection = new Promise(resolve => {
    for (let i = 0; i < promises.length; i++) {
      promises[i].then(r => {
        results[r.index] = r;
        settledCount++;
        if (r.ok && r.blocked && !blocked) { blocked = r; resolve(); }
        if (settledCount === promises.length) resolve();
      }).catch(() => {
        settledCount++;
        if (settledCount === promises.length) resolve();
      });
    }
  });

  const minWait = new Promise(r => setTimeout(r, cfg.MIN_WAIT_MS));

  // Phase 1: wait for first block confirmation OR minimum wait window
  await Promise.race([collection, minWait]);

  // Early block return: answer as soon as one upstream reports a block, then
  // finish the fan-out in the background and cache the verdict if every
  // upstream answered -- the same rule phase 2 applies. A resolver block is
  // among the fastest answers an upstream produces, so almost every block takes
  // this path; without the deferred write the edge cache would never hold one
  // and each repeat query would re-run the whole fan-out.
  if (blocked) {
    if (cfg.DEBUG) console.log(`[DoH] Early BLOCKED from upstream[${blocked.index}] (${upstreamUrls[blocked.index]})`);
    const resp = buildBlockedResponseForClient(blocked, profileId, upstreamUrls, bodyBytes || wireGetQueryBytes, isJsonGet, cfg, clientCd);
    const toCache = resp.clone();
    ctx.waitUntil(Promise.allSettled(promises).then(async (settled) => {
      if (!ecsForwarded && settled.every(s => s.status === "fulfilled" && s.value && s.value.ok)) {
        await putCache(cache, cacheKey, toCache, true, cfg);
      }
    }));
    return applyClientEdns(resp, clientDnsId, clientWantsNsid ? cfg.PRIVACY_NSID_VALUE : null, clientWantsDo, queryQtype, cfg);
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
  for (let i = 0; i < results.length; i++) if (results[i] && results[i].ok) okCount++;
  const allResponded = okCount === results.length;

  // Check for blocked responses after all are settled
  for (let i = 0; i < results.length; i++) {
    const r = results[i];
    if (r && r.ok && r.blocked) {
      if (cfg.DEBUG) console.log(`[DoH] BLOCKED by upstream[${r.index}] (${upstreamUrls[r.index]})  allResponded=${allResponded}`);
      const resp = buildBlockedResponseForClient(r, profileId, upstreamUrls, bodyBytes || wireGetQueryBytes, isJsonGet, cfg, clientCd);
      if (allResponded && !ecsForwarded) ctx.waitUntil(putCache(cache, cacheKey, resp.clone(), true, cfg));
      return applyClientEdns(resp, clientDnsId, clientWantsNsid ? cfg.PRIVACY_NSID_VALUE : null, clientWantsDo, queryQtype, cfg);
    }
  }

  // Pick the best clean result with DNSSEC preference
  const best = pickBestResult(results);
  if (best) {
    if (cfg.DEBUG) console.log(`[DoH] OK from upstream[${best.index}] (${upstreamUrls[best.index]})  hasDnssec=${!!best.hasDnssec}  allResponded=${allResponded}`);
    const resp = buildResponse(best, profileId, false, allResponded, cfg);
    if (allResponded && !ecsForwarded) ctx.waitUntil(putCache(cache, cacheKey, resp.clone(), false, cfg));
    return applyClientEdns(resp, clientDnsId, clientWantsNsid ? cfg.PRIVACY_NSID_VALUE : null, clientWantsDo, queryQtype, cfg);
  }

  // All upstreams failed: build a synthetic SERVFAIL from the original query,
  // returned with HTTP 200 (RFC 8484 s4.2.1) and Cache-Control: no-store so
  // the error is never cached (RFC 2308).
  if (cfg.DEBUG) console.log(`[DoH] All ${cfg.UPSTREAM_COUNT} upstreams failed (SERVFAIL) profileId=${profileId}`);

  const servfailExtra = { "Cache-Control": "no-store", "X-Profile-Id": profileId, "X-Worker-Version": VERSION };

  if (isJsonGet) {
    // JSON DoH: return SERVFAIL as application/dns-json (Status=2)
    const qname = url.searchParams.get("name") || ".";
    const qtypeNum = queryQtype;
    const servfailJson = { Status: 2, TC: false, RD: true, RA: true, AD: false, CD: clientCd, Question: [{ name: qname, type: qtypeNum }] };
    return new Response(JSON.stringify(servfailJson), { status: 200, headers: dohJsonHeaders(servfailExtra) });
  }

  // Wire DoH (POST or GET): build SERVFAIL from original query bytes.
  const queryBytesForServfail = bodyBytes || wireGetQueryBytes || null;
  const servfailWire = buildServfailResponse(queryBytesForServfail);
  const servfailResp = new Response(servfailWire, { status: 200, headers: dohWireHeaders(servfailExtra) });
  return applyClientEdns(servfailResp, clientDnsId, null, clientWantsDo, queryQtype, cfg);
}
