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
import { bytesToHex, hasNsidRequest, injectNsidToResponse, hasDoBit, stripDnssecFromWire, stripDnssecFromJson, clearDoBitInResponse, DNS_TYPE_TO_NUMBER, extractQueryNameType, buildBlockedResponse, buildServfailResponse, setTtlWire, setTtlJson, base64urlToBytes, hasEcsOption } from "./dns.js";
import { buildUpstreamUrl, queryUpstream } from "./upstream.js";
import { buildCacheKey, jsonQuery, putCache, computeClientTtl, shouldRenewCache, remainingClientTtl, stripCacheBookkeeping } from "./cache.js";
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
 * injection (substitute mode; nsidValue is null when not needed), TTL stamping
 * and DNS transaction ID restore. A single body-read covers all wire operations;
 * each step is a no-op when it has nothing to change.
 *
 * @param {Response} response
 * @param {number} dnsId
 * @param {string|null} nsidValue
 * @param {boolean} clientWantsDo
 * @param {number} queryQtype
 * @param {object} cfg
 * @returns {Promise<Response>}
 */
async function applyClientEdns(response, dnsId, nsidValue, clientWantsDo, queryQtype, cfg) {
  const ct = response.headers.get("content-type") || "";
  const ttl = remainingClientTtl(response.headers, cfg);
  const init = { status: response.status, headers: clientHeaders(response.headers, ttl, cfg.DEBUG) };

  if (ct.includes("dns-message")) {
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
    return new Response(buf, init);
  }

  if (ct.includes("dns-json")) {
    let json = await response.json();
    if (!clientWantsDo) json = stripDnssecFromJson(json, queryQtype);
    if (ttl !== null) json = setTtlJson(json, ttl);
    return new Response(JSON.stringify(json), init);
  }
  return new Response(response.body, init);
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
  return bestDnssec || bestPlain;
}

// ---------------------------------------------------------------------------
// Blocked response builder (with configurable blocking mode)
// ---------------------------------------------------------------------------

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

/**
 * Build a client-facing response for a blocked domain using the configured
 * blocking mode. For wire-format clients, generates a local DNS response from
 * the original query (the handler has already rejected queries shorter than a
 * DNS header). For JSON clients, builds a JSON response matching the mode.
 *
 * @param {object} blockedResult - The upstream result that detected the block
 * @param {object} rq - Request context (see handleRequest)
 * @returns {Response}
 */
function buildBlockedResponseForClient(blockedResult, rq) {
  const mode = rq.cfg.BLOCKING_MODE || "null";
  const ttl = computeClientTtl(blockedResult, true, rq.cfg);
  const extra = {
    "Cache-Control": `public, max-age=${ttl}`,
    "X-Profile-Id": rq.profileId,
    "X-Client-Cache-TTL": String(ttl),
    "X-Blocked": "true",
    "X-Upstream-Index": String(blockedResult.index),
    "X-Blocking-Mode": mode,
    "X-Worker-Version": VERSION,
  };
  // Both forms leave record TTLs at 0; they are stamped at egress, where the
  // entry's age is known, so the cached copy holds no time-relative value.

  if (rq.isJsonGet) {
    const json = buildBlockedJson(blockedResult, mode, rq.clientCd);
    return new Response(JSON.stringify(json), { status: 200, headers: dohJsonHeaders(extra) });
  }

  // EDE text names the blocking upstream by host only (RFC 8914 info code 15).
  // The full URL would disclose its path to every client that trips a block,
  // and an upstream template such as https://dns.nextdns.io/{PROFILE_ID} puts
  // the operator's profile id -- effectively a bearer secret -- in that path.
  const edeText = `Blocked (${upstreamHost(rq.upstreamUrls[blockedResult.index])})`;
  const wireResp = buildBlockedResponse(rq.bodyBytes || rq.wireGetBytes, mode, { edeText });
  return new Response(wireResp, { status: 200, headers: dohWireHeaders(extra) });
}

/**
 * Build a JSON blocked response matching the configured blocking mode.
 */
function buildBlockedJson(blockedResult, mode, clientCd = false) {
  const question = (blockedResult.json && blockedResult.json.Question) || [];

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
// Upstream fan-out and outcome
// ---------------------------------------------------------------------------

// Queries every upstream concurrently: one promise per upstream, in priority
// order. queryUpstream reports failures as { ok: false } rather than rejecting.
function fanOut(rq) {
  return rq.upstreamUrls.map((u, i) =>
    queryUpstream(i, u, rq.method, rq.url, rq.bodyBytes, rq.isJsonGet, rq.cfg, rq.wireGetBytes));
}

// One result per upstream, in priority order, from settled fan-out promises.
function settledResults(settlements) {
  return settlements.map((s, i) => s.status === "fulfilled" ? s.value : { index: i, ok: false });
}

// The shared edge cache only takes an outcome once every upstream has answered.
// Caching a partial fan-out would let a transient upstream failure replace a
// blocked verdict with the surviving upstream's clean answer, un-blocking the
// domain for every client on this profile.
function allResponded(results) {
  return results.every(r => r && r.ok);
}

// The response a settled fan-out resolves to. A block from any upstream wins
// (lowest index first); otherwise the best clean answer (see pickBestResult).
// Returns null when no upstream produced a usable answer.
function resolveOutcome(results, rq) {
  const blocked = results.find(r => r && r.ok && r.blocked);
  if (blocked) return { result: blocked, isBlocked: true, resp: buildBlockedResponseForClient(blocked, rq) };
  const best = pickBestResult(results);
  if (!best) return null;
  return { result: best, isBlocked: false, resp: buildResponse(best, rq.profileId, false, allResponded(results), rq.cfg) };
}

// Writes a settled fan-out's outcome to the edge cache, under allResponded's rule.
async function cacheOutcome(cache, key, results, rq) {
  if (!allResponded(results)) return;
  const outcome = resolveOutcome(results, rq);
  if (outcome) await putCache(cache, key, outcome.resp, outcome.isBlocked, rq.cfg);
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
    try { await run(); } catch { /* best-effort */ }
    finally { INFLIGHT_REFRESH.delete(key); }
  })());
  return true;
}

// Re-queries all upstreams and writes the outcome back to the edge cache under
// the same rules as a cache miss. Called via ctx.waitUntil() after a
// stale-but-valid cached response has already been returned to the client.
async function backgroundRefreshCache(cache, cacheKeyReq, rq) {
  const results = settledResults(await Promise.allSettled(fanOut(rq)));
  await cacheOutcome(cache, cacheKeyReq, results, rq);
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

  // Every POST reaching here is application/dns-message (checked above).
  const isWirePost = request.method === "POST";
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
    return errorResponse(400,
      JSON.stringify({ error: "Invalid DoH request. Use ?name=&type= (JSON), ?dns= (wire GET), or POST with application/dns-message." }),
      { "Content-Type": "application/json" });
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
  // requests; sourced from ?cd= for JSON DoH.
  let clientCd = false;
  // Numeric DNS type of the first question: the DNSSEC strip exception keeps
  // this type in Answer even for non-DO clients (e.g. ?type=RRSIG).
  let queryQtype = 1; // default A

  if (isJsonGet) {
    // JSON DoH has no wire header: ?do= and ?cd= stand in for the DO and CD
    // bits, read exactly as the cache key and the upstream query read them.
    const q = jsonQuery(url);
    clientWantsDo = q.do;
    clientCd = q.cd;
    queryQtype = DNS_TYPE_TO_NUMBER[q.type] ?? (parseInt(q.type, 10) || 1);
  } else {
    let wire;
    if (isWirePost) {
      wire = new Uint8Array(await request.arrayBuffer());
      if (wire.length > cfg.MAX_DNS_MESSAGE_SIZE) return errorResponse(413, "Content Too Large.");
    } else {
      try {
        // Same size gate as POST, applied before the output buffer is allocated.
        wire = base64urlToBytes(url.searchParams.get("dns") || "", cfg.MAX_DNS_MESSAGE_SIZE);
      } catch (e) {
        if (e instanceof RangeError) return errorResponse(413, "Content Too Large.");
        // RFC 8484 S.4.1: the ?dns= value MUST be a valid non-padding base64url string.
        return errorResponse(400, "Bad Request. Invalid base64url encoding in ?dns= parameter.");
      }
    }
    // A valid DNS message requires at least a 12-byte header; a shorter one is
    // always malformed and would only draw HTTP 4xx/5xx errors from upstreams.
    if (wire.length < 12) {
      return errorResponse(400, isWirePost
        ? "Bad Request. DNS message body too short."
        : "Bad Request. DNS message in ?dns= parameter is too short.");
    }
    clientDnsId = (wire[0] << 8) | wire[1];
    // RFC 8484 SS.4.1: zero the DNS ID for upstream and cache key -- cached
    // messages must never carry one client's transaction ID; applyClientEdns
    // restores the original ID on the direct reply.
    wire[0] = 0; wire[1] = 0;
    clientWantsDo = hasDoBit(wire);
    queryQtype = extractQueryNameType(wire)?.qtype ?? 1;
    if (isWirePost) bodyBytes = wire; else wireGetQueryBytes = wire;
    if (cfg.DEBUG) {
      const n = Math.min(wire.length, 40);
      console.log(`[DoH] wire query: ${wire.length}B  hex[0:${n}]=${bytesToHex(wire.subarray(0, n))}  clientDnsId=${clientDnsId}  clientWantsDo=${clientWantsDo}  queryQtype=${queryQtype}`);
    }
  }

  // NSID substitute mode answers a client's NSID request itself (RFC 5001).
  // Only wire requests can carry one: JSON mode has no EDNS OPT record.
  const nsidValue = cfg.PRIVACY_NSID_MODE === "substitute" && hasNsidRequest(bodyBytes || wireGetQueryBytes)
    ? cfg.PRIVACY_NSID_VALUE
    : null;
  const reply = (resp, nsid = nsidValue) => applyClientEdns(resp, clientDnsId, nsid, clientWantsDo, queryQtype, cfg);

  // Everything the fan-out, outcome and refresh paths need about this request.
  const rq = {
    method: request.method,
    url,
    bodyBytes,
    wireGetBytes: wireGetQueryBytes,
    isJsonGet,
    clientCd,
    profileId,
    upstreamUrls: cfg.UPSTREAM_SERVERS.map(t => buildUpstreamUrl(t, profileId)),
    cfg,
  };

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
      const started = startBackgroundRefresh(ctx, cacheKey.url, () => backgroundRefreshCache(cache, cacheKey, rq));
      if (cfg.DEBUG) console.log(`[DoH] Cache renew ${started ? "triggered" : "skipped (already in flight)"}  profileId=${profileId}`);
    }
    return reply(cached);
  }
  if (cfg.DEBUG) console.log(`[DoH] Cache MISS - querying ${cfg.UPSTREAM_COUNT} upstreams`);

  const promises = fanOut(rq);

  // Phase 1: wait for the first upstream to confirm a block, or for every
  // upstream to settle, or for the minimum wait window -- whichever is first.
  const firstBlock = new Promise(resolve => {
    let pending = promises.length;
    if (pending === 0) resolve(null);
    for (const p of promises) {
      p.then(r => { if (r.ok && r.blocked) resolve(r); }, () => {})
        .finally(() => { if (--pending === 0) resolve(null); });
    }
  });
  const minWait = new Promise(r => setTimeout(() => r(null), cfg.MIN_WAIT_MS));
  const blocked = await Promise.race([firstBlock, minWait]);

  // Early block return: answer as soon as one upstream reports a block, then
  // finish the fan-out in the background and cache its outcome if every
  // upstream answered -- the same rule phase 2 applies. A resolver block is
  // among the fastest answers an upstream produces, so almost every block takes
  // this path; without the deferred write the edge cache would never hold one
  // and each repeat query would re-run the whole fan-out.
  if (blocked) {
    if (cfg.DEBUG) console.log(`[DoH] Early BLOCKED from upstream[${blocked.index}] (${rq.upstreamUrls[blocked.index]})`);
    if (!ecsForwarded) {
      ctx.waitUntil(Promise.allSettled(promises).then(settled => cacheOutcome(cache, cacheKey, settledResults(settled), rq)));
    }
    return reply(buildBlockedResponseForClient(blocked, rq));
  }

  // Phase 2: wait for all upstreams to finish
  const results = settledResults(await Promise.allSettled(promises));
  const complete = allResponded(results);
  const outcome = resolveOutcome(results, rq);
  if (outcome) {
    if (cfg.DEBUG) {
      const r = outcome.result;
      console.log(`[DoH] ${outcome.isBlocked ? "BLOCKED by" : "OK from"} upstream[${r.index}] (${rq.upstreamUrls[r.index]})  hasDnssec=${!!r.hasDnssec}  allResponded=${complete}`);
    }
    if (complete && !ecsForwarded) ctx.waitUntil(putCache(cache, cacheKey, outcome.resp.clone(), outcome.isBlocked, cfg));
    return reply(outcome.resp);
  }

  // All upstreams failed: build a synthetic SERVFAIL from the original query,
  // returned with HTTP 200 (RFC 8484 s4.2.1) and Cache-Control: no-store so
  // the error is never cached (RFC 2308).
  if (cfg.DEBUG) console.log(`[DoH] All ${cfg.UPSTREAM_COUNT} upstreams failed (SERVFAIL) profileId=${profileId}`);

  // Both forms leave through reply(), like every other answer, so the
  // diagnostic headers are dropped unless DEBUG is on.
  const servfailExtra = { "Cache-Control": "no-store", "X-Profile-Id": profileId, "X-Worker-Version": VERSION };

  if (isJsonGet) {
    // JSON DoH: return SERVFAIL as application/dns-json (Status=2)
    const qname = url.searchParams.get("name") || ".";
    const servfailJson = { Status: 2, TC: false, RD: true, RA: true, AD: false, CD: clientCd, Question: [{ name: qname, type: queryQtype }] };
    return reply(new Response(JSON.stringify(servfailJson), { status: 200, headers: dohJsonHeaders(servfailExtra) }), null);
  }

  // Wire DoH (POST or GET): build SERVFAIL from original query bytes.
  const servfailWire = buildServfailResponse(bodyBytes || wireGetQueryBytes);
  return reply(new Response(servfailWire, { status: 200, headers: dohWireHeaders(servfailExtra) }), null);
}
