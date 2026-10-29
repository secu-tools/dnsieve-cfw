// SPDX-License-Identifier: MIT
// dnsieve-cfw - Upstream DoH query dispatch
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)

import {
  isBlockedOrNxdomain,
  isServerFailure,
  inspectWireResponse,
  wireToJson,
  stripBase64Padding,
  processEdnsOutgoing,
  processEdnsIncoming,
  hasDnssecData,
  hasDnssecDataJson,
  base64urlToBytes,
  bytesToBase64url,
} from "./dns.js";
import { jsonQuery } from "./cache.js";
import { UPSTREAM_TIMEOUT_MS, DEBUG, PRIVACY_COOKIES_MODE } from "./config.js";

// ---------------------------------------------------------------------------
// Per-upstream cookie state (RFC 7873 reoriginate mode)
// ---------------------------------------------------------------------------
// Module-level Map: lives for the lifetime of the worker instance (resets on
// cold start). Keys are upstream URL strings; values are { client, server }.
// Exported so tests can inspect and reset it between cases.
export const COOKIE_STORE = new Map();

// Upper bound on COOKIE_STORE. Keys are resolved upstream URLs, so a template
// containing {PROFILE_ID} yields one entry per profile a client names -- and
// any client can name millions. Past the cap the oldest entry is evicted; its
// upstream then sees a fresh client cookie, exactly as after a cold start.
const COOKIE_STORE_MAX = 1024;

function getCookieBytes(upstreamUrl) {
  if (!COOKIE_STORE.has(upstreamUrl)) {
    if (COOKIE_STORE.size >= COOKIE_STORE_MAX) COOKIE_STORE.delete(COOKIE_STORE.keys().next().value);
    const client = new Uint8Array(8);
    crypto.getRandomValues(client);
    COOKIE_STORE.set(upstreamUrl, { client, server: null });
  }
  const { client, server } = COOKIE_STORE.get(upstreamUrl);
  if (server) {
    const combined = new Uint8Array(client.length + server.length);
    combined.set(client);
    combined.set(server, client.length);
    return combined;
  }
  return client;
}

function updateServerCookie(upstreamUrl, serverBytes) {
  const state = COOKIE_STORE.get(upstreamUrl);
  if (state) state.server = new Uint8Array(serverBytes);
}

const DNS_HEADER_SIZE = 12;

// A JSON answer spells out every owner name in full and renders RDATA as text,
// so it runs several times the size of the same answer on the wire (where a
// repeated name is a 2-byte pointer). Capping JSON bodies at the wire limit
// would turn a large but legitimate answer into SERVFAIL.
const JSON_SIZE_FACTOR = 16;

// Reads a response body, refusing anything larger than maxBytes.
//
// MAX_DNS_MESSAGE_SIZE guards client input; upstream bodies were unbounded, so
// a broken or hostile upstream could have the isolate buffer an arbitrarily
// large body -- and every copy made while parsing it -- against the 128 MB
// isolate limit shared with other in-flight requests. The body is streamed and
// the read abandoned as soon as it passes the cap, so a body without a
// Content-Length (chunked) is bounded too, not only one that declares its size.
async function readCapped(resp, maxBytes) {
  const declared = Number(resp.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new RangeError("upstream response too large");
  }
  const chunks = [];
  let total = 0;
  if (resp.body) {
    const reader = resp.body.getReader();
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        reader.cancel().catch(() => {});
        throw new RangeError("upstream response too large");
      }
      chunks.push(value);
    }
  }
  if (chunks.length === 1) return chunks[0];
  const out = new Uint8Array(total);
  let w = 0;
  for (const c of chunks) { out.set(c, w); w += c.byteLength; }
  return out;
}

export function buildUpstreamUrl(template, profileId) {
  return template.replace("{PROFILE_ID}", profileId);
}

/**
 * Send a single DNS query to one upstream server and return a normalised result.
 *
 * @param {number} index - Upstream index (priority order)
 * @param {string} upstreamUrl - Resolved upstream URL (profile ID already substituted)
 * @param {string} method - Client HTTP method ("GET" or "POST")
 * @param {URL} url - Parsed client request URL
 * @param {Uint8Array|null} bodyBytes - POST body (ID already zeroed) or null
 * @param {boolean} clientWantsJson - True if client Accept: application/dns-json
 * @param {object} [cfg] - Optional runtime config from getConfig(env); falls back to module defaults
 * @param {Uint8Array|null} [wireGetBytes] - Pre-decoded ?dns= payload for wire GET
 *   requests (avoids re-decoding the base64url parameter per upstream)
 * @returns {Promise<{index: number, ok: boolean, blocked?: boolean, wire?: boolean, raw?: Uint8Array, json?: object}>}
 */
export async function queryUpstream(index, upstreamUrl, method, url, bodyBytes, clientWantsJson, cfg, wireGetBytes = null) {
  const timeout = cfg ? cfg.UPSTREAM_TIMEOUT_MS : UPSTREAM_TIMEOUT_MS;
  const debug   = cfg ? cfg.DEBUG               : DEBUG;
  const cookiesMode = cfg ? cfg.PRIVACY_COOKIES_MODE : PRIVACY_COOKIES_MODE;
  const declaredMax = Number(cfg && cfg.MAX_DNS_MESSAGE_SIZE);
  const maxMessage = Number.isFinite(declaredMax) && declaredMax > 0 ? declaredMax : 65535;
  if (debug) console.log(`[DoH] Upstream[${index}] -> ${upstreamUrl}  method=${method} clientWantsJson=${clientWantsJson}`);
  const ac = new AbortController();
  const timer = setTimeout(() => ac.abort(), timeout);

  // Pre-compute cookie bytes for reoriginate mode (shared across POST/GET-wire paths)
  const cookieBytes = cookiesMode === "reoriginate" ? getCookieBytes(upstreamUrl) : null;

  try {
    const isWirePost = method === "POST";
    const isGetWire  = method === "GET" && url.searchParams.has("dns");

    let resp;
    if (isWirePost) {
      resp = await fetch(upstreamUrl, {
        method: "POST",
        headers: { Accept: "application/dns-message", "Content-Type": "application/dns-message" },
        body: cfg ? processEdnsOutgoing(bodyBytes, cfg, cookieBytes) : bodyBytes,
        signal: ac.signal,
      });
    } else if (isGetWire) {
      const target = new URL(upstreamUrl);
      // Decode the base64url DNS query, apply EDNS processing (strip/modify OPT),
      // then re-encode before forwarding. Falls back to the original value on parse error.
      let dnsParam = stripBase64Padding(url.searchParams.get("dns") || "");
      if (cfg) {
        try {
          let decoded = wireGetBytes;
          if (decoded) {
            // RFC 8484 SS.4.1: forward with a zeroed DNS ID. The handler already
            // zeroes it; copy before writing in case a caller passed live bytes.
            if (decoded.length >= 2 && (decoded[0] !== 0 || decoded[1] !== 0)) {
              decoded = decoded.slice();
              decoded[0] = 0; decoded[1] = 0;
            }
          } else {
            decoded = base64urlToBytes(dnsParam);
            // RFC 8484 SS.4.1: zero the DNS ID before upstream forwarding (same as POST path)
            if (decoded.length >= 2) { decoded[0] = 0; decoded[1] = 0; }
          }
          dnsParam = bytesToBase64url(processEdnsOutgoing(decoded, cfg, cookieBytes));
        } catch {}
      }
      target.searchParams.set("dns", dnsParam);
      resp = await fetch(target.href, {
        method: "GET",
        headers: { Accept: "application/dns-message" },
        signal: ac.signal,
      });
    } else {
      // JSON GET mode
      const target = new URL(upstreamUrl);
      // Only an allowlist reaches the upstream: forwarding arbitrary client
      // params (e.g. edns_client_subnet) would leak client identity to it.
      // name, type and cd are sent as jsonQuery interprets them -- the reading
      // buildCacheKey keys on -- never as the client spelled them. Forwarding
      // raw values let the two diverge: "?name=a&name=b" queried b and cached
      // the answer under a, and a Unicode name the upstream folded differently
      // could bind one domain's answer to another's key.
      const q = jsonQuery(url);
      target.searchParams.set("name", q.name);
      target.searchParams.set("type", q.type);
      if (q.cd) target.searchParams.set("cd", "1");
      const ct = url.searchParams.get("ct");
      if (ct !== null) target.searchParams.set("ct", ct);
      // ECS forward mode: also pass edns_client_subnet if present in client request
      if (cfg && cfg.PRIVACY_ECS_MODE === "forward") {
        const ecs = url.searchParams.get("edns_client_subnet");
        if (ecs !== null) target.searchParams.set("edns_client_subnet", ecs);
      }
      // ECS substitute mode: inject the configured subnet as edns_client_subnet
      if (cfg && cfg.PRIVACY_ECS_MODE === "substitute" && cfg.PRIVACY_ECS_SUBNET) {
        target.searchParams.set("edns_client_subnet", cfg.PRIVACY_ECS_SUBNET);
      }
      // RFC 4035 Section 3.2.1: always request DNSSEC records from upstream so the
      // cache is always populated with signatures regardless of the client DO bit.
      // The handler strips DNSSEC RRs from responses sent to non-DO clients.
      target.searchParams.set("do", "1");
      resp = await fetch(target.href, {
        method: "GET",
        headers: { Accept: "application/dns-json" },
        signal: ac.signal,
      });
    }

    if (!resp.ok) {
      clearTimeout(timer);
      if (debug) console.log(`[DoH] Upstream[${index}] HTTP error ${resp.status}`);
      return { index, ok: false };
    }

    const ct = (resp.headers.get("content-type") || "").toLowerCase();
    if (debug) console.log(`[DoH] Upstream[${index}] HTTP ${resp.status}  ct="${ct}"`);

    if (ct.includes("dns-message")) {
      // The timeout must stay armed across the body read: headers can arrive
      // promptly and the body then stall forever, which would hang the fan-out.
      const rawFull = await readCapped(resp, maxMessage);
      clearTimeout(timer);
      // A 200 with a body too short to be a DNS message is not a usable answer;
      // without this it scores as ok and can win pickBestResult and be cached.
      if (rawFull.length < DNS_HEADER_SIZE) {
        if (debug) console.log(`[DoH] Upstream[${index}] response too short (${rawFull.length}B)`);
        return { index, ok: false };
      }
      rawFull[0] = 0; rawFull[1] = 0; // Zero DNS ID (RFC 8484 SS.4.1)
      // Strip/filter EDNS OPT from upstream response: removes server cookies, upstream
      // NSID data, and other upstream-specific options before caching or returning.
      const raw = cfg
        ? processEdnsIncoming(rawFull, cfg, (serverCookieBytes) => {
            if (cookiesMode === "reoriginate") updateServerCookie(upstreamUrl, serverCookieBytes);
          })
        : rawFull;

      const { blocked, servfail } = inspectWireResponse(raw);
      if (debug) {
        const f = raw.length >= 4 ? (raw[2] << 8) | raw[3] : 0;
        const nscount = raw.length >= 10 ? (raw[8] << 8) | raw[9] : 0;
        console.log(`[DoH] Upstream[${index}] wire: len=${raw.length} rcode=${f & 0xf} AA=${!!(f & 0x0400)} nscount=${nscount} blocked=${blocked} servfail=${servfail}`);
      }
      if (servfail) return { index, ok: false };

      if (clientWantsJson) {
        const json = wireToJson(raw);
        if (!json) return { index, ok: false };
        return { index, ok: true, blocked, wire: false, json, hasDnssec: hasDnssecDataJson(json) };
      }
      return { index, ok: true, blocked, wire: true, raw, hasDnssec: hasDnssecData(raw) };
    }

    const json = JSON.parse(new TextDecoder().decode(await readCapped(resp, maxMessage * JSON_SIZE_FACTOR)));
    clearTimeout(timer);
    if (debug) console.log(`[DoH] Upstream[${index}] json: Status=${json.Status} hasAnswer=${Array.isArray(json.Answer)} hasAuthority=${Array.isArray(json.Authority)} authorityLen=${Array.isArray(json.Authority) ? json.Authority.length : 0}`);
    if (isServerFailure(json)) return { index, ok: false };
    return { index, ok: true, blocked: isBlockedOrNxdomain(json), wire: false, json, hasDnssec: hasDnssecDataJson(json) };

  } catch (e) {
    clearTimeout(timer);
    if (debug) console.log(`[DoH] Upstream[${index}] exception: ${e && e.message || "timeout/network error"}`);
    return { index, ok: false };
  }
}
