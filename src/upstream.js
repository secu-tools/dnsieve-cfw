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
} from "./dns.js";
import { UPSTREAM_TIMEOUT_MS, DEBUG, PRIVACY_COOKIES_MODE } from "./config.js";

// Only these query parameters are forwarded to upstream DoH servers in JSON mode.
// Forwarding arbitrary client params (e.g. edns_client_subnet) would leak client
// identity information to the upstream resolver.
const ALLOWED_JSON_PARAMS = new Set(["name", "type", "ct", "do", "cd"]);

// ---------------------------------------------------------------------------
// Per-upstream cookie state (RFC 7873 reoriginate mode)
// ---------------------------------------------------------------------------
// Module-level Map: lives for the lifetime of the worker instance (resets on
// cold start). Keys are upstream URL strings; values are { client, server }.
// Exported so tests can inspect and reset it between cases.
export const COOKIE_STORE = new Map();

function getCookieBytes(upstreamUrl) {
  if (!COOKIE_STORE.has(upstreamUrl)) {
    const client = new Uint8Array(8);
    crypto.getRandomValues(client);
    COOKIE_STORE.set(upstreamUrl, { client: client.slice(), server: null });
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

// ---------------------------------------------------------------------------
// Pre-parsed upstream URL cache
// ---------------------------------------------------------------------------
// Avoids re-parsing on every request in the hot path.
const UPSTREAM_URL_CACHE = new Map();

function getUpstreamUrlObj(resolvedUrl) {
  let u = UPSTREAM_URL_CACHE.get(resolvedUrl);
  if (!u) {
    u = new URL(resolvedUrl);
    if (UPSTREAM_URL_CACHE.size > 100) UPSTREAM_URL_CACHE.clear();
    UPSTREAM_URL_CACHE.set(resolvedUrl, u);
  }
  return u;
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
 * @returns {Promise<{index: number, ok: boolean, blocked?: boolean, wire?: boolean, raw?: Uint8Array, json?: object}>}
 */
export async function queryUpstream(index, upstreamUrl, method, url, bodyBytes, clientWantsJson, cfg) {
  const timeout = cfg ? cfg.UPSTREAM_TIMEOUT_MS : UPSTREAM_TIMEOUT_MS;
  const debug   = cfg ? cfg.DEBUG               : DEBUG;
  const cookiesMode = cfg ? cfg.PRIVACY_COOKIES_MODE : PRIVACY_COOKIES_MODE;
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
      const base = getUpstreamUrlObj(upstreamUrl);
      const target = new URL(base.href);
      // Decode the base64url DNS query, apply EDNS processing (strip/modify OPT),
      // then re-encode before forwarding. Falls back to the original value on parse error.
      let dnsParam = stripBase64Padding(url.searchParams.get("dns") || "");
      if (cfg) {
        try {
          const padded = dnsParam.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - dnsParam.length % 4) % 4);
          const binStr = atob(padded);
          const decoded = new Uint8Array(binStr.length);
          for (let i = 0; i < binStr.length; i++) decoded[i] = binStr.charCodeAt(i);
          // RFC 8484 SS.4.1: zero the DNS ID before upstream forwarding (same as POST path)
          if (decoded.length >= 2) { decoded[0] = 0; decoded[1] = 0; }
          const processed = processEdnsOutgoing(decoded, cfg, cookieBytes);
          let reenc = "";
          for (let i = 0; i < processed.length; i++) reenc += String.fromCharCode(processed[i]);
          dnsParam = btoa(reenc).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
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
      const base = getUpstreamUrlObj(upstreamUrl);
      const target = new URL(base.href);
      for (const [k, v] of url.searchParams.entries()) {
        if (ALLOWED_JSON_PARAMS.has(k)) target.searchParams.set(k, v);
        // ECS forward mode: also pass edns_client_subnet if present in client request
        if (k === "edns_client_subnet" && cfg && cfg.PRIVACY_ECS_MODE === "forward") {
          target.searchParams.set(k, v);
        }
      }
      // ECS substitute mode: inject the configured subnet as edns_client_subnet
      if (cfg && cfg.PRIVACY_ECS_MODE === "substitute" && cfg.PRIVACY_ECS_SUBNET) {
        target.searchParams.set("edns_client_subnet", cfg.PRIVACY_ECS_SUBNET);
      }
      // RFC 4035 Section 3.2.1: always request DNSSEC records from upstream so the
      // cache is always populated with signatures regardless of the client DO bit.
      // The handler strips DNSSEC RRs from responses sent to non-DO clients.
      target.searchParams.set("do", "1");
      if (!target.searchParams.has("name")) target.searchParams.set("name", ".");
      resp = await fetch(target.href, {
        method: "GET",
        headers: { Accept: "application/dns-json" },
        signal: ac.signal,
      });
    }

    clearTimeout(timer);
    if (!resp.ok) {
      if (debug) console.log(`[DoH] Upstream[${index}] HTTP error ${resp.status}`);
      return { index, ok: false };
    }

    const ct = (resp.headers.get("content-type") || "").toLowerCase();
    if (debug) console.log(`[DoH] Upstream[${index}] HTTP ${resp.status}  ct="${ct}"`);

    if (ct.includes("dns-message")) {
      const rawFull = new Uint8Array(await resp.arrayBuffer());
      if (rawFull.length >= 2) { rawFull[0] = 0; rawFull[1] = 0; } // Zero DNS ID (RFC 8484 SS.4.1)
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

    const json = await resp.json();
    if (debug) console.log(`[DoH] Upstream[${index}] json: Status=${json.Status} hasAnswer=${Array.isArray(json.Answer)} hasAuthority=${Array.isArray(json.Authority)} authorityLen=${Array.isArray(json.Authority) ? json.Authority.length : 0}`);
    if (isServerFailure(json)) return { index, ok: false };
    return { index, ok: true, blocked: isBlockedOrNxdomain(json), wire: false, json, hasDnssec: hasDnssecDataJson(json) };

  } catch (e) {
    clearTimeout(timer);
    if (debug) console.log(`[DoH] Upstream[${index}] exception: ${e && e.message || "timeout/network error"}`);
    return { index, ok: false };
  }
}
