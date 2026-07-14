// SPDX-License-Identifier: MIT
// dnsieve-cfw - Configuration constants
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)

// Profile used when no /p-{hex} segment is present in the request URL
export const GENERAL_PROFILE_ID = "000000";

// Minimum milliseconds to wait before returning an early block result
export const MIN_WAIT_MS = 200;

// Per-upstream fetch timeout; timed-out upstreams are treated as failed
export const UPSTREAM_TIMEOUT_MS = 1500;

// Absolute minimum TTL applied to both edge and client caches
export const MIN_CACHE_TTL_FLOOR = 60;

// Edge cache TTL for normal (non-blocked) responses
export const WORKER_CACHE_TTL_SECONDS = 1800;

// Edge cache TTL for blocked / NXDOMAIN responses
export const WORKER_BLOCKED_CACHE_TTL_SECONDS = 86400;

// Cache-Control max-age for normal responses
export const CLIENT_CACHE_TTL_SECONDS = 1800;

// Cache-Control max-age for blocked responses
export const CLIENT_BLOCKED_CACHE_TTL_SECONDS = 86400;

// Upstream DoH servers in priority order (index 0 = highest priority)
// {PROFILE_ID} is substituted at request time via buildUpstreamUrl().
//
// To use a profile-based resolver (e.g. NextDNS), add it as the first entry:
//   "https://dns.nextdns.io/{PROFILE_ID}",
export const UPSTREAM_SERVERS = [
  "https://dns.quad9.net/dns-query",
  "https://security.cloudflare-dns.com/dns-query",
];

export const UPSTREAM_COUNT = UPSTREAM_SERVERS.length;

export const MAX_DNS_MESSAGE_SIZE = 65535;

// Verbose console.log output visible via `wrangler tail`. Keep false in
// production: debug logs include query details.
export const DEBUG = false;

// ---------------------------------------------------------------------------
// Privacy - EDNS option handling for outgoing queries and upstream responses
// ---------------------------------------------------------------------------
// ECS (RFC 7871, EDNS option 8) handling mode:
//   "strip"      - Remove ECS from all forwarded queries (best for privacy)
//   "forward"    - Forward client ECS verbatim to upstreams
//   "substitute" - Replace with PRIVACY_ECS_SUBNET (hides exact client address)
export const PRIVACY_ECS_MODE = "strip";

// Subnet sent upstream when PRIVACY_ECS_MODE = "substitute", e.g. "203.0.113.0/24"
export const PRIVACY_ECS_SUBNET = "";

// DNS Cookie (RFC 7873, EDNS option 10) handling mode:
//   "strip"       - Remove all cookies from forwarded queries and responses
//   "reoriginate" - Generate a proxy-owned per-upstream cookie; client cookies are
//                   never forwarded. Cookie state is per worker instance.
export const PRIVACY_COOKIES_MODE = "reoriginate";

// NSID (RFC 5001, EDNS option 3) handling mode:
//   "strip"      - Remove NSID from forwarded queries
//   "forward"    - Forward NSID requests to upstreams verbatim
//   "substitute" - Intercept NSID; return PRIVACY_NSID_VALUE as the proxy identifier
//                  (NSID request is NOT forwarded to upstreams in this mode)
export const PRIVACY_NSID_MODE = "strip";

// Identifier returned to clients when PRIVACY_NSID_MODE = "substitute"
export const PRIVACY_NSID_VALUE = "";

// ---------------------------------------------------------------------------
// Blocking - controls how blocked domain responses are generated locally
// ---------------------------------------------------------------------------
// Blocking mode (how the proxy responds to blocked domains):
//   "null"      - NOERROR with A=0.0.0.0 / AAAA=:: (Pi-hole NULL equivalent)
//   "nxdomain"  - NXDOMAIN (rcode=3), empty answer, no authority
//   "nodata"    - NOERROR, empty answer section
//   "refused"   - REFUSED (rcode=5)
export const BLOCKING_MODE = "null";

// ---------------------------------------------------------------------------
// Cache renewal - stale-while-revalidate background refresh
// ---------------------------------------------------------------------------
// Percentage (0-99) of the original worker-side TTL that, when remaining,
// triggers a background upstream refresh while the cached entry is still
// served to the client. 0 disables proactive refresh.
export const CACHE_RENEW_PERCENT = 10;

// Wire-format blocked responses always include an EDE (RFC 8914) option with
// info code 15 (Blocked) naming the blocking upstream. Not configurable.

// ---------------------------------------------------------------------------
// Runtime config factory - merges CF Workers env bindings with the defaults above.
// ---------------------------------------------------------------------------

/**
 * Build a runtime configuration object from CF Workers env bindings
 * (wrangler.toml [vars] / dashboard variables; all bindings are strings).
 * Every field falls back to the module-level default when the binding is
 * absent. See README.md for the full variable reference.
 *
 * @param {object} [env={}] CF Workers env bindings
 * @returns {object} Runtime configuration
 */
export function getConfig(env = {}) {
  let servers = UPSTREAM_SERVERS;
  if (env.UPSTREAM_SERVERS) {
    try {
      const parsed = JSON.parse(env.UPSTREAM_SERVERS);
      if (Array.isArray(parsed)) servers = parsed;
    } catch {}
  }

  return {
    GENERAL_PROFILE_ID:               env.GENERAL_PROFILE_ID               ?? GENERAL_PROFILE_ID,
    MIN_WAIT_MS:                       Number(env.MIN_WAIT_MS                ?? MIN_WAIT_MS),
    UPSTREAM_TIMEOUT_MS:               Number(env.UPSTREAM_TIMEOUT_MS        ?? UPSTREAM_TIMEOUT_MS),
    MIN_CACHE_TTL_FLOOR:               Number(env.MIN_CACHE_TTL_FLOOR        ?? MIN_CACHE_TTL_FLOOR),
    WORKER_CACHE_TTL_SECONDS:          Number(env.WORKER_CACHE_TTL_SECONDS   ?? WORKER_CACHE_TTL_SECONDS),
    WORKER_BLOCKED_CACHE_TTL_SECONDS:  Number(env.WORKER_BLOCKED_CACHE_TTL_SECONDS ?? WORKER_BLOCKED_CACHE_TTL_SECONDS),
    CLIENT_CACHE_TTL_SECONDS:          Number(env.CLIENT_CACHE_TTL_SECONDS   ?? CLIENT_CACHE_TTL_SECONDS),
    CLIENT_BLOCKED_CACHE_TTL_SECONDS:  Number(env.CLIENT_BLOCKED_CACHE_TTL_SECONDS ?? CLIENT_BLOCKED_CACHE_TTL_SECONDS),
    UPSTREAM_SERVERS:                  servers,
    UPSTREAM_COUNT:                    servers.length,
    MAX_DNS_MESSAGE_SIZE:              Number(env.MAX_DNS_MESSAGE_SIZE       ?? MAX_DNS_MESSAGE_SIZE),
    DEBUG:                             env.DEBUG === "true" || DEBUG,
    PRIVACY_ECS_MODE:                  env.PRIVACY_ECS_MODE                  ?? PRIVACY_ECS_MODE,
    PRIVACY_ECS_SUBNET:                env.PRIVACY_ECS_SUBNET                ?? PRIVACY_ECS_SUBNET,
    PRIVACY_COOKIES_MODE:              env.PRIVACY_COOKIES_MODE              ?? PRIVACY_COOKIES_MODE,
    PRIVACY_NSID_MODE:                 env.PRIVACY_NSID_MODE                 ?? PRIVACY_NSID_MODE,
    PRIVACY_NSID_VALUE:                env.PRIVACY_NSID_VALUE                ?? PRIVACY_NSID_VALUE,
    BLOCKING_MODE:                     env.BLOCKING_MODE                     ?? BLOCKING_MODE,
    CACHE_RENEW_PERCENT:               Number(env.CACHE_RENEW_PERCENT         ?? CACHE_RENEW_PERCENT),
  };
}
