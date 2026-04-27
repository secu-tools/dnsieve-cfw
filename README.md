# dnsieve-cfw

A lightweight Cloudflare Worker that acts as a DNS-over-HTTPS (DoH) multi-upstream proxy with
built-in blocking detection, per-profile routing, and dual-layer caching.

> **Development Status**
>
> DNSieve-CFW is still under active development. Not all features have been fully tested and edge cases may exist. This project was built for personal use -- use it at your own discretion.
>
> If you encounter any issues, please open a report in the [Issues](../../issues) section. Include full app version and commit sha, steps to reproduce and a screenshot when possible -- it helps a lot. I may or may not have time to address every report, but all feedback is appreciated.

> **Note - Go version available**
> A Go implementation with improved performance, lower latency, and additional capabilities is
> available at <https://github.com/secu-tools/dnsieve>. If you need higher throughput or
> self-hosted deployment outside Cloudflare Workers, the Go version is the recommended choice.

## AI Assisted

This project is AI assisted. The core idea and original code started back in 2020 as a personal project, written in a messy "it works on my machine" style. AI helped finish planned features, clean up and restructure the code, make it more efficient, and catch bugs that weren't even on the radar.

## Script Privacy

The app communicates only with the IPs and domains you explicitly configure in the config file. That's it. No telemetry, no callbacks, no surprises. Feel free to read through the code to verify.

## What it does

dnsieve-cfw receives DoH queries from DNS clients (browsers, dnscrypt-proxy, system resolvers, etc.)
and fans them out concurrently to multiple upstream DoH servers. It:

- Forwards queries in both wire format (RFC 8484) and JSON format
- Inspects each upstream response to detect **blocked / NXDOMAIN** answers before replying
- Returns the first clean answer or, when all upstreams agree, the blocked result
- Caches responses at the Cloudflare edge (worker-side) and instructs clients via `Cache-Control`
- Routes queries to different upstream profiles based on the URL path

## Features

| Feature | Detail |
|---|---|
| RFC 8484 compliant | Wire-format GET (`?dns=`) and POST (`Content-Type: application/dns-message`) |
| JSON DoH | `?name=example.com&type=A` with `application/dns-json` response |
| IDN / Unicode domains | Normalises Unicode labels to ACE / Punycode for cache key consistency |
| Multi-upstream fan-out | Queries all upstreams concurrently; returns the best result by priority |
| Block detection | Detects `0.0.0.0` / `::` A/AAAA answers and NXDOMAIN with no authority section (Quad9-style blocks) |
| Configurable blocking mode | Generates local block responses in `null`, `nxdomain`, `nodata`, or `refused` mode |
| Early block return | Returns a blocked result as soon as one upstream confirms it; skips the remaining wait |
| EDE for blocked domains | Optionally injects RFC 8914 Extended DNS Error (info-code 15 / Blocked) into block responses |
| DNSSEC preference | Prefers DNSSEC-signed upstream responses (AD flag or RRSIG) over unsigned ones |
| SERVFAIL / REFUSED filtering | Treats SERVFAIL (rcode=2) and REFUSED (rcode=5) upstream responses as failed upstreams. If all upstreams fail, returns HTTP 200 with a synthetic SERVFAIL DNS response (RFC 8484 s4.2.1). Neither error type is cached (RFC 2308, RFC 8484 s5.1) |
| Per-profile routing | URL path `/p-{6 hex chars}` selects a NextDNS-style profile ID for the first upstream |
| Dual-layer caching | Edge cache (`caches.default`) + `Cache-Control` header for client-side caching |
| Background cache refresh | Stale-while-revalidate: when a cached entry falls below `CACHE_RENEW_PERCENT`% of its TTL, the cached response is served immediately while a background upstream re-query refreshes the cache via `ctx.waitUntil()` |
| Separate blocked TTL | Blocked results use a longer, independently configurable TTL |
| DNS transaction ID | Client wire-format ID preserved in responses; upstream and cache always use ID 0 (RFC 8484 SS.4.1) |
| Circular pointer guard | DNS name parser rejects malformed packets with compression pointer loops (max 128 hops) |
| DNSSEC-aware caching | Upstreams always queried with DO=1; cache stores full DNSSEC-signed responses; DNSSEC RRs stripped for non-DO clients (RFC 4035 SS.3.1.4.1) |
| CORS | `Access-Control-Allow-Origin: *` on all responses; `OPTIONS` preflight handled |
| Wire <-> JSON converter | Built-in wire-to-JSON parser (no external dependencies) covering A, AAAA, CNAME, DNAME, MX, NS, PTR, SOA, SRV, TXT, DS, RRSIG, NSEC, DNSKEY, NSEC3, CAA, and more |

## Deployment

### Option 1 - Cloudflare Builds (git-integrated)

> **Prerequisite**
>
> Cloudflare Builds can only connect to a repository that you own. If you are deploying from
> this project, you must fork it to your own GitHub or GitLab account before proceeding. Do not
> attempt to connect the original repository directly

Cloudflare Builds provides native git integration. Every push to the connected branch
triggers a build and deploy automatically with no additional secrets or workflows.

1. Fork this repository to your own GitHub or GitLab account.
2. Go to your Cloudflare dashboard and open the Worker.
3. Navigate to **Settings > Builds**.
4. Connect your forked repository.
5. Set the following commands (leave blank to use Cloudflare defaults):

   | Setting | Value |
   |---|---|
   | Build command | `npm test` |
   | Deploy command | `npx wrangler deploy` (Cloudflare default) |

6. Push to the configured branch - Cloudflare will run the tests and deploy automatically.

Non-production branches use `npx wrangler versions upload` by default, which uploads a preview
version without making it live. You can override this in the Builds settings.

### Option 2 - Wrangler CLI (manual / CI)

```sh
npm install
npm test          # run tests before deploying
npx wrangler deploy
```

Requires `CLOUDFLARE_API_TOKEN` in the environment (or in `~/.wrangler/config`).

### GitHub Actions

`.github/workflows/ci.yml` runs the test suite on every push and pull request as an
additional safety net. Deployment itself is handled by Cloudflare Builds so no

## Configuration

Configuration is driven by two layers that are merged at request time:

1. **`src/config.js`** -- module-level defaults. Changing these requires redeploying code.
2. **`wrangler.toml` `[vars]` / Cloudflare dashboard** -- runtime environment variables that
   override the defaults without a code redeploy. Set them under
   **Workers > Settings > Variables** in the Cloudflare dashboard, or in the `[vars]` block of
   `wrangler.toml`.

The `getConfig(env)` factory in `src/config.js` merges both layers on every request.

### Identity

| Variable | Default | Description |
|---|---|---|
| `GENERAL_PROFILE_ID` | `"000000"` | Fallback profile ID used when no `/p-{hex}` segment is present in the URL |

### Timing

| Variable | Default | Description |
|---|---|---|
| `MIN_WAIT_MS` | `"200"` | Minimum milliseconds to wait before declaring an early block result and returning |
| `UPSTREAM_TIMEOUT_MS` | `"1500"` | Per-upstream fetch timeout in milliseconds; timed-out upstreams are treated as failed |

### Upstream servers

Default value in `wrangler.toml`:
```toml
UPSTREAM_SERVERS = '["https://dns.quad9.net/dns-query","https://security.cloudflare-dns.com/dns-query"]'
```

Or as a code comment in `src/config.js`:
```js
export const UPSTREAM_SERVERS = [
  // To use a profile-based resolver (e.g. NextDNS), add it as the first entry:
  // "https://dns.nextdns.io/{PROFILE_ID}",
  "https://dns.quad9.net/dns-query",               // index 0 - highest priority
  "https://security.cloudflare-dns.com/dns-query", // index 1
];
```

- The defaults are two public resolvers (Quad9 + Cloudflare). No account or signup needed.
- Entries are tried **in parallel**; results are selected in **priority order** (index 0 first).
- `{PROFILE_ID}` in a template is replaced with the extracted or default profile ID at request time.
- Add, remove, or reorder entries freely. `UPSTREAM_COUNT` is derived automatically.
- To override via the dashboard, set `UPSTREAM_SERVERS` to a JSON array string.

### Cache TTLs

| Variable | Default | Description |
|---|---|---|
| `MIN_CACHE_TTL_FLOOR` | `"60"` | Absolute minimum TTL (seconds) applied to both edge and client caches |
| `WORKER_CACHE_TTL_SECONDS` | `"1800"` | Edge cache TTL for normal (non-blocked) responses |
| `WORKER_BLOCKED_CACHE_TTL_SECONDS` | `"86400"` | Edge cache TTL for blocked / NXDOMAIN responses |
| `CLIENT_CACHE_TTL_SECONDS` | `"1800"` | `Cache-Control: max-age` for normal responses sent to clients |
| `CLIENT_BLOCKED_CACHE_TTL_SECONDS` | `"86400"` | `Cache-Control: max-age` for blocked responses sent to clients |
| `CACHE_RENEW_PERCENT` | `"10"` | Percentage of original worker-side TTL remaining that triggers a background upstream refresh (0 = disabled) |

The actual TTL is `min(configured_ttl, dns_record_ttl)`, floored at `MIN_CACHE_TTL_FLOOR`.

### Background cache refresh (stale-while-revalidate)

When `CACHE_RENEW_PERCENT` is greater than 0, the worker uses a stale-while-revalidate strategy
to keep cached entries fresh without adding latency:

1. A client request arrives and finds a cache hit.
2. If the remaining worker-side TTL is below `CACHE_RENEW_PERCENT`% of the original TTL, the
   cached response is returned to the client immediately (no extra latency).
3. Simultaneously, `ctx.waitUntil()` fires a background upstream re-query using the same rules
   as a normal cache miss (all upstreams in parallel, DNSSEC preference, blocked-result logic).
4. The fresh result is written back to the edge cache before the background task completes.

**Example:** with `CACHE_RENEW_PERCENT = 10` and `WORKER_CACHE_TTL_SECONDS = 1800`, the
background refresh triggers when 180 seconds or fewer remain on the cached entry -- well before
the entry expires and forces a synchronous upstream round-trip.

Set `CACHE_RENEW_PERCENT = 0` to revert to on-demand-only caching (the previous default
behaviour).

The `X-Cache-Inserted-At` header stored internally on each edge-cache entry records the Unix
timestamp (seconds) when the entry was written. This is used by the worker to calculate remaining
TTL at serve time. The header is not forwarded to clients.

### Debug logging

| Variable | Default | Description |
|---|---|---|
| `DEBUG` | `"false"` | Set to `"true"` to enable verbose `console.log` output visible via `wrangler tail` |

Keeping `DEBUG = "false"` in production prevents sensitive query details from appearing in logs.
Toggle it to `"true"` temporarily in the Cloudflare dashboard to diagnose issues without redeploying.

Cloudflare Workers Logs (persistent structured logs in the dashboard) are separately controlled by
`[observability] enabled = false` in `wrangler.toml`, which is set to `false` by default in this
project. See the [Privacy](#privacy) section for full details.

### Blocking modes

When an upstream resolver signals that a domain is blocked (e.g. Quad9-style NXDOMAIN with no
authority, or `0.0.0.0`/`::` answers), the proxy generates a local response in one of four modes.
This controls exactly what the client sees.

| `BLOCKING_MODE` | Description |
|---|---|
| `"null"` **(default)** | NOERROR with `A=0.0.0.0` / `AAAA=::`. Compatible with Pi-hole NULL mode. |
| `"nxdomain"` | NXDOMAIN (rcode=3), empty answer, no authority section. |
| `"nodata"` | NOERROR (rcode=0), empty answer section. |
| `"refused"` | REFUSED (rcode=5). |

| Variable | Default | Description |
|---|---|---|
| `BLOCKING_MODE` | `"null"` | Blocking response mode (see table above) |

Wire-format blocked responses always include an Extended DNS Error (RFC 8914) option with info
code 15 (Blocked) and extra text derived automatically from the blocking upstream URL:
`Blocked (https://upstream/dns-query)`.

The proxy always prefers upstream responses that contain DNSSEC data (AD flag or RRSIG records)
over unsigned responses, even if the unsigned response arrived from a higher-priority upstream.

## Privacy

dnsieve-cfw is designed with privacy as a default. The following measures are in place:

| Area | Behaviour |
|---|---|
| **Cloudflare Workers Logs** | Explicitly disabled via `[observability] enabled = false` in `wrangler.toml`. Cloudflare will not persist structured request logs in the dashboard. |
| **Verbose logging** | `DEBUG = "false"` by default. No query names, client IDs, or upstream details are written to `console.log` in production. Enable only temporarily via the dashboard for diagnostics. |
| **Query parameter forwarding** | In JSON DoH mode, only the standard parameters (`name`, `type`, `ct`, `do`, `cd`) are forwarded to upstream resolvers. All other client-supplied parameters are silently dropped. In ECS `forward` or `substitute` mode `edns_client_subnet` is also forwarded (see below). |
| **EDNS OPT processing (wire format)** | In wire-format mode (POST and GET `?dns=`), the EDNS OPT record is processed according to the per-option privacy modes configured in `wrangler.toml [vars]` (see table below). By default all privacy-sensitive options are stripped. The DNSSEC OK (DO) bit is always set to 1 in outgoing queries regardless of what the client sent (RFC 4035 SS.3.2.1); clients that did not request DNSSEC receive stripped responses (RFC 4035 SS.3.1.4.1). OPT records are also processed on upstream responses before caching. |
| **Client headers** | Upstream fetches only send `Accept` and `Content-Type`. No client IP, `User-Agent`, `Cookie`, or other request headers are forwarded. |
| **DNS transaction IDs** | Wire-format IDs are zeroed before being sent upstream and before caching (RFC 8484 SS.4.1). The original ID is restored only in the copy returned to the requesting client. |

### Configurable EDNS Privacy Modes

Each EDNS option type has an independent mode that you can set in `wrangler.toml [vars]`.
All modes default to `"strip"` for maximum privacy.

#### ECS -- EDNS Client Subnet (RFC 7871, option 8)

| `PRIVACY_ECS_MODE` | Behaviour |
|---|---|
| `"strip"` **(default)** | ECS is removed from all forwarded queries and upstream responses. |
| `"forward"` | Client ECS is forwarded verbatim to upstream resolvers. Also passes `edns_client_subnet` in JSON mode. |
| `"substitute"` | ECS in the forwarded query is replaced with `PRIVACY_ECS_SUBNET` (e.g. `"203.0.113.0/24"`). Hides the exact client address while still providing coarse geolocation. Also injects `edns_client_subnet` in JSON mode. |

`PRIVACY_ECS_SUBNET` -- CIDR string used when `PRIVACY_ECS_MODE = "substitute"` (e.g. `"203.0.113.0/24"`).

#### DNS Cookies (RFC 7873, option 10)

| `PRIVACY_COOKIES_MODE` | Behaviour |
|---|---|
| `"strip"` | All cookies are removed from forwarded queries and upstream responses. |
| `"reoriginate"` **(default)** | Client cookies are never forwarded. The proxy generates its own stable per-upstream client cookie and manages the server cookie state in worker memory. Enables resolver-side RTT optimisation without exposing any client-side cookie. Cookie state is per worker instance and resets on cold start. |

#### NSID -- Name Server Identifier (RFC 5001, option 3)

| `PRIVACY_NSID_MODE` | Behaviour |
|---|---|
| `"strip"` **(default)** | NSID requests are removed from forwarded queries; NSID data is removed from upstream responses. |
| `"forward"` | NSID requests are forwarded to upstreams and NSID data in responses is passed through to the client. |
| `"substitute"` | NSID requests are NOT forwarded to upstreams. Instead the proxy returns `PRIVACY_NSID_VALUE` as its own NSID identifier directly in the response. Upstream resolver identity is hidden. |

`PRIVACY_NSID_VALUE` -- human-readable proxy identifier returned when `PRIVACY_NSID_MODE = "substitute"` (e.g. `"dnsieve-cfw-01"`).

> **Note:** Cloudflare itself still processes all traffic as the underlying platform.
> The measures above reduce data exposure within the worker runtime and to upstream DNS resolvers,
> but they do not remove Cloudflare infrastructure-level visibility.

## Supported client request formats

```
GET  /dns-query?name=example.com&type=A        Accept: application/dns-json
GET  /dns-query?name=muenchen.de&type=AAAA     Accept: application/dns-json   (IDN normalised)
GET  /dns-query?dns=<base64url>                Accept: application/dns-message
POST /dns-query                                Content-Type: application/dns-message
```

## Response headers

Every successful response includes:

| Header | Example | Description |
|---|---|---|
| `X-Profile-Id` | `000000` | Profile ID used for this request |
| `X-Blocked` | `true` | Whether the response was classified as blocked |
| `X-Blocking-Mode` | `null` | Blocking mode used to generate the block response (only present on blocked responses) |
| `X-Upstream-Index` | `0` | Index of the upstream server that provided the result |
| `X-All-Responded` | `true` | Whether all configured upstreams responded before the result was returned |
| `X-Client-Cache-TTL` | `1800` | The `max-age` value written into `Cache-Control` |
| `X-Worker-Version` | `1.0.0` | Semantic version of the deployed worker (see `src/version.js`) |
| `X-Worker-Cache-TTL` | `1800` | (on cached clones only) Edge cache TTL applied by the worker |
| `X-Cache-Inserted-At` | `1713220800` | (on cached clones only) Unix timestamp (seconds) when the edge-cache entry was written; used internally for background refresh TTL calculation |
| `Cache-Control` | `public, max-age=1800` | Standard caching directive for the client |

## Error responses

| HTTP Status | Condition |
|---|---|
| `400` | Request does not match any supported DoH format |
| `405` | Method other than GET, POST, or OPTIONS |
| `413` | POST body exceeds 65535 bytes |
| `415` | POST with wrong `Content-Type` (must be `application/dns-message`) |
| `200` + SERVFAIL DNS body | All configured upstream servers failed or timed out (RFC 8484 s4.2.1: DNS errors use HTTP 200) |
| `500` | Unexpected internal worker error |

## URL path and profile routing

Requests to a path matching `/p-{6 hex chars}` extract those 6 hex digits as the profile ID.
Any other path falls back to `GENERAL_PROFILE_ID`.

```
https://your-worker.example.com/p-000000/dns-query?name=example.com&type=A
                                    ^
                                    profile ID injected into the first upstream URL template
```

The profile ID is substituted into upstream URL templates containing `{PROFILE_ID}` (e.g. NextDNS).

## DNSSEC-aware caching

dnsieve-cfw follows RFC 4035 for DNSSEC handling at the proxy layer:

### Outgoing queries always carry DO=1 (RFC 4035 SS.3.2.1)

Regardless of whether the client set the DNSSEC OK bit, every query forwarded to an upstream
resolver has DO=1. This ensures that cached responses always contain the full set of DNSSEC
authentication records (RRSIG, NSEC, DNSKEY, NSEC3).

### Unified cache keys for DO=0 and DO=1 clients

Cache keys are derived from the query name and type (e.g. `example.com/A`), not from the raw
wire message bytes. A non-validating client (DO=0) and a DNSSEC-validating client (DO=1) querying
the same name and type share the same cache entry. The single cached copy always contains DNSSEC
records; they are stripped before delivery to non-DO clients (see below).

### DNSSEC stripping for non-DO clients (RFC 4035 SS.3.1.4.1)

When a cached (or freshly fetched) response is returned to a client that did not set DO=1, the
proxy removes DNSSEC authentication RRs (RRSIG, NSEC, DNSKEY, NSEC3) from the Answer and
Authority sections before replying. The DO bit in the response OPT record is also cleared to
accurately reflect the client's request (RFC 6891 S.6.1.4 / RFC 3225). This applies to:

- Wire-format responses (POST and GET `?dns=`)
- JSON DoH responses (`?name=&type=`)

Exception: if the client explicitly requested a DNSSEC record type (e.g. `type=DNSKEY` or
`type=RRSIG`), that type is kept in the response even without DO=1.

### Synthetic response headers mirror client query context (RFC 1035 S.4.1.1)

SERVFAIL and blocked responses generated locally by the proxy copy the RD (Recursion Desired)
bit from the original client query into the response header, as required by RFC 1035 Section 4.1.1.

### Wire GET malformed request handling (RFC 8484 S.4.1)

A GET request with a `?dns=` parameter that is not a valid base64url string, or that decodes to
fewer than 12 bytes (the minimum DNS message header size), returns HTTP 400 immediately. This
matches the requirement in RFC 8484 Section 4.1 that servers return 400 for invalid encodings.

## Standards compliance

- RFC 1035 - Domain Names - Implementation and Specification (DNS wire format)
  - S.4.1.1: RD (Recursion Desired) bit copied from query into all synthetic responses (SERVFAIL, blocked)
- RFC 2782 - A DNS RR for specifying the location of services (SRV)
- RFC 3596 - DNS Extensions to Support IP Version 6 (AAAA)
- RFC 4034 - Resource Records for the DNS Security Extensions (DNSKEY, RRSIG, NSEC, DS)
- RFC 4035 - Protocol Modifications for the DNS Security Extensions
  - SS.3.2.1: outgoing queries always carry DO=1 so cache is always populated with DNSSEC records
  - SS.3.1.4.1: DNSSEC authentication RRs (RRSIG, NSEC, DNSKEY, NSEC3) stripped from responses to non-DO clients, unless the type was explicitly requested
- RFC 4343 - DNS Case-Insensitivity
- RFC 5001 - DNS Name Server Identifier (NSID) option
- RFC 5155 - DNS Security (DNSSEC) Hashed Authenticated Denial of Existence (NSEC3)
- RFC 5891 / IDNA 2008 - Internationalized Domain Names
- RFC 6672 - DNAME Redirection in the DNS
- RFC 6891 - Extension Mechanisms for DNS (EDNS(0))
  - S.6.1.4: DO bit cleared in responses sent to non-DO clients (mirrored from query per RFC 3225)
- RFC 7871 - Client Subnet in DNS Queries (ECS)
- RFC 7873 - Domain Name System (DNS) Cookies
- RFC 8484 - DNS Queries over HTTPS
  - S.4.1: HTTP 400 returned for invalid base64url encoding or sub-12-byte DNS message in `?dns=`
  - S.4.2.1: SERVFAIL returned as HTTP 200 (not 502); Cache-Control: no-store on errors
- RFC 8659 - DNS Certification Authority Authorization (CAA) Resource Record
- RFC 8914 - Extended DNS Errors
- RFC 9460 - Service Binding and Parameter Specification via the DNS (SVCB and HTTPS)
- WHATWG URL Standard SS.3.3 - IDN toASCII processing
- Google / Cloudflare JSON DoH API convention

## License

MIT License - Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (<https://jack-l.com>)

See [LICENSE](LICENSE) for the full license text.
