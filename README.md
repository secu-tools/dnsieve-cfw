# dnsieve-cfw

A lightweight Cloudflare Worker that acts as a DNS-over-HTTPS (DoH) multi-upstream proxy with
built-in blocking detection, per-profile routing, and dual-layer caching.

> [!NOTE]
> A Go implementation with better performance and additional capabilities is available at
> <https://github.com/secu-tools/dnsieve>. Prefer it for higher throughput or self-hosted
> deployment outside Cloudflare Workers.

If you hit a problem, open a report in the [Issues](../../issues) section with the app version
and commit sha, steps to reproduce, and a screenshot when possible.

## Script Privacy

The app communicates only with the upstream DoH servers you configure. No telemetry, no
callbacks, no surprises. Feel free to read through the code to verify.

## What it does

dnsieve-cfw receives DoH queries from DNS clients (browsers, dnscrypt-proxy, system resolvers)
and fans them out concurrently to multiple upstream DoH servers. It:

- Forwards queries in both wire format (RFC 8484) and JSON format
- Inspects each upstream response to detect blocked / NXDOMAIN answers before replying
- Returns the first clean answer or, when all upstreams agree, the blocked result
- Caches responses at the Cloudflare edge and instructs clients via `Cache-Control`
- Routes queries to different upstream profiles based on the URL path

## Features

| Feature | Detail |
|---|---|
| RFC 8484 compliant | Wire-format GET (`?dns=`) and POST |
| JSON DoH | `?name=example.com&type=A` (Google/Cloudflare convention) |
| IDN / Unicode domains | Normalised to ACE / Punycode for cache key consistency |
| Multi-upstream fan-out | All upstreams queried concurrently; best result selected by priority |
| Block detection | `0.0.0.0` / `::` answers and NXDOMAIN without authority (Quad9-style) |
| Configurable blocking mode | Local block responses in `null`, `nxdomain`, `nodata`, or `refused` mode |
| Early block return | Replies as soon as one upstream confirms a block |
| EDE for blocked domains | RFC 8914 Extended DNS Error (info-code 15 / Blocked) on wire-format block responses |
| DNSSEC preference | Signed upstream responses (AD flag or RRSIG) preferred over unsigned ones |
| SERVFAIL / REFUSED filtering | Failing upstreams are skipped; synthetic SERVFAIL when all fail (never cached) |
| Per-profile routing | URL path `/p-{6 hex chars}` selects the profile ID for `{PROFILE_ID}` upstream templates |
| Dual-layer caching | Edge cache (`caches.default`) + `Cache-Control` for clients |
| Background cache refresh | Stale-while-revalidate re-query via `ctx.waitUntil()` |
| Separate blocked TTL | Blocked results use a longer, independently configurable TTL |
| DNSSEC-aware caching | Upstreams always queried with DO=1; DNSSEC RRs stripped for non-DO clients |
| CORS | `Access-Control-Allow-Origin: *`; `OPTIONS` preflight handled |
| Wire <-> JSON converter | Built-in wire-to-JSON parser, no external dependencies |

## Deployment

### Option 1 - Cloudflare Builds (git-integrated)

> [!IMPORTANT]
> Cloudflare Builds can only connect to a repository you own. Fork this project to your own
> GitHub or GitLab account first; do not connect the original repository directly.

Every push to the connected branch triggers a build and deploy automatically:

1. Fork this repository.
2. In the Cloudflare dashboard, open the Worker and go to **Settings > Builds**.
3. Connect your forked repository.
4. Set the build command to `npm test`; leave the deploy command at the Cloudflare default
   (`npx wrangler deploy`).
5. Push to the configured branch.

Non-production branches upload a preview version by default without making it live.

### Option 2 - Wrangler CLI (manual / CI)

```sh
npm install
npm test
npx wrangler deploy
```

Requires `CLOUDFLARE_API_TOKEN` in the environment (or in `~/.wrangler/config`).

`.github/workflows/ci.yml` runs the test suite on every push and pull request as an additional
safety net; deployment itself is handled by Cloudflare Builds.

## Configuration

Two layers are merged at request time by `getConfig(env)`:

1. **`src/config.js`** -- defaults; changing them requires a redeploy.
2. **`wrangler.toml` `[vars]` or the Cloudflare dashboard** (**Workers > Settings >
   Variables**) -- runtime overrides, no redeploy needed.

### Identity

| Variable | Default | Description |
|---|---|---|
| `GENERAL_PROFILE_ID` | `"000000"` | Fallback profile ID when no `/p-{hex}` segment is in the URL |

### Timing and limits

| Variable | Default | Description |
|---|---|---|
| `MIN_WAIT_MS` | `"200"` | Minimum milliseconds to wait before returning an early block result |
| `UPSTREAM_TIMEOUT_MS` | `"1500"` | Per-upstream fetch timeout; timed-out upstreams count as failed |
| `MAX_DNS_MESSAGE_SIZE` | `"65535"` | Maximum accepted DNS message size in bytes (larger requests get HTTP 413) |

### Upstream servers

Default value in `wrangler.toml`:
```toml
UPSTREAM_SERVERS = '["https://dns.quad9.net/dns-query","https://security.cloudflare-dns.com/dns-query"]'
```

- The defaults are two public resolvers (Quad9 + Cloudflare); no account needed.
- Entries are queried **in parallel**; results are selected in **priority order** (index 0 first).
- `{PROFILE_ID}` in a template is replaced at request time -- for a profile-based resolver
  such as NextDNS, add `"https://dns.nextdns.io/{PROFILE_ID}"` as the first entry.
- To override via the dashboard, set `UPSTREAM_SERVERS` to a JSON array string.

### Cache TTLs

| Variable | Default | Description |
|---|---|---|
| `MIN_CACHE_TTL_FLOOR` | `"60"` | Absolute minimum TTL (seconds) for both edge and client caches |
| `WORKER_CACHE_TTL_SECONDS` | `"1800"` | Edge cache TTL for normal responses |
| `WORKER_BLOCKED_CACHE_TTL_SECONDS` | `"86400"` | Edge cache TTL for blocked / NXDOMAIN responses |
| `CLIENT_CACHE_TTL_SECONDS` | `"1800"` | `Cache-Control: max-age` for normal responses |
| `CLIENT_BLOCKED_CACHE_TTL_SECONDS` | `"86400"` | `Cache-Control: max-age` for blocked responses |
| `CACHE_RENEW_PERCENT` | `"10"` | Remaining-TTL percentage that triggers a background refresh (0 = off) |

The actual TTL is `min(configured_ttl, dns_record_ttl)`, floored at `MIN_CACHE_TTL_FLOOR`.

### Background cache refresh (stale-while-revalidate)

When a cache hit has less than `CACHE_RENEW_PERCENT`% of its worker-side TTL remaining, the
cached response is returned immediately and a background re-query (via `ctx.waitUntil()`)
refreshes the edge cache using the normal cache-miss rules. Set `CACHE_RENEW_PERCENT = 0` to
disable.

### Debug logging

| Variable | Default | Description |
|---|---|---|
| `DEBUG` | `"false"` | Set to `"true"` for verbose `console.log` output visible via `wrangler tail` |

> [!CAUTION]
> Keep `DEBUG = "false"` in production -- verbose logs include query details. Toggle it in the
> dashboard temporarily to diagnose issues without redeploying.

### Blocking modes

When an upstream signals that a domain is blocked, the proxy generates a local response in one
of four modes:

| `BLOCKING_MODE` | Description |
|---|---|
| `"null"` **(default)** | NOERROR with `A=0.0.0.0` / `AAAA=::` (Pi-hole NULL equivalent) |
| `"nxdomain"` | NXDOMAIN (rcode=3), empty answer, no authority section |
| `"nodata"` | NOERROR (rcode=0), empty answer section |
| `"refused"` | REFUSED (rcode=5) |

Wire-format blocked responses always include an Extended DNS Error (RFC 8914) option with
info-code 15 (Blocked) naming the blocking upstream.

## Privacy

| Area | Behaviour |
|---|---|
| **Cloudflare Workers Logs** | Disabled via `[observability] enabled = false` in `wrangler.toml`. |
| **Verbose logging** | `DEBUG = "false"` by default; no query names or client details are logged. |
| **Query parameter forwarding** | JSON mode forwards only `name`, `type`, `ct`, `do`, `cd` (plus `edns_client_subnet` in ECS forward/substitute mode). |
| **EDNS OPT processing** | Options handled per the privacy modes below; unknown options are stripped, on both queries and responses. |
| **Client headers** | Upstream fetches send only `Accept` and `Content-Type` -- no client IP, `User-Agent`, or cookies. |
| **DNS transaction IDs** | Zeroed before upstream forwarding and caching (RFC 8484); restored only on the client's reply. |

### Configurable EDNS privacy modes

Set in `wrangler.toml [vars]`; all modes default to the most private option.

#### ECS -- EDNS Client Subnet (RFC 7871)

| `PRIVACY_ECS_MODE` | Behaviour |
|---|---|
| `"strip"` **(default)** | ECS removed from all forwarded queries and upstream responses. |
| `"forward"` | Client ECS forwarded verbatim. |
| `"substitute"` | ECS replaced with `PRIVACY_ECS_SUBNET` (e.g. `"203.0.113.0/24"`) -- coarse geolocation without the client address. |

#### DNS Cookies (RFC 7873)

| `PRIVACY_COOKIES_MODE` | Behaviour |
|---|---|
| `"strip"` | All cookies removed from forwarded queries and responses. |
| `"reoriginate"` **(default)** | Client cookies never forwarded; the proxy manages its own per-upstream cookie (resets on cold start). |

#### NSID -- Name Server Identifier (RFC 5001)

| `PRIVACY_NSID_MODE` | Behaviour |
|---|---|
| `"strip"` **(default)** | NSID removed from forwarded queries and upstream responses. |
| `"forward"` | NSID requests and response data passed through. |
| `"substitute"` | Proxy answers NSID itself with `PRIVACY_NSID_VALUE`; upstream identity stays hidden. |

> [!NOTE]
> Cloudflare itself still processes all traffic as the underlying platform. These measures
> reduce exposure to upstream resolvers, not Cloudflare infrastructure-level visibility.

## Supported client request formats

```
GET  /dns-query?name=example.com&type=A        Accept: application/dns-json
GET  /dns-query?name=muenchen.de&type=AAAA     Accept: application/dns-json   (IDN normalised)
GET  /dns-query?dns=<base64url>                Accept: application/dns-message
POST /dns-query                                Content-Type: application/dns-message
```

## Response headers

| Header | Example | Description |
|---|---|---|
| `X-Profile-Id` | `000000` | Profile ID used for this request |
| `X-Blocked` | `true` | Whether the response was classified as blocked |
| `X-Blocking-Mode` | `null` | Blocking mode used (only on blocked responses) |
| `X-Upstream-Index` | `0` | Index of the upstream that provided the result |
| `X-All-Responded` | `true` | Whether all upstreams responded before the result was returned |
| `X-Client-Cache-TTL` | `1800` | The `max-age` value written into `Cache-Control` |
| `X-Worker-Version` | `1.0.0` | Version of the deployed worker |
| `X-Worker-Cache-TTL` | `1800` | (cached copies only) Edge cache TTL applied by the worker |
| `X-Cache-Inserted-At` | `1713220800` | (cached copies only) Unix timestamp when the entry was cached |
| `Cache-Control` | `public, max-age=1800` | Standard caching directive for the client |

## Error responses

| HTTP Status | Condition |
|---|---|
| `400` | Request does not match any supported DoH format, or the DNS message is invalid / under 12 bytes |
| `405` | Method other than GET, POST, or OPTIONS |
| `413` | DNS message exceeds `MAX_DNS_MESSAGE_SIZE` (default 65535 bytes) |
| `415` | POST with wrong `Content-Type` (must be `application/dns-message`) |
| `200` + SERVFAIL DNS body | All upstreams failed or timed out (RFC 8484: DNS errors use HTTP 200) |
| `500` | Unexpected internal worker error |

## URL path and profile routing

A path matching `/p-{6 hex chars}` selects that profile ID; any other path falls back to
`GENERAL_PROFILE_ID`. The ID is substituted into upstream URL templates containing
`{PROFILE_ID}` (e.g. NextDNS).

```
https://your-worker.example.com/p-000000/dns-query?name=example.com&type=A
```

## DNSSEC handling

- Every upstream query carries DO=1 (RFC 4035), so cached responses always contain the full
  DNSSEC record set.
- Cache keys are derived from the query name and type, so DO=0 and DO=1 clients share the
  same cache entry.
- Responses to non-DO clients have RRSIG/NSEC/DNSKEY/NSEC3 stripped and the DO bit cleared
  (RFC 4035 / RFC 6891), unless the client explicitly queried for that DNSSEC type.
- Locally generated responses (SERVFAIL, blocked) mirror the client's RD and CD bits.

## Standards compliance

- RFC 1035 - Domain Names - Implementation and Specification (DNS wire format)
- RFC 2782 - A DNS RR for specifying the location of services (SRV)
- RFC 3596 - DNS Extensions to Support IP Version 6 (AAAA)
- RFC 4034 - Resource Records for the DNS Security Extensions
- RFC 4035 - Protocol Modifications for the DNS Security Extensions
- RFC 4343 - DNS Case-Insensitivity
- RFC 5001 - DNS Name Server Identifier (NSID) option
- RFC 5155 - DNSSEC Hashed Authenticated Denial of Existence (NSEC3)
- RFC 5891 / IDNA 2008 - Internationalized Domain Names
- RFC 6672 - DNAME Redirection in the DNS
- RFC 6891 - Extension Mechanisms for DNS (EDNS(0))
- RFC 7871 - Client Subnet in DNS Queries (ECS)
- RFC 7873 - Domain Name System (DNS) Cookies
- RFC 8484 - DNS Queries over HTTPS
- RFC 8659 - DNS Certification Authority Authorization (CAA) Resource Record
- RFC 8914 - Extended DNS Errors
- RFC 9460 - Service Binding via the DNS (SVCB and HTTPS)
- WHATWG URL Standard - IDN toASCII processing
- Google / Cloudflare JSON DoH API convention

## License

MIT License - Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (<https://jack-l.com>)

See [LICENSE](LICENSE) for the full license text.
