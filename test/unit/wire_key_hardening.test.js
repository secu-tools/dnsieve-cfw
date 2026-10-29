// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// A wire query's cache key must name exactly what the upstream is asked.
// Resolvers compare labels octet by octet, folding ASCII case and nothing else
// (RFC 4343), so any wider folding of the question name -- Unicode case
// mapping, IDNA, lossy UTF-8 decoding -- let one client bind its answer to a
// name every other client looks up. Likewise a query carrying more than one
// plain question must not borrow that question's name+type key.

import { describe, it, expect, vi, afterEach } from "vitest";
import { buildCacheKey } from "../../src/cache.js";
import { buildDnsQuery, buildDnsQueryWithDo, buildDnsResponse, wireQueryKey } from "../../src/dns.js";
import { makeFakeCache, dispatch } from "../helpers/worker.js";

const POST_URL = new URL("https://w.example.com/dns-query");
const ONE = JSON.stringify(["https://u1.example.com/dns-query"]);

const ascii = (s) => Array.from(s, c => c.charCodeAt(0));

// A standard query (RD=1, class IN) whose name is given as raw label octets.
function queryFor(labels, qtype = 1) {
  const name = [];
  for (const l of labels) name.push(l.length, ...l);
  return new Uint8Array([
    0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ...name, 0x00, qtype >> 8, qtype & 0xff, 0x00, 0x01,
  ]);
}

const keyOf = async (q) => (await buildCacheKey("000000", POST_URL, q)).url;

afterEach(() => vi.restoreAllMocks());

describe("wire question names are keyed by their exact octets", () => {
  it("U+212A KELVIN SIGN does not share the key of the ASCII letter k", async () => {
    // "faceboo" + E2 84 AA + ".com": String.toLowerCase maps U+212A to "k".
    const kelvin = queryFor([[...ascii("faceboo"), 0xe2, 0x84, 0xaa], ascii("com")]);
    expect(await keyOf(kelvin)).not.toBe(await keyOf(buildDnsQuery("facebook.com", 1)));
  });

  it("raw UTF-8 labels do not share the key of their punycode form", async () => {
    // "m" + C3 BC + "nchen.de" is a different name on the wire from xn--mnchen-3ya.de.
    const raw = queryFor([[0x6d, 0xc3, 0xbc, ...ascii("nchen")], ascii("de")]);
    expect(await keyOf(raw)).not.toBe(await keyOf(buildDnsQuery("xn--mnchen-3ya.de", 1)));
  });

  it("non-ASCII letters differing only in case keep distinct keys", async () => {
    // C3 84 / C3 A4 are U+00C4 / U+00E4; DNS folds ASCII case only.
    const upper = queryFor([[0xc3, 0x84], ascii("com")]);
    const lower = queryFor([[0xc3, 0xa4], ascii("com")]);
    expect(await keyOf(upper)).not.toBe(await keyOf(lower));
  });

  it("invalid UTF-8 octets keep distinct keys", async () => {
    // Both decode to U+FFFD, which once collapsed them onto one key.
    expect(await keyOf(queryFor([[0x80], ascii("com")])))
      .not.toBe(await keyOf(queryFor([[0x81], ascii("com")])));
  });

  it("ASCII case still folds, and plain names keep the established key", async () => {
    expect(await keyOf(buildDnsQuery("EXAMPLE.com", 1))).toBe(await keyOf(buildDnsQuery("example.com", 1)));
    expect(await keyOf(buildDnsQuery("example.com", 1)))
      .toBe("https://doh-cache.internal/000000/json/example.com/A");
  });

  it("writes octets outside printable ASCII as \\DDD and escapes dots", () => {
    expect(wireQueryKey(queryFor([[0x61, 0x20, 0x62], [0x2e], [0xff]])).name).toBe("a\\032b.\\..\\255");
  });
});

describe("only plain queries borrow the name+type key", () => {
  // Each case keeps "victim.example A" as the first question but sends the
  // upstream something that key does not describe.
  const base = () => Array.from(buildDnsQuery("victim.example", 1));
  const aRecord = [0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 2, 3, 4];

  it.each([
    ["QDCOUNT=2", () => { const q = base(); q[5] = 2; return [...q, 0x01, 0x78, 0x00, 0x00, 0x01, 0x00, 0x01]; }],
    ["QCLASS CH", () => { const q = base(); q[q.length - 1] = 3; return q; }],
    ["an Answer record", () => { const q = base(); q[7] = 1; return [...q, ...aRecord]; }],
    ["a non-OPT Additional record", () => { const q = base(); q[11] = 1; return [...q, ...aRecord]; }],
    ["the QR bit", () => { const q = base(); q[2] |= 0x80; return q; }],
    ["the TC bit", () => { const q = base(); q[2] |= 0x02; return q; }],
    ["a compression pointer in the question name", () => [
      // The name is a pointer to bytes after the question, which the upstream
      // never receives once trailing bytes are dropped.
      0x00, 0x00, 0x01, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0xc0, 0x12, 0x00, 0x01, 0x00, 0x01,
      0x06, ...ascii("victim"), 0x07, ...ascii("example"), 0x00,
    ]],
  ])("%s is keyed on its exact bytes", async (_label, build) => {
    const key = await keyOf(new Uint8Array(build()));
    expect(key).not.toBe(await keyOf(new Uint8Array(base())));
    expect(key).toContain("/wire/");
  });

  it("an OPT record and the AD bit still share the plain key", async () => {
    const plain = await keyOf(buildDnsQuery("victim.example", 1));
    expect(await keyOf(buildDnsQueryWithDo("victim.example", 1, 0x1234))).toBe(plain);
    const ad = buildDnsQuery("victim.example", 1);
    ad[3] |= 0x20;
    expect(await keyOf(ad)).toBe(plain);
  });
});

describe("a look-alike wire query cannot poison the real name", () => {
  const post = (body) => new Request("https://w.example.com/dns-query", {
    method: "POST", headers: { "Content-Type": "application/dns-message" }, body,
  });

  it("an answer for faceboo\\u212A.com is never served for facebook.com", async () => {
    const real = buildDnsQuery("facebook.com", 1);
    const realQuestion = Array.from(real.subarray(12));
    // Answers the real name; anything else is a genuine NXDOMAIN (NSCOUNT=1),
    // which is cacheable and not classified as a block.
    globalThis.fetch = vi.fn(async (_u, init) => {
      const body = new Uint8Array(init.body);
      const isReal = realQuestion.every((b, i) => body[12 + i] === b);
      const msg = isReal
        ? buildDnsResponse("facebook.com", "1.2.3.4", 300)
        : buildDnsResponse("x.example", "1.2.3.4", 300, 3, 1);
      return new Response(msg, { headers: { "Content-Type": "application/dns-message" } });
    });
    const cache = makeFakeCache();
    const env = { UPSTREAM_SERVERS: ONE };

    const kelvin = queryFor([[...ascii("faceboo"), 0xe2, 0x84, 0xaa], ascii("com")]);
    await dispatch(post(kelvin), { cache, env });
    const { response } = await dispatch(post(real), { cache, env });

    const body = new Uint8Array(await response.arrayBuffer());
    expect(body[3] & 0x0f).toBe(0);              // NOERROR, not the look-alike's NXDOMAIN
    expect((body[6] << 8) | body[7]).toBe(1);    // one answer
  });
});
