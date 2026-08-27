// SPDX-License-Identifier: MIT
// dnsieve-cfw - Client-facing TTL regression tests
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// Guards the client data-usage defect: OS-level DoH clients cache on the record
// TTL in the message body and ignore Cache-Control, so a stale short TTL -- or
// TTL=0 on a blocked answer -- makes them re-query continuously.
//
// These cover the primitives; test/integration/data_usage.test.js covers the
// behaviour through the real request path.

import { describe, it, expect } from "vitest";
import {
  setTtlWire,
  setTtlJson,
  buildBlockedResponse,
  extractMinTtlWire,
  buildDnsQuery,
  buildDnsResponse,
  buildDnsQueryWithDo,
  hasDoBit,
} from "../../src/dns.js";
import { remainingClientTtl } from "../../src/cache.js";

const CFG = { MIN_CACHE_TTL_FLOOR: 60 };
const nowSec = () => Math.floor(Date.now() / 1000);

describe("setTtlWire", () => {
  it("rewrites a short record TTL to the supplied value", () => {
    const buf = buildDnsResponse("www.example.com", "93.184.216.34", 5);
    expect(extractMinTtlWire(buf)).toBe(5);
    expect(extractMinTtlWire(setTtlWire(buf, 1800))).toBe(1800);
  });

  it("does not mutate the input buffer", () => {
    const buf = buildDnsResponse("www.example.com", "93.184.216.34", 5);
    setTtlWire(buf, 1800);
    expect(extractMinTtlWire(buf)).toBe(5);
  });

  it("returns the input untouched when every TTL already matches", () => {
    // The common case, so no copy should be allocated.
    const buf = buildDnsResponse("www.example.com", "93.184.216.34", 300);
    expect(setTtlWire(buf, 300)).toBe(buf);
  });

  it("preserves everything except the TTL octets", () => {
    const buf = buildDnsResponse("www.example.com", "93.184.216.34", 5);
    const out = setTtlWire(buf, 300);
    expect(out.length).toBe(buf.length);
    const diffs = [];
    for (let i = 0; i < buf.length; i++) if (buf[i] !== out[i]) diffs.push(i);
    expect(diffs.length).toBeLessThanOrEqual(4);
  });

  it("returns short, empty or null buffers unchanged", () => {
    const tiny = new Uint8Array([1, 2, 3]);
    expect(setTtlWire(tiny, 300)).toBe(tiny);
    expect(setTtlWire(null, 300)).toBe(null);
  });

  it("clamps negative and fractional values", () => {
    const buf = buildDnsResponse("www.example.com", "93.184.216.34", 5);
    expect(extractMinTtlWire(setTtlWire(buf, -10))).toBe(0);
    expect(extractMinTtlWire(setTtlWire(buf, 60.9))).toBe(60);
  });

  it("leaves the OPT pseudo-record alone (RFC 6891 S.6.1.3)", () => {
    // OPT reuses the TTL field for rcode/version/flags; writing there would
    // clear the DO bit.
    const withOpt = buildDnsQueryWithDo("x.example.com", 1, 0, true);
    expect(hasDoBit(setTtlWire(withOpt, 1800))).toBe(true);
  });
});

describe("setTtlJson", () => {
  it("rewrites TTLs across Answer, Authority and Additional", () => {
    const json = {
      Status: 0,
      Answer: [{ name: "a.", type: 1, TTL: 5, data: "1.2.3.4" }],
      Authority: [{ name: "b.", type: 6, TTL: 9, data: "ns." }],
      Additional: [{ name: "c.", type: 1, TTL: 3, data: "5.6.7.8" }],
    };
    const out = setTtlJson(json, 600);
    expect(out.Answer[0].TTL).toBe(600);
    expect(out.Authority[0].TTL).toBe(600);
    expect(out.Additional[0].TTL).toBe(600);
  });

  it("does not mutate the input", () => {
    const json = { Answer: [{ name: "a.", type: 1, TTL: 5 }] };
    setTtlJson(json, 600);
    expect(json.Answer[0].TTL).toBe(5);
  });

  it("preserves other fields and tolerates missing sections", () => {
    const out = setTtlJson({ Status: 0, Question: [{ name: "a.", type: 1 }] }, 600);
    expect(out.Status).toBe(0);
    expect(out.Question).toEqual([{ name: "a.", type: 1 }]);
  });

  it("tolerates non-object input", () => {
    expect(setTtlJson(null, 60)).toBe(null);
    expect(setTtlJson(undefined, 60)).toBe(undefined);
  });
});

describe("remainingClientTtl", () => {
  // A record TTL counts down from now, so an entry served from cache must have
  // its age subtracted or total staleness exceeds the configured maximum.
  function headers(obj) {
    return new Headers(obj);
  }

  it("returns the full budget for a freshly built response", () => {
    expect(remainingClientTtl(headers({ "X-Client-Cache-TTL": "1800" }), CFG)).toBe(1800);
  });

  it("subtracts the age of a cached entry", () => {
    const h = headers({
      "X-Client-Cache-TTL": "1800",
      "X-Cache-Inserted-At": String(nowSec() - 500),
    });
    expect(remainingClientTtl(h, CFG)).toBe(1300);
  });

  it("floors the remainder at MIN_CACHE_TTL_FLOOR", () => {
    const h = headers({
      "X-Client-Cache-TTL": "1800",
      "X-Cache-Inserted-At": String(nowSec() - 1799),
    });
    expect(remainingClientTtl(h, CFG)).toBe(60);
  });

  it("never returns a negative value for an over-aged entry", () => {
    const h = headers({
      "X-Client-Cache-TTL": "1800",
      "X-Cache-Inserted-At": String(nowSec() - 99999),
    });
    expect(remainingClientTtl(h, CFG)).toBe(60);
  });

  it("returns null when no TTL budget is recorded", () => {
    // SERVFAIL and other synthesised replies carry no records to stamp.
    expect(remainingClientTtl(headers({}), CFG)).toBe(null);
  });

  it("ignores a clock skew that puts insertion in the future", () => {
    const h = headers({
      "X-Client-Cache-TTL": "1800",
      "X-Cache-Inserted-At": String(nowSec() + 600),
    });
    expect(remainingClientTtl(h, CFG)).toBe(1800);
  });

  // A NaN reaching setTtlWire is written to the wire as TTL=0, silently
  // reinstating the "never cache" defect, so malformed input must never yield one.
  it("survives a non-numeric MIN_CACHE_TTL_FLOOR without collapsing to 0", () => {
    const h = headers({
      "X-Client-Cache-TTL": "1800",
      "X-Cache-Inserted-At": String(nowSec() - 100),
    });
    const ttl = remainingClientTtl(h, { MIN_CACHE_TTL_FLOOR: Number("not-a-number") });
    expect(Number.isFinite(ttl)).toBe(true);
    expect(ttl).toBe(1700);
  });

  it("returns null rather than NaN for a malformed TTL budget", () => {
    expect(remainingClientTtl(headers({ "X-Client-Cache-TTL": "abc" }), CFG)).toBe(null);
    expect(remainingClientTtl(headers({ "X-Client-Cache-TTL": "-5" }), CFG)).toBe(null);
  });

  it("ignores a malformed insertion timestamp", () => {
    const h = headers({ "X-Client-Cache-TTL": "1800", "X-Cache-Inserted-At": "xyz" });
    expect(remainingClientTtl(h, CFG)).toBe(1800);
  });

  it("tolerates a missing cfg", () => {
    const h = headers({ "X-Client-Cache-TTL": "1800", "X-Cache-Inserted-At": String(nowSec() - 100) });
    expect(remainingClientTtl(h, undefined)).toBe(1700);
  });

  it("never yields a value that stamps as TTL=0 on the wire", () => {
    // Whatever remainingClientTtl returns must survive clampTtl as a usable TTL.
    const cases = [
      { MIN_CACHE_TTL_FLOOR: Number("bad") },
      { MIN_CACHE_TTL_FLOOR: undefined },
      { MIN_CACHE_TTL_FLOOR: -1 },
      {},
      undefined,
    ];
    for (const cfg of cases) {
      const h = headers({
        "X-Client-Cache-TTL": "1800",
        "X-Cache-Inserted-At": String(nowSec() - 100),
      });
      const ttl = remainingClientTtl(h, cfg);
      const stamped = setTtlWire(buildDnsResponse("a.example.com", "1.2.3.4", 300), ttl);
      expect(extractMinTtlWire(stamped)).toBeGreaterThan(0);
    }
  });

  it("total client staleness never exceeds the configured budget", () => {
    // The property the whole design rests on: budget - age, for every age.
    for (const age of [0, 1, 100, 900, 1799, 1800, 5000]) {
      const h = headers({
        "X-Client-Cache-TTL": "1800",
        "X-Cache-Inserted-At": String(nowSec() - age),
      });
      const remaining = remainingClientTtl(h, CFG);
      expect(remaining).toBeLessThanOrEqual(1800 - Math.min(age, 1740));
      expect(remaining).toBeGreaterThanOrEqual(CFG.MIN_CACHE_TTL_FLOOR);
    }
  });
});

describe("blocked wire answers are stampable", () => {
  // buildBlockedResponse synthesises TTL=0; the egress stamp supplies the value.
  it.each([
    ["A", 1],
    ["AAAA", 28],
  ])("null mode %s answer carries the stamped TTL", (_label, qtype) => {
    const query = buildDnsQuery("ads.example.com", qtype, 0x1234);
    const blocked = buildBlockedResponse(query, "null", { edeText: "Blocked" });
    expect(extractMinTtlWire(setTtlWire(blocked, 86400))).toBe(86400);
  });

  it("preserves the query transaction ID through the stamp", () => {
    const query = buildDnsQuery("ads.example.com", 1, 0x1234);
    const out = setTtlWire(buildBlockedResponse(query, "null", { edeText: "Blocked" }), 86400);
    expect(out[0]).toBe(0x12);
    expect(out[1]).toBe(0x34);
  });

  it("is a no-op for record-less blocking modes", () => {
    const query = buildDnsQuery("ads.example.com", 1, 0x1234);
    for (const mode of ["nxdomain", "nodata", "refused"]) {
      const blocked = buildBlockedResponse(query, mode, { edeText: "Blocked" });
      expect(() => setTtlWire(blocked, 86400)).not.toThrow();
    }
  });
});
