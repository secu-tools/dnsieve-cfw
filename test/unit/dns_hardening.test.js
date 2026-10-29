// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// Malformed DNS messages reach this codec from both untrusted clients and
// upstream resolvers. They must never be rebuilt into a message whose section
// counts disagree with its contents, and never throw out of a rebuild path.

import { describe, it, expect } from "vitest";
import {
  stripDnssecFromWire, processEdnsOutgoing, processEdnsIncoming, buildBlockedResponse,
  buildServfailResponse, wireToJson, parseRdata, buildDnsQuery, buildDnsResponse,
  hasDoBit, hasNsidRequest,
} from "../../src/dns.js";

const STRIP_CFG = {
  PRIVACY_ECS_MODE: "strip", PRIVACY_COOKIES_MODE: "strip", PRIVACY_NSID_MODE: "strip",
};

// True when `needle` occurs as a contiguous run inside `hay`.
function hasBytes(hay, needle) {
  outer: for (let i = 0; i + needle.length <= hay.length; i++) {
    for (let j = 0; j < needle.length; j++) if (hay[i + j] !== needle[j]) continue outer;
    return true;
  }
  return false;
}

// OPT RR header (root name, TYPE=41, CLASS=4096, TTL with the given DO byte)
// followed by RDATA.
const optRecord = (rdata, doByte = 0x00) =>
  [0x00, 0x00, 0x29, 0x10, 0x00, 0x00, 0x00, doByte, 0x00, rdata.length >> 8, rdata.length & 0xff, ...rdata];

describe("stripDnssecFromWire never emits a corrupted message", () => {
  it("returns the input untouched when a record is truncated mid-header", () => {
    // ANCOUNT=2; the second answer stops 5 bytes into its 10-byte fixed header.
    // Continuing would splice bytes out of the middle of that record and leave
    // ARCOUNT claiming an additional record that no longer exists.
    const buf = new Uint8Array([
      0x00,0x00,0x81,0x80, 0x00,0x01, 0x00,0x02, 0x00,0x01, 0x00,0x01,
      0x01,0x61,0x00, 0x00,0x01, 0x00,0x01,
      0xc0,0x0c, 0x00,0x01, 0x00,0x01, 0x00,0x00,0x00,0x3c, 0x00,0x04, 0x01,0x02,0x03,0x04,
      0xc0,0x0c, 0x00,0x2e, 0x00,0x01, 0x00,
    ]);
    const out = stripDnssecFromWire(buf, 1);
    expect(out.length).toBe(buf.length);
    expect(Array.from(out)).toEqual(Array.from(buf));
  });

  it("returns the input untouched when a record's rdlength runs past the end", () => {
    const buf = new Uint8Array([
      0x00,0x00,0x81,0x80, 0x00,0x01, 0x00,0x01, 0x00,0x00, 0x00,0x00,
      0x01,0x61,0x00, 0x00,0x01, 0x00,0x01,
      0xc0,0x0c, 0x00,0x2e, 0x00,0x01, 0x00,0x00,0x00,0x3c, 0xff,0xff, 0x01,
    ]);
    expect(Array.from(stripDnssecFromWire(buf, 1))).toEqual(Array.from(buf));
  });
});

describe("malformed OPT records do not throw out of a rebuild path", () => {
  it("an OPT whose RDLENGTH runs past the buffer is handled without throwing", () => {
    // This once produced RangeError, failing every upstream and returning
    // SERVFAIL for the query.
    const buf = new Uint8Array([
      0x00,0x00,0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x01,
      0x01,0x61,0x00, 0x00,0x01, 0x00,0x01,
      0x00, 0x00,0x29, 0x10,0x00, 0x00,0x00,0x00,0x00, 0xff,0xff,
    ]);
    expect(() => processEdnsOutgoing(buf, STRIP_CFG, null)).not.toThrow();
  });

  it("an option LENGTH beyond the OPT record does not swallow following records", () => {
    // The EDE option declares 0x00c8 bytes but only 4 exist; slicing to the
    // buffer end would copy the following A record into the option's data.
    const buf = new Uint8Array([
      0x00,0x00,0x81,0x80, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x02,
      0x01,0x61,0x00, 0x00,0x01, 0x00,0x01,
      0x00, 0x00,0x29, 0x10,0x00, 0x00,0x00,0x00,0x00, 0x00,0x08,
      0x00,0x0f, 0x00,0xc8, 0xaa,0xbb,0xcc,0xdd,
      0xc0,0x0c, 0x00,0x01, 0x00,0x01, 0x00,0x00,0x00,0x3c, 0x00,0x04, 0x09,0x09,0x09,0x09,
    ]);
    const out = processEdnsOutgoing(buf, STRIP_CFG, null);
    // The A record's rdata must appear exactly once -- never also copied into
    // the option's data, which is where it used to be echoed.
    const hex = Array.from(out).map(b => b.toString(16).padStart(2, "0")).join("");
    expect(hex.split("09090909").length - 1).toBe(1);
  });
});

describe("EDNS sanitising fails closed on malformed input", () => {
  it("an upstream OPT with an overrunning option is still rebuilt, dropping its NSID", () => {
    // NSID "up-1", then an option declaring 50 bytes where 2 remain. Treating
    // the whole OPT as unparseable once passed it to clients untouched.
    const nsid = [0x75, 0x70, 0x2d, 0x31];
    const msg = new Uint8Array([
      ...buildDnsResponse("a.example", "1.2.3.4"),
      ...optRecord([0x00, 0x03, 0x00, 0x04, ...nsid, 0x00, 0x63, 0x00, 0x32, 0x01, 0x02], 0x80),
    ]);
    msg[11] = 1;
    const out = processEdnsIncoming(msg, STRIP_CFG, null);
    expect(hasBytes(out, nsid)).toBe(false);
    expect(hasNsidRequest(out)).toBe(false);
    expect(hasDoBit(out)).toBe(true);
  });

  it("an OPT placed in the Answer section is removed and ANCOUNT corrected", () => {
    const q = buildDnsQuery("a.example", 1);
    const msg = new Uint8Array([...q, ...optRecord([])]);
    msg[7] = 1; // ANCOUNT=1: the OPT sits in the answer section
    const out = processEdnsOutgoing(msg, STRIP_CFG, null);
    expect((out[6] << 8) | out[7]).toBe(0);
    expect((out[10] << 8) | out[11]).toBe(1); // only the proxy's own OPT
    expect(out.length).toBe(q.length + 11);
  });

  it("a question that cannot be walked forwards the header alone", () => {
    // QDCOUNT=20 over one question: the walk runs off the end, and the raw
    // bytes -- with the client's ECS option -- were once forwarded as-is.
    const ecs = [0x00, 0x08, 0x00, 0x07, 0x00, 0x01, 0x18, 0x00, 0xc6, 0x33, 0x64];
    const msg = new Uint8Array([...buildDnsQuery("a.example", 1), ...optRecord(ecs)]);
    msg[5] = 20; msg[11] = 1;
    const out = processEdnsOutgoing(msg, STRIP_CFG, null);
    expect(hasBytes(out, ecs)).toBe(false);
    expect(Array.from(out.subarray(4, 10))).toEqual([0, 0, 0, 0, 0, 0]);
    expect(out.length).toBe(12 + 11); // header + the proxy's own OPT
  });
});

describe("synthesised blocked responses stay self-consistent", () => {
  it("emits no question and no answer when the query's question is truncated", () => {
    // A 0xc00c owner-name pointer needs a question to point at; without one it
    // would point into the answer record itself.
    const q = new Uint8Array([0,0,1,0, 0,1, 0,0, 0,0, 0,0, 3,0x77,0x77]);
    const r = buildBlockedResponse(q, "null", { edeText: "Blocked" });
    expect((r[4] << 8) | r[5]).toBe(0); // QDCOUNT
    expect((r[6] << 8) | r[7]).toBe(0); // ANCOUNT
    expect(wireToJson(r)).not.toBe(null);
  });

  it("SERVFAIL drops a question that runs past the query instead of copying it short", () => {
    const q = buildDnsQuery("a.example", 1);
    q[5] = 3; // QDCOUNT=3 over a single question
    const r = buildServfailResponse(q);
    expect(r.length).toBe(12);
    expect((r[4] << 8) | r[5]).toBe(0); // QDCOUNT
    expect(r[3] & 0x0f).toBe(2);        // still SERVFAIL
  });

  it("still answers 0.0.0.0 for a well-formed query", () => {
    const r = buildBlockedResponse(buildDnsQuery("blocked.example.com", 1, 0x1234), "null", { edeText: "Blocked" });
    const json = wireToJson(r);
    expect(json.Answer[0].data).toBe("0.0.0.0");
    expect(json.Question[0].name).toBe("blocked.example.com.");
  });
});

describe("parsers do not read past the buffer", () => {
  it("wireToJson does not fabricate questions from an inflated QDCOUNT", () => {
    // A 12-byte reply claiming 65535 questions once produced a ~1.4 MB body.
    const buf = new Uint8Array([0,0,0x81,0x80, 0xff,0xff, 0,0, 0,0, 0,0]);
    const json = wireToJson(buf);
    const questions = json && Array.isArray(json.Question) ? json.Question.length : 0;
    expect(questions).toBeLessThanOrEqual(1);
  });

  it("the rdata hex fallback stops at the end of the buffer", () => {
    expect(parseRdata(new Uint8Array([0xaa, 0xbb]), 0, 999, 8)).toBe("aabb");
  });
});
