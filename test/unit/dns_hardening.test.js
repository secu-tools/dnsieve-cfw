// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// Malformed DNS messages reach this codec from both untrusted clients and
// upstream resolvers. They must never be rebuilt into a message whose section
// counts disagree with its contents, and never throw out of a rebuild path.

import { describe, it, expect } from "vitest";
import {
  stripDnssecFromWire, processEdnsOutgoing, buildBlockedResponse,
  wireToJson, parseRdata, buildDnsQuery,
} from "../../src/dns.js";

const STRIP_CFG = {
  PRIVACY_ECS_MODE: "strip", PRIVACY_COOKIES_MODE: "strip", PRIVACY_NSID_MODE: "strip",
};

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
