// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/rfc/rfc6672_dname.test.js
// RFC 6672 DNAME (Delegation Name) record type compliance tests

import { describe, it, expect } from "vitest";
import {
  DNS_TYPE_TO_NUMBER,
  DNS_NUMBER_TO_TYPE,
  parseRdata,
  normalizeType,
} from "../../src/dns.js";

describe("RFC 6672 - DNAME record type", () => {
  it("DNAME is type 39 in DNS_TYPE_TO_NUMBER", () => {
    expect(DNS_TYPE_TO_NUMBER.DNAME).toBe(39);
  });

  it("type 39 maps back to 'DNAME' in DNS_NUMBER_TO_TYPE", () => {
    expect(DNS_NUMBER_TO_TYPE[39]).toBe("DNAME");
  });

  it("normalizeType('DNAME') returns 'DNAME'", () => {
    expect(normalizeType("DNAME")).toBe("DNAME");
  });

  it("normalizeType('dname') returns 'DNAME'", () => {
    expect(normalizeType("dname")).toBe("DNAME");
  });

  it("normalizeType('39') returns 'DNAME'", () => {
    expect(normalizeType("39")).toBe("DNAME");
  });
});

describe("RFC 6672 - DNAME RDATA parsing", () => {
  it("parses DNAME RDATA as a domain name", () => {
    // DNAME RDATA is a single domain name (same as CNAME/NS/PTR)
    // Build RDATA for "target.example.com."
    const labels = ["target", "example", "com"];
    let size = 0;
    for (const l of labels) size += 1 + l.length;
    size += 1; // root label

    const buf = new Uint8Array(size);
    let off = 0;
    for (const label of labels) {
      buf[off++] = label.length;
      for (let i = 0; i < label.length; i++) buf[off++] = label.charCodeAt(i);
    }
    buf[off++] = 0; // root label

    const result = parseRdata(buf, 0, 39, size);
    expect(result).toBe("target.example.com.");
  });

  it("parses single-label DNAME", () => {
    // Build RDATA for "example."
    const buf = new Uint8Array(9);
    buf[0] = 7; // length of "example"
    const label = "example";
    for (let i = 0; i < label.length; i++) buf[1 + i] = label.charCodeAt(i);
    buf[8] = 0; // root

    const result = parseRdata(buf, 0, 39, 9);
    expect(result).toBe("example.");
  });
});
