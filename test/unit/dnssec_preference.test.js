// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/unit/dnssec_preference.test.js
// Unit tests for DNSSEC data detection and DNSSEC preference functions

import { describe, it, expect } from "vitest";
import {
  hasDnssecData,
  hasDnssecDataJson,
  buildDnsQuery,
  buildDnsResponse,
  buildDnsQueryWithDo,
  DNS_TYPE_TO_NUMBER,
} from "../../src/dns.js";

// ---------------------------------------------------------------------------
// Helper: build a wire response with AD bit set
// ---------------------------------------------------------------------------
function buildResponseWithAD(name, ip, ttl = 300) {
  const resp = buildDnsResponse(name, ip, ttl);
  // Set AD bit: byte 3, bit 5 (0x20)
  resp[3] |= 0x20;
  return resp;
}

// Helper: build a wire response with an RRSIG record in the answer
function buildResponseWithRRSIG(name) {
  // Build a minimal response then manually append an RRSIG RR
  const base = buildDnsResponse(name, "1.2.3.4", 300);
  // We'll add a minimal RRSIG (type 46) after the existing A record
  // RRSIG RDATA: type-covered(2) + algorithm(1) + labels(1) + origTTL(4) +
  //              sigExpiration(4) + sigInception(4) + keyTag(2) + signer(1 root label) + sig(1 byte)
  const rrsigRdata = new Uint8Array(20);
  rrsigRdata[0] = 0; rrsigRdata[1] = 1; // type covered = A
  rrsigRdata[2] = 8; // algorithm = RSA/SHA-256
  rrsigRdata[3] = 2; // labels
  // rest is zeros for test purposes

  // Build RRSIG RR: name pointer (2) + type(2) + class(2) + ttl(4) + rdlength(2) + rdata
  const rrsigRR = new Uint8Array(12 + rrsigRdata.length);
  rrsigRR[0] = 0xc0; rrsigRR[1] = 0x0c; // pointer to question name
  rrsigRR[2] = 0x00; rrsigRR[3] = 0x2e; // TYPE RRSIG (46)
  rrsigRR[4] = 0x00; rrsigRR[5] = 0x01; // CLASS IN
  rrsigRR[6] = 0x00; rrsigRR[7] = 0x00;
  rrsigRR[8] = 0x01; rrsigRR[9] = 0x2c; // TTL 300
  rrsigRR[10] = (rrsigRdata.length >> 8) & 0xff;
  rrsigRR[11] = rrsigRdata.length & 0xff;
  rrsigRR.set(rrsigRdata, 12);

  const out = new Uint8Array(base.length + rrsigRR.length);
  out.set(base);
  out.set(rrsigRR, base.length);
  // Increment ANCOUNT
  const ancount = (out[6] << 8) | out[7];
  const newAn = ancount + 1;
  out[6] = (newAn >> 8) & 0xff;
  out[7] = newAn & 0xff;
  return out;
}

// ---------------------------------------------------------------------------
// hasDnssecData (wire)
// ---------------------------------------------------------------------------

describe("hasDnssecData", () => {
  it("returns false for null/short buffer", () => {
    expect(hasDnssecData(null)).toBe(false);
    expect(hasDnssecData(new Uint8Array(4))).toBe(false);
  });

  it("returns false for a plain A response without AD or RRSIG", () => {
    const resp = buildDnsResponse("example.com", "1.2.3.4", 300);
    expect(hasDnssecData(resp)).toBe(false);
  });

  it("returns true when AD bit is set", () => {
    const resp = buildResponseWithAD("example.com", "1.2.3.4");
    expect(hasDnssecData(resp)).toBe(true);
  });

  it("returns true when RRSIG records are present", () => {
    const resp = buildResponseWithRRSIG("example.com");
    expect(hasDnssecData(resp)).toBe(true);
  });

  it("returns false for NXDOMAIN without DNSSEC", () => {
    const resp = buildDnsResponse("example.com", "0.0.0.0", 300, 3);
    expect(hasDnssecData(resp)).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// hasDnssecDataJson
// ---------------------------------------------------------------------------

describe("hasDnssecDataJson", () => {
  it("returns false for null", () => {
    expect(hasDnssecDataJson(null)).toBe(false);
  });

  it("returns false for plain JSON response", () => {
    expect(hasDnssecDataJson({
      Status: 0,
      AD: false,
      Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "1.2.3.4" }],
    })).toBe(false);
  });

  it("returns true when AD is true", () => {
    expect(hasDnssecDataJson({
      Status: 0,
      AD: true,
      Answer: [{ name: "example.com.", type: 1, TTL: 300, data: "1.2.3.4" }],
    })).toBe(true);
  });

  it("returns true when RRSIG (type 46) present in Answer", () => {
    expect(hasDnssecDataJson({
      Status: 0,
      AD: false,
      Answer: [
        { name: "example.com.", type: 1, TTL: 300, data: "1.2.3.4" },
        { name: "example.com.", type: 46, TTL: 300, data: "..." },
      ],
    })).toBe(true);
  });

  it("returns true when RRSIG present in Authority", () => {
    expect(hasDnssecDataJson({
      Status: 0,
      AD: false,
      Authority: [{ name: "example.com.", type: 46, TTL: 300, data: "..." }],
    })).toBe(true);
  });

  it("returns false when no Answer or Authority", () => {
    expect(hasDnssecDataJson({ Status: 0, AD: false })).toBe(false);
  });
});
