// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// The privacy modes are the project's headline guarantee. A client controls
// every byte of its query including the header counts, so the sanitiser must
// trust the bytes it can walk rather than the counts the client declares.
// Two shapes once slipped past it and carried ECS, a client-chosen DNS cookie
// and an NSID request through to the upstream despite strip mode.

import { describe, it, expect } from "vitest";
import { processEdnsOutgoing } from "../../src/dns.js";

const hex = (u8) => Array.from(u8).map(b => b.toString(16).padStart(2, "0")).join("");
const STRIP = {
  PRIVACY_ECS_MODE: "strip", PRIVACY_COOKIES_MODE: "strip", PRIVACY_NSID_MODE: "strip",
};

const QUESTION = [3,119,119,119, 7,101,120,97,109,112,108,101, 3,99,111,109, 0, 0x00,0x01, 0x00,0x01];
const ECS_OPTION    = [0x00,0x08, 0x00,0x07, 0x00,0x01, 0x18,0x00, 0xc6,0x33,0x64];
const COOKIE_OPTION = [0x00,0x0a, 0x00,0x08, 0xde,0xad,0xbe,0xef,0x01,0x02,0x03,0x04];
const NSID_OPTION   = [0x00,0x03, 0x00,0x00];
const ECS_HEX    = "0008000700011800c63364";
const COOKIE_HEX = "000a0008deadbeef01020304";

const optRecord = (opts) => [
  0x00, 0x00,0x29, 0x10,0x00, 0x00,0x00,0x80,0x00,
  (opts.length >> 8) & 0xff, opts.length & 0xff, ...opts,
];
const query = (arcount, trailing) => new Uint8Array([
  0x00,0x00, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00,
  (arcount >> 8) & 0xff, arcount & 0xff,
  ...QUESTION, ...trailing,
]);

describe("strip mode cannot be bypassed via the header counts", () => {
  const payload = [...ECS_OPTION, ...COOKIE_OPTION, ...NSID_OPTION];

  it("strips an OPT the header does not count (ARCOUNT=0)", () => {
    // The parser skipped it, then appending a clean OPT set ARCOUNT=1, so the
    // upstream read the client's OPT as the only one.
    const out = hex(processEdnsOutgoing(query(0, optRecord(payload)), STRIP, null));
    expect(out).not.toContain(ECS_HEX);
    expect(out).not.toContain(COOKIE_HEX);
  });

  it("strips a payload OPT hidden behind a decoy OPT (ARCOUNT=2)", () => {
    // Only the first OPT was rewritten; the rest were forwarded verbatim.
    const out = hex(processEdnsOutgoing(
      query(2, [...optRecord([]), ...optRecord(payload)]), STRIP, null));
    expect(out).not.toContain(ECS_HEX);
    expect(out).not.toContain(COOKIE_HEX);
  });

  it("still strips an honestly-declared OPT", () => {
    const out = hex(processEdnsOutgoing(query(1, optRecord(payload)), STRIP, null));
    expect(out).not.toContain(ECS_HEX);
    expect(out).not.toContain(COOKIE_HEX);
  });

  it("forwards exactly one OPT record", () => {
    // RFC 6891 Section 6.1.1 permits at most one.
    const out = hex(processEdnsOutgoing(query(0, optRecord(payload)), STRIP, null));
    expect(out.split("000029").length - 1).toBe(1);
  });

  it("substitute mode does not let the client's own subnet ride along", () => {
    const out = hex(processEdnsOutgoing(query(0, optRecord(ECS_OPTION)),
      { ...STRIP, PRIVACY_ECS_MODE: "substitute", PRIVACY_ECS_SUBNET: "203.0.113.0/24" }, null));
    expect(out).not.toContain(ECS_HEX);
  });

  it("preserves a counted non-OPT additional record", () => {
    // Only OPT is removed; other additional records must survive with ARCOUNT
    // adjusted to match.
    const extraA = [0xc0,0x0c, 0x00,0x01, 0x00,0x01, 0x00,0x00,0x00,0x3c, 0x00,0x04, 9,9,9,9];
    const out = processEdnsOutgoing(query(2, [...optRecord([]), ...extraA]), STRIP, null);
    expect(hex(out)).toContain("09090909");
    expect((out[10] << 8) | out[11]).toBe(2); // the kept A record plus our OPT
  });

  it("emits a usable query when the records cannot be walked", () => {
    // Truncated mid-record: nothing after the question may be forwarded.
    const truncated = query(1, [0x00, 0x00,0x29, 0x10]);
    const out = processEdnsOutgoing(truncated, STRIP, null);
    expect((out[6] << 8) | out[7]).toBe(0);  // ANCOUNT
    expect((out[10] << 8) | out[11]).toBe(1); // just our OPT
    expect(hex(out).split("000029").length - 1).toBe(1);
  });
});
