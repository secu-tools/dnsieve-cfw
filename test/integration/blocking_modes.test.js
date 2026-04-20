// test/integration/blocking_modes.test.js
// Integration tests for all blocking modes: null, nxdomain, nodata, refused.
// Tests both JSON and wire-format blocked responses, EDE inclusion, and
// header correctness.

import { describe, it, expect } from "vitest";
import {
  buildBlockedResponse,
  buildDnsQuery,
  wireToJson,
  inspectWireResponse,
  extractQueryNameType,
  buildEdeOption,
  injectEdeToResponse,
} from "../../src/dns.js";

describe("Blocking mode: null (A query)", () => {
  it("produces NOERROR with A=0.0.0.0", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    const resp = buildBlockedResponse(query, "null");
    const json = wireToJson(resp);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(0); // NOERROR
    expect(json.Answer).toHaveLength(1);
    expect(json.Answer[0].type).toBe(1); // A
    expect(json.Answer[0].data).toBe("0.0.0.0");
  });

  it("is detected as blocked by inspectWireResponse", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    const resp = buildBlockedResponse(query, "null");
    const { blocked } = inspectWireResponse(resp);
    expect(blocked).toBe(true);
  });
});

describe("Blocking mode: null (AAAA query)", () => {
  it("produces NOERROR with AAAA=::", () => {
    const query = buildDnsQuery("blocked.example.com", 28);
    const resp = buildBlockedResponse(query, "null");
    const json = wireToJson(resp);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(0);
    expect(json.Answer).toHaveLength(1);
    expect(json.Answer[0].type).toBe(28); // AAAA
    // All zeros = ::
    const data = json.Answer[0].data;
    expect(data).toMatch(/^0+:.*:0+$/);
  });
});

describe("Blocking mode: null (non-A/AAAA query)", () => {
  it("produces NOERROR with empty answer for MX query", () => {
    const query = buildDnsQuery("blocked.example.com", 15); // MX
    const resp = buildBlockedResponse(query, "null");
    const json = wireToJson(resp);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(0);
    expect(json.Answer).toBeUndefined();
  });
});

describe("Blocking mode: nxdomain", () => {
  it("produces NXDOMAIN (rcode=3) with empty answer", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    const resp = buildBlockedResponse(query, "nxdomain");
    const json = wireToJson(resp);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(3);
    expect(json.Answer).toBeUndefined();
  });

  it("is detected as blocked (NXDOMAIN + no authority) by inspectWireResponse", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    const resp = buildBlockedResponse(query, "nxdomain");
    const { blocked } = inspectWireResponse(resp);
    expect(blocked).toBe(true);
  });
});

describe("Blocking mode: nodata", () => {
  it("produces NOERROR with empty answer section", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    const resp = buildBlockedResponse(query, "nodata");
    const json = wireToJson(resp);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(0);
    expect(json.Answer).toBeUndefined();
  });

  it("is NOT detected as blocked by inspectWireResponse", () => {
    // NOERROR with no answer is a legitimate nodata response, not a block
    const query = buildDnsQuery("blocked.example.com", 1);
    const resp = buildBlockedResponse(query, "nodata");
    const { blocked, servfail } = inspectWireResponse(resp);
    expect(blocked).toBe(false);
    expect(servfail).toBe(false);
  });
});

describe("Blocking mode: refused", () => {
  it("produces REFUSED (rcode=5) with empty answer", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    const resp = buildBlockedResponse(query, "refused");
    const json = wireToJson(resp);
    expect(json).not.toBeNull();
    expect(json.Status).toBe(5);
    expect(json.Answer).toBeUndefined();
  });
});

describe("Blocked response with EDE", () => {
  it("EDE injection adds Blocked info to response", () => {
    const query = buildDnsQuery("blocked.example.com", 1);
    const resp = buildBlockedResponse(query, "null", {
      edeText: "Blocked (https://dns.example.com/dns-query)",
    });
    // Check ARCOUNT > 0 (EDE is in OPT record in Additional section)
    const arcount = (resp[10] << 8) | resp[11];
    expect(arcount).toBeGreaterThanOrEqual(1);
  });

  it("EDE text is retrievable from the response", () => {
    const edeText = "Blocked (https://test.upstream.com/dns-query)";
    const query = buildDnsQuery("malware.example.com", 1);
    const resp = buildBlockedResponse(query, "null", { edeText });
    // The EDE text should be embedded in the wire response
    const textBytes = new TextEncoder().encode("Blocked");
    let found = false;
    for (let i = 0; i <= resp.length - textBytes.length; i++) {
      let match = true;
      for (let j = 0; j < textBytes.length; j++) {
        if (resp[i + j] !== textBytes[j]) { match = false; break; }
      }
      if (match) { found = true; break; }
    }
    expect(found).toBe(true);
  });
});

describe("Blocked response - question section preservation", () => {
  it("preserves original question name in blocked response", () => {
    const query = buildDnsQuery("ads.tracker.example.net", 1);
    const resp = buildBlockedResponse(query, "null");
    const meta = extractQueryNameType(resp);
    expect(meta).not.toBeNull();
    expect(meta.name).toBe("ads.tracker.example.net.");
    expect(meta.qtype).toBe(1);
  });

  it("preserves AAAA question type", () => {
    const query = buildDnsQuery("blocked.com", 28);
    const resp = buildBlockedResponse(query, "null");
    const meta = extractQueryNameType(resp);
    expect(meta).not.toBeNull();
    expect(meta.qtype).toBe(28);
  });
});

describe("Malformed query handling for blocked responses", () => {
  it("returns original for null query", () => {
    const result = buildBlockedResponse(null, "null");
    expect(result).toBeNull();
  });

  it("returns original for short query", () => {
    const short = new Uint8Array(5);
    const result = buildBlockedResponse(short, "null");
    expect(result).toBe(short);
  });
});
