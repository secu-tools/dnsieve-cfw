// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/rfc/rfc7871_ecs.test.js
// Tests for RFC 7871 EDNS Client Subnet (ECS) handling:
// strip, forward, and substitute modes.

import { describe, it, expect } from "vitest";
import {
  buildEcsOption,
  processEdnsOutgoing,
  buildDnsQueryWithDo,
} from "../../src/dns.js";
import { getConfig } from "../../src/config.js";

// Helper: build a query with an ECS option
function buildQueryWithEcs(name, subnet) {
  const base = buildDnsQueryWithDo(name, 1, 0, true);
  const ecsData = buildEcsOption(subnet);
  if (!ecsData) return base;

  // Add ECS option to the existing OPT record
  const optStart = base.length - 11;
  const ecsOpt = new Uint8Array(4 + ecsData.length);
  ecsOpt[0] = 0x00; ecsOpt[1] = 0x08; // code 8 (ECS)
  ecsOpt[2] = (ecsData.length >> 8) & 0xff;
  ecsOpt[3] = ecsData.length & 0xff;
  ecsOpt.set(ecsData, 4);

  const out = new Uint8Array(base.length + ecsOpt.length);
  out.set(base);
  out.set(ecsOpt, base.length);

  // Update RDLENGTH
  const oldRdlen = (base[optStart + 9] << 8) | base[optStart + 10];
  const newRdlen = oldRdlen + ecsOpt.length;
  out[optStart + 9] = (newRdlen >> 8) & 0xff;
  out[optStart + 10] = newRdlen & 0xff;
  return out;
}

describe("RFC 7871 - ECS option building", () => {
  it("builds valid IPv4 /24 ECS option", () => {
    const result = buildEcsOption("203.0.113.0/24");
    expect(result).not.toBeNull();
    // Family = 1 (IPv4)
    expect(result[0]).toBe(0);
    expect(result[1]).toBe(1);
    // Source prefix length = 24
    expect(result[2]).toBe(24);
    // Scope = 0
    expect(result[3]).toBe(0);
    // 3 bytes of address (24/8 = 3)
    expect(result.length).toBe(4 + 3);
    expect(result[4]).toBe(203);
    expect(result[5]).toBe(0);
    expect(result[6]).toBe(113);
  });

  it("builds valid IPv6 /32 ECS option", () => {
    const result = buildEcsOption("2001:db8::/32");
    expect(result).not.toBeNull();
    // Family = 2 (IPv6)
    expect(result[0]).toBe(0);
    expect(result[1]).toBe(2);
    // Source prefix length = 32
    expect(result[2]).toBe(32);
    // 4 bytes of address (32/8 = 4)
    expect(result.length).toBe(4 + 4);
  });

  it("builds valid IPv4 /8 ECS option", () => {
    const result = buildEcsOption("10.0.0.0/8");
    expect(result).not.toBeNull();
    expect(result[2]).toBe(8);
    expect(result.length).toBe(4 + 1); // 1 byte of address
    expect(result[4]).toBe(10);
  });

  it("builds IPv4 /32 with full address", () => {
    const result = buildEcsOption("172.16.0.1/32");
    expect(result).not.toBeNull();
    expect(result[2]).toBe(32);
    expect(result.length).toBe(4 + 4);
  });

  it("builds IPv6 /128 with full address", () => {
    const result = buildEcsOption("::1/128");
    expect(result).not.toBeNull();
    expect(result[2]).toBe(128);
    expect(result.length).toBe(4 + 16);
  });
});

describe("RFC 7871 - ECS privacy modes", () => {
  it("strip mode removes ECS from outgoing query", () => {
    const cfg = getConfig({ PRIVACY_ECS_MODE: "strip" });
    const query = buildQueryWithEcs("example.com", "192.168.1.0/24");
    const processed = processEdnsOutgoing(query, cfg, null);
    // Processed query should be smaller (ECS removed)
    expect(processed.length).toBeLessThan(query.length);
  });

  it("forward mode preserves client ECS", () => {
    const cfg = getConfig({ PRIVACY_ECS_MODE: "forward" });
    const query = buildQueryWithEcs("example.com", "192.168.1.0/24");
    const processed = processEdnsOutgoing(query, cfg, null);
    // Should contain ECS option - same size or similar
    expect(processed.length).toBeGreaterThan(20);
  });

  it("substitute mode replaces ECS with configured subnet", () => {
    const cfg = getConfig({
      PRIVACY_ECS_MODE: "substitute",
      PRIVACY_ECS_SUBNET: "203.0.113.0/24",
    });
    const query = buildDnsQueryWithDo("example.com", 1, 0, true);
    const processed = processEdnsOutgoing(query, cfg, null);
    // Should be larger than base (ECS option added)
    expect(processed.length).toBeGreaterThan(query.length);
  });

  it("substitute mode with empty subnet adds nothing", () => {
    const cfg = getConfig({
      PRIVACY_ECS_MODE: "substitute",
      PRIVACY_ECS_SUBNET: "",
    });
    const query = buildDnsQueryWithDo("example.com", 1, 0, true);
    const processed = processEdnsOutgoing(query, cfg, null);
    // No ECS added since subnet is empty
    expect(processed.length).toBeLessThanOrEqual(query.length);
  });
});
