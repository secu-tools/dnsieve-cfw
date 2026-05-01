// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/unit/config.test.js
// Unit tests for configuration constants (src/config.js)

import { describe, it, expect } from "vitest";
import {
  GENERAL_PROFILE_ID,
  MIN_WAIT_MS,
  UPSTREAM_TIMEOUT_MS,
  MIN_CACHE_TTL_FLOOR,
  WORKER_CACHE_TTL_SECONDS,
  WORKER_BLOCKED_CACHE_TTL_SECONDS,
  CLIENT_CACHE_TTL_SECONDS,
  CLIENT_BLOCKED_CACHE_TTL_SECONDS,
  UPSTREAM_SERVERS,
  UPSTREAM_COUNT,
  MAX_DNS_MESSAGE_SIZE,
  PRIVACY_ECS_MODE,
  PRIVACY_ECS_SUBNET,
  PRIVACY_COOKIES_MODE,
  PRIVACY_NSID_MODE,
  PRIVACY_NSID_VALUE,
  BLOCKING_MODE,
  CACHE_RENEW_PERCENT,
  getConfig,
} from "../../src/config.js";

describe("Configuration constants", () => {
  it("GENERAL_PROFILE_ID is a 6-hex-char string", () => {
    expect(GENERAL_PROFILE_ID).toMatch(/^[0-9a-f]{6}$/);
  });

  it("MIN_WAIT_MS is a positive number", () => {
    expect(MIN_WAIT_MS).toBeGreaterThan(0);
  });

  it("UPSTREAM_TIMEOUT_MS is greater than MIN_WAIT_MS", () => {
    expect(UPSTREAM_TIMEOUT_MS).toBeGreaterThan(MIN_WAIT_MS);
  });

  it("MIN_CACHE_TTL_FLOOR is at least 1", () => {
    expect(MIN_CACHE_TTL_FLOOR).toBeGreaterThanOrEqual(1);
  });

  it("blocked cache TTLs are longer than normal TTLs", () => {
    expect(WORKER_BLOCKED_CACHE_TTL_SECONDS).toBeGreaterThan(WORKER_CACHE_TTL_SECONDS);
    expect(CLIENT_BLOCKED_CACHE_TTL_SECONDS).toBeGreaterThan(CLIENT_CACHE_TTL_SECONDS);
  });

  it("UPSTREAM_SERVERS is a non-empty array", () => {
    expect(Array.isArray(UPSTREAM_SERVERS)).toBe(true);
    expect(UPSTREAM_SERVERS.length).toBeGreaterThan(0);
  });

  it("UPSTREAM_COUNT matches UPSTREAM_SERVERS length", () => {
    expect(UPSTREAM_COUNT).toBe(UPSTREAM_SERVERS.length);
  });

  it("all upstream URLs are valid HTTPS URLs", () => {
    for (const tmpl of UPSTREAM_SERVERS) {
      const resolved = tmpl.replace("{PROFILE_ID}", "aabbcc");
      expect(() => new URL(resolved)).not.toThrow();
      expect(new URL(resolved).protocol).toBe("https:");
    }
  });

  it("MAX_DNS_MESSAGE_SIZE is 65535", () => {
    expect(MAX_DNS_MESSAGE_SIZE).toBe(65535);
  });

  it("UPSTREAM_SERVERS strings contain valid HTTPS URLs (profile placeholder is optional)", () => {
    // {PROFILE_ID} is an optional placeholder supported by buildUpstreamUrl().
    // Default upstream entries do not use it; profile-based resolvers (e.g. NextDNS)
    // can add it. We only assert that every URL is a valid HTTPS string.
    for (const tmpl of UPSTREAM_SERVERS) {
      expect(tmpl).toMatch(/^https:\/\//i);
    }
  });

  it("TTLs conform to reasonable real-world bounds", () => {
    // Arbitrary sanity checks for bounds
    expect(WORKER_CACHE_TTL_SECONDS).toBeLessThanOrEqual(86400 * 30); 
    expect(CLIENT_CACHE_TTL_SECONDS).toBeLessThanOrEqual(86400 * 30);
  });
});

// ---------------------------------------------------------------------------
// Privacy mode constants
// ---------------------------------------------------------------------------

describe("Privacy mode constants", () => {
  it("PRIVACY_ECS_MODE defaults to 'strip'", () => {
    expect(PRIVACY_ECS_MODE).toBe("strip");
  });

  it("PRIVACY_ECS_SUBNET defaults to empty string", () => {
    expect(PRIVACY_ECS_SUBNET).toBe("");
  });

  it("PRIVACY_COOKIES_MODE defaults to 'reoriginate'", () => {
    expect(PRIVACY_COOKIES_MODE).toBe("reoriginate");
  });

  it("PRIVACY_NSID_MODE defaults to 'strip'", () => {
    expect(PRIVACY_NSID_MODE).toBe("strip");
  });

  it("PRIVACY_NSID_VALUE defaults to empty string", () => {
    expect(PRIVACY_NSID_VALUE).toBe("");
  });
});

// ---------------------------------------------------------------------------
// getConfig - privacy bindings
// ---------------------------------------------------------------------------

describe("getConfig - privacy env bindings", () => {
  it("uses module defaults when no env bindings are provided", () => {
    const cfg = getConfig({});
    expect(cfg.PRIVACY_ECS_MODE).toBe("strip");
    expect(cfg.PRIVACY_ECS_SUBNET).toBe("");
    expect(cfg.PRIVACY_COOKIES_MODE).toBe("reoriginate");
    expect(cfg.PRIVACY_NSID_MODE).toBe("strip");
    expect(cfg.PRIVACY_NSID_VALUE).toBe("");
  });

  it("respects PRIVACY_ECS_MODE override from env", () => {
    const cfg = getConfig({ PRIVACY_ECS_MODE: "forward" });
    expect(cfg.PRIVACY_ECS_MODE).toBe("forward");
  });

  it("respects PRIVACY_ECS_SUBNET override from env", () => {
    const cfg = getConfig({ PRIVACY_ECS_SUBNET: "198.51.100.0/24" });
    expect(cfg.PRIVACY_ECS_SUBNET).toBe("198.51.100.0/24");
  });

  it("respects PRIVACY_COOKIES_MODE override from env", () => {
    const cfg = getConfig({ PRIVACY_COOKIES_MODE: "reoriginate" });
    expect(cfg.PRIVACY_COOKIES_MODE).toBe("reoriginate");
  });

  it("respects PRIVACY_NSID_MODE override from env", () => {
    const cfg = getConfig({ PRIVACY_NSID_MODE: "substitute" });
    expect(cfg.PRIVACY_NSID_MODE).toBe("substitute");
  });

  it("respects PRIVACY_NSID_VALUE override from env", () => {
    const cfg = getConfig({ PRIVACY_NSID_VALUE: "dnsieve-cfw-01" });
    expect(cfg.PRIVACY_NSID_VALUE).toBe("dnsieve-cfw-01");
  });

  it("all five privacy fields are present in the returned config object", () => {
    const cfg = getConfig({});
    expect(Object.prototype.hasOwnProperty.call(cfg, "PRIVACY_ECS_MODE")).toBe(true);
    expect(Object.prototype.hasOwnProperty.call(cfg, "PRIVACY_ECS_SUBNET")).toBe(true);
    expect(Object.prototype.hasOwnProperty.call(cfg, "PRIVACY_COOKIES_MODE")).toBe(true);
    expect(Object.prototype.hasOwnProperty.call(cfg, "PRIVACY_NSID_MODE")).toBe(true);
    expect(Object.prototype.hasOwnProperty.call(cfg, "PRIVACY_NSID_VALUE")).toBe(true);
  });
});

// ---------------------------------------------------------------------------
// Blocking mode constants
// ---------------------------------------------------------------------------

describe("Blocking mode constants", () => {
  it("BLOCKING_MODE defaults to 'null'", () => {
    expect(BLOCKING_MODE).toBe("null");
  });
});

// ---------------------------------------------------------------------------
// getConfig - blocking env bindings
// ---------------------------------------------------------------------------

describe("getConfig - blocking env bindings", () => {
  it("uses module defaults for blocking when no env bindings", () => {
    const cfg = getConfig({});
    expect(cfg.BLOCKING_MODE).toBe("null");
  });

  it("respects BLOCKING_MODE override from env", () => {
    const cfg = getConfig({ BLOCKING_MODE: "nxdomain" });
    expect(cfg.BLOCKING_MODE).toBe("nxdomain");
  });

  it("BLOCKING_MODE field is present in config", () => {
    const cfg = getConfig({});
    expect(Object.prototype.hasOwnProperty.call(cfg, "BLOCKING_MODE")).toBe(true);
  });

  it("BLOCKING_EDE_TEXT is not a config field (behaviour is hardcoded)", () => {
    const cfg = getConfig({});
    expect(Object.prototype.hasOwnProperty.call(cfg, "BLOCKING_EDE_TEXT")).toBe(false);
  });

  it("DNSSEC_PREFERENCE is not a config field (behaviour is hardcoded)", () => {
    const cfg = getConfig({});
    expect(Object.prototype.hasOwnProperty.call(cfg, "DNSSEC_PREFERENCE")).toBe(false);
  });
});

// ---------------------------------------------------------------------------
// CACHE_RENEW_PERCENT constant
// ---------------------------------------------------------------------------

describe("CACHE_RENEW_PERCENT constant", () => {
  it("default is 10", () => {
    expect(CACHE_RENEW_PERCENT).toBe(10);
  });

  it("is a number between 0 and 99 (inclusive)", () => {
    expect(CACHE_RENEW_PERCENT).toBeGreaterThanOrEqual(0);
    expect(CACHE_RENEW_PERCENT).toBeLessThanOrEqual(99);
  });
});

// ---------------------------------------------------------------------------
// getConfig - CACHE_RENEW_PERCENT env binding
// ---------------------------------------------------------------------------

describe("getConfig - CACHE_RENEW_PERCENT env binding", () => {
  it("defaults to CACHE_RENEW_PERCENT when not set", () => {
    const cfg = getConfig({});
    expect(cfg.CACHE_RENEW_PERCENT).toBe(CACHE_RENEW_PERCENT);
  });

  it("respects CACHE_RENEW_PERCENT override from env", () => {
    const cfg = getConfig({ CACHE_RENEW_PERCENT: "25" });
    expect(cfg.CACHE_RENEW_PERCENT).toBe(25);
  });

  it("accepts 0 to disable background refresh", () => {
    const cfg = getConfig({ CACHE_RENEW_PERCENT: "0" });
    expect(cfg.CACHE_RENEW_PERCENT).toBe(0);
  });

  it("CACHE_RENEW_PERCENT field is present in config object", () => {
    const cfg = getConfig({});
    expect(Object.prototype.hasOwnProperty.call(cfg, "CACHE_RENEW_PERCENT")).toBe(true);
  });

  it("stores as a number even when env binding is a string", () => {
    const cfg = getConfig({ CACHE_RENEW_PERCENT: "15" });
    expect(typeof cfg.CACHE_RENEW_PERCENT).toBe("number");
    expect(cfg.CACHE_RENEW_PERCENT).toBe(15);
  });
});
