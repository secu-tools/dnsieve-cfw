// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/unit/config_validation.test.js
// Tests for configuration validation edge cases: NaN values, invalid types,
// extreme ranges, and malformed environment bindings.

import { describe, it, expect } from "vitest";
import { getConfig, GENERAL_PROFILE_ID, UPSTREAM_SERVERS } from "../../src/config.js";

describe("getConfig - invalid environment bindings", () => {
  it("NaN UPSTREAM_TIMEOUT_MS falls back gracefully", () => {
    const cfg = getConfig({ UPSTREAM_TIMEOUT_MS: "not-a-number" });
    expect(Number.isNaN(cfg.UPSTREAM_TIMEOUT_MS)).toBe(true);
  });

  it("NaN MIN_WAIT_MS produces NaN (no clamping)", () => {
    const cfg = getConfig({ MIN_WAIT_MS: "abc" });
    expect(Number.isNaN(cfg.MIN_WAIT_MS)).toBe(true);
  });

  it("NaN MIN_CACHE_TTL_FLOOR produces NaN", () => {
    const cfg = getConfig({ MIN_CACHE_TTL_FLOOR: "xyz" });
    expect(Number.isNaN(cfg.MIN_CACHE_TTL_FLOOR)).toBe(true);
  });

  it("NaN MAX_DNS_MESSAGE_SIZE produces NaN", () => {
    const cfg = getConfig({ MAX_DNS_MESSAGE_SIZE: "large" });
    expect(Number.isNaN(cfg.MAX_DNS_MESSAGE_SIZE)).toBe(true);
  });

  it("negative timeout value is accepted as-is", () => {
    const cfg = getConfig({ UPSTREAM_TIMEOUT_MS: "-500" });
    expect(cfg.UPSTREAM_TIMEOUT_MS).toBe(-500);
  });

  it("zero timeout is accepted", () => {
    const cfg = getConfig({ UPSTREAM_TIMEOUT_MS: "0" });
    expect(cfg.UPSTREAM_TIMEOUT_MS).toBe(0);
  });

  it("extremely large numeric values are accepted", () => {
    const cfg = getConfig({ WORKER_CACHE_TTL_SECONDS: "999999999" });
    expect(cfg.WORKER_CACHE_TTL_SECONDS).toBe(999999999);
  });

  it("empty string numeric field becomes 0", () => {
    const cfg = getConfig({ UPSTREAM_TIMEOUT_MS: "" });
    expect(cfg.UPSTREAM_TIMEOUT_MS).toBe(0);
  });

  it("float string is accepted as float", () => {
    const cfg = getConfig({ MIN_CACHE_TTL_FLOOR: "30.5" });
    expect(cfg.MIN_CACHE_TTL_FLOOR).toBe(30.5);
  });
});

describe("getConfig - UPSTREAM_SERVERS parsing", () => {
  it("invalid JSON falls back to module defaults", () => {
    const cfg = getConfig({ UPSTREAM_SERVERS: "not json" });
    expect(cfg.UPSTREAM_SERVERS).toEqual(UPSTREAM_SERVERS);
    expect(cfg.UPSTREAM_COUNT).toBe(UPSTREAM_SERVERS.length);
  });

  it("empty JSON array produces 0 upstreams", () => {
    const cfg = getConfig({ UPSTREAM_SERVERS: "[]" });
    expect(cfg.UPSTREAM_SERVERS).toEqual([]);
    expect(cfg.UPSTREAM_COUNT).toBe(0);
  });

  it("JSON object (not array) falls back to defaults", () => {
    // Previously: a JSON object was accepted and servers.length was undefined.
    // After fix: non-array values fall back to module defaults.
    const cfg = getConfig({ UPSTREAM_SERVERS: '{"a":"b"}' });
    expect(cfg.UPSTREAM_SERVERS).toEqual(UPSTREAM_SERVERS);
    expect(cfg.UPSTREAM_COUNT).toBe(UPSTREAM_SERVERS.length);
  });

  it("single-element array", () => {
    const cfg = getConfig({ UPSTREAM_SERVERS: '["https://dns.example.com/dns-query"]' });
    expect(cfg.UPSTREAM_SERVERS).toEqual(["https://dns.example.com/dns-query"]);
    expect(cfg.UPSTREAM_COUNT).toBe(1);
  });

  it("null JSON string falls back to defaults (null is not an array)", () => {
    // Previously: JSON.parse("null") returned null and servers.length threw.
    // After fix: non-array parsed values fall back to module defaults gracefully.
    const cfg = getConfig({ UPSTREAM_SERVERS: "null" });
    expect(cfg.UPSTREAM_SERVERS).toEqual(UPSTREAM_SERVERS);
    expect(cfg.UPSTREAM_COUNT).toBe(UPSTREAM_SERVERS.length);
  });
});

describe("getConfig - boolean and string bindings", () => {
  it('DEBUG is true only when env.DEBUG === "true"', () => {
    expect(getConfig({ DEBUG: "true" }).DEBUG).toBe(true);
    expect(getConfig({ DEBUG: "false" }).DEBUG).toBe(false);
    expect(getConfig({ DEBUG: "1" }).DEBUG).toBe(false);
    expect(getConfig({ DEBUG: "yes" }).DEBUG).toBe(false);
    expect(getConfig({}).DEBUG).toBe(false);
  });

  it("PRIVACY_ECS_MODE defaults to strip", () => {
    expect(getConfig({}).PRIVACY_ECS_MODE).toBe("strip");
  });

  it("PRIVACY_COOKIES_MODE defaults to reoriginate", () => {
    expect(getConfig({}).PRIVACY_COOKIES_MODE).toBe("reoriginate");
  });

  it("PRIVACY_NSID_MODE defaults to strip", () => {
    expect(getConfig({}).PRIVACY_NSID_MODE).toBe("strip");
  });

  it("BLOCKING_MODE defaults to null", () => {
    expect(getConfig({}).BLOCKING_MODE).toBe("null");
  });

  it("overrides BLOCKING_MODE from env", () => {
    expect(getConfig({ BLOCKING_MODE: "nxdomain" }).BLOCKING_MODE).toBe("nxdomain");
  });

  it("overrides GENERAL_PROFILE_ID from env", () => {
    const cfg = getConfig({ GENERAL_PROFILE_ID: "ff00aa" });
    expect(cfg.GENERAL_PROFILE_ID).toBe("ff00aa");
  });
});

describe("getConfig - all fields have defaults when env is empty", () => {
  it("returns complete config with no env", () => {
    const cfg = getConfig();
    expect(cfg.GENERAL_PROFILE_ID).toBe(GENERAL_PROFILE_ID);
    expect(typeof cfg.MIN_WAIT_MS).toBe("number");
    expect(typeof cfg.UPSTREAM_TIMEOUT_MS).toBe("number");
    expect(typeof cfg.MIN_CACHE_TTL_FLOOR).toBe("number");
    expect(typeof cfg.WORKER_CACHE_TTL_SECONDS).toBe("number");
    expect(typeof cfg.WORKER_BLOCKED_CACHE_TTL_SECONDS).toBe("number");
    expect(typeof cfg.CLIENT_CACHE_TTL_SECONDS).toBe("number");
    expect(typeof cfg.CLIENT_BLOCKED_CACHE_TTL_SECONDS).toBe("number");
    expect(Array.isArray(cfg.UPSTREAM_SERVERS)).toBe(true);
    expect(typeof cfg.UPSTREAM_COUNT).toBe("number");
    expect(typeof cfg.MAX_DNS_MESSAGE_SIZE).toBe("number");
    expect(typeof cfg.DEBUG).toBe("boolean");
    expect(typeof cfg.PRIVACY_ECS_MODE).toBe("string");
    expect(typeof cfg.PRIVACY_ECS_SUBNET).toBe("string");
    expect(typeof cfg.PRIVACY_COOKIES_MODE).toBe("string");
    expect(typeof cfg.PRIVACY_NSID_MODE).toBe("string");
    expect(typeof cfg.PRIVACY_NSID_VALUE).toBe("string");
    expect(typeof cfg.BLOCKING_MODE).toBe("string");
  });
});
