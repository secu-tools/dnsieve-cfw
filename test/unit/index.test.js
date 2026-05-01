// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// test/unit/index.test.js
// Unit tests for worker entrypoint error handling (src/index.js)

import { describe, it, expect, vi, afterEach } from "vitest";

afterEach(() => {
  vi.resetModules();
  vi.restoreAllMocks();
  vi.doUnmock("../../src/handler.js");
});

describe("worker entrypoint", () => {
  it("returns 500 JSON response when handleRequest throws", async () => {
    vi.doMock("../../src/handler.js", () => ({
      handleRequest: vi.fn(async () => {
        throw new Error("boom");
      }),
    }));

    const worker = (await import("../../src/index.js")).default;
    const response = await worker.fetch(new Request("https://worker.example.com/dns-query"), {}, {});

    expect(response.status).toBe(500);
    expect(response.headers.get("content-type")).toContain("application/json");
    expect(response.headers.get("cache-control")).toBe("no-store");

    const body = await response.json();
    expect(body.error).toBe("Internal worker error");
    expect(body.detail).toBeUndefined(); // detail suppressed for security
  });

  it("passes through successful handleRequest response", async () => {
    vi.doMock("../../src/handler.js", () => ({
      handleRequest: vi.fn(async () => {
        return new Response("ok", {
          status: 200,
          headers: { "Content-Type": "text/plain" },
        });
      }),
    }));

    const worker = (await import("../../src/index.js")).default;
    const response = await worker.fetch(new Request("https://worker.example.com/dns-query"), {}, {});

    expect(response.status).toBe(200);
    expect(await response.text()).toBe("ok");
  });

  it("returns 500 when thrown error is not an Error object", async () => {
    vi.doMock("../../src/handler.js", () => ({
      handleRequest: vi.fn(async () => {
        throw "string error boom";
      }),
    }));

    const worker = (await import("../../src/index.js")).default;
    const response = await worker.fetch(new Request("https://worker.example.com/dns-query"), {}, {});

    expect(response.status).toBe(500);
    const body = await response.json();
    expect(body.error).toBe("Internal worker error");
    expect(body.detail).toBeUndefined(); // detail suppressed for security
  });
});