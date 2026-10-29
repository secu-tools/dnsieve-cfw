// SPDX-License-Identifier: MIT
// dnsieve-cfw - Vitest / Cloudflare Workers test configuration
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
import { cloudflareTest } from "@cloudflare/vitest-plugin";
import { defineConfig } from "vitest/config";

// Use the Cloudflare Workers plugin so that tests run inside the workerd runtime,
// giving correct behaviour for Web APIs (fetch, caches, crypto, URL, etc.)
export default defineConfig({
  plugins: [
    cloudflareTest({
      wrangler: { configPath: "./wrangler.toml" },
    }),
  ],
  test: {
    // All test files under test/
    include: ["test/**/*.test.js"],
    // Increase timeout for integration tests that use fake timers or multiple awaits
    testTimeout: 15000,
    coverage: {
      // V8 native coverage relies on node:inspector, which workerd does not
      // implement, so instrument the sources with Istanbul instead.
      provider: "istanbul",
      include: ["src/**/*.js"],
    },
  },
});
