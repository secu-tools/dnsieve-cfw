// SPDX-License-Identifier: MIT
// dnsieve-cfw: Cloudflare Worker DNS-over-HTTPS (DoH) Multi-Upstream Proxy
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
// Repository: https://github.com/secu-tools/dnsieve-cfw
//
// Entry point for the Cloudflare Worker. All logic is in src/handler.js.

import { handleRequest } from "./handler.js";

export default {
  async fetch(request, env, ctx) {
    try {
      return await handleRequest(request, env, ctx);
    } catch (err) {
      if (typeof console !== "undefined") {
        const detail = (err instanceof Error) ? (err.message || "unknown") : (err != null ? String(err) : "unknown");
        console.error(`[DoH] Internal error: ${detail}`);
      }
      return new Response(
        JSON.stringify({ error: "Internal worker error" }),
        { status: 500, headers: { "Content-Type": "application/json", "Cache-Control": "no-store", "Access-Control-Allow-Origin": "*" } }
      );
    }
  },
};
