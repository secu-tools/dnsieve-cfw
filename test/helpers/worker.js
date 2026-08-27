// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// Shared scaffolding for tests that drive handleRequest.

import { handleRequest } from "../../src/handler.js";

// Stand-in for caches.default.
//
// match() clones, matching the real Cache API where each hit yields a fresh
// readable body. A fake that returns the same Response twice lets a test pass
// on a body that production would have already consumed.
export function makeFakeCache() {
  const store = new Map();
  return {
    store,
    async match(req) {
      const key = typeof req === "string" ? req : req.url;
      const hit = store.get(key);
      return hit ? hit.clone() : null;
    },
    async put(req, resp) {
      const key = typeof req === "string" ? req : req.url;
      store.set(key, resp.clone());
    },
  };
}

// Dispatches a request with a fake cache and ctx.
//
// Options rather than positional arguments: the per-file copies this replaces
// had disagreed on whether env or cache came second.
// Set awaitBackground false to inspect waitUntil work before it settles.
export async function dispatch(request, { cache, env = {}, awaitBackground = true } = {}) {
  // Tests observe behaviour through the X- diagnostic headers, which production
  // omits to save bytes on metered links, so DEBUG defaults on here. A test can
  // still set DEBUG explicitly; test/unit/response_size.test.js covers what a
  // real client receives with it off.
  const theEnv = { DEBUG: "true", ...env };
  const theCache = cache || makeFakeCache();
  const waitUntilTasks = [];
  const ctx = { waitUntil: (p) => waitUntilTasks.push(p) };

  const originalCaches = globalThis.caches;
  globalThis.caches = { default: theCache };
  try {
    const response = await handleRequest(request, theEnv, ctx);
    if (awaitBackground) await Promise.allSettled(waitUntilTasks);
    return { response, cache: theCache, waitUntilTasks };
  } finally {
    globalThis.caches = originalCaches;
  }
}
