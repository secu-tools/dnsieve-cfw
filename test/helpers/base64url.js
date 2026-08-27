// SPDX-License-Identifier: MIT
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// base64url codec for tests building RFC 8484 ?dns= parameters.

// Loop rather than String.fromCharCode(...bytes): the spread form overflows the
// call stack on large buffers.
export function toBase64url(bytes) {
  let bin = "";
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return btoa(bin).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function fromBase64url(str) {
  const clean = str.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(clean + "=".repeat((4 - clean.length % 4) % 4));
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}
