// SPDX-License-Identifier: MIT
// dnsieve-cfw - DNS wire format parsing and JSON conversion
// Copyright (c) 2020-2026 Jack L. (Cpt-JackL) (https://jack-l.com)
//
// Implements:
//   - RFC 1035  (DNS wire format, label encoding, compression)
//   - RFC 3596  (AAAA records)
//   - RFC 2782  (SRV records)
//   - RFC 4034  (DS, RRSIG, NSEC, DNSKEY; DNSSEC DO bit handling)
//   - RFC 4035  (DNSSEC protocol: outgoing DO=1 forcing, non-DO response stripping)
//   - RFC 5155  (NSEC3)
//   - RFC 5001  (NSID EDNS option)
//   - RFC 6891  (EDNS0 OPT record)
//   - RFC 7871  (ECS EDNS option)
//   - RFC 7873  (DNS Cookies EDNS option)
//   - RFC 8659  (CAA records)
//   - RFC 6672  (DNAME records)
//   - RFC 8914  (EDE EDNS option, pass-through and generation)
//   - RFC 9460  (SVCB / HTTPS records)

// Pre-computed hex lookup table - avoids per-byte toString calls in hot paths
export const HEX_TABLE = new Array(256);
for (let i = 0; i < 256; i++) HEX_TABLE[i] = i.toString(16).padStart(2, "0");

const TEXT_DECODER = new TextDecoder("utf-8");
const TEXT_ENCODER = new TextEncoder();

export const DNS_TYPE_TO_NUMBER = {
  A: 1, NS: 2, CNAME: 5, SOA: 6, PTR: 12, MX: 15, TXT: 16, AAAA: 28,
  SRV: 33, DNAME: 39, DS: 43, RRSIG: 46, NSEC: 47, DNSKEY: 48, NSEC3: 50,
  SVCB: 64, HTTPS: 65, OPT: 41, CAA: 257, ANY: 255,
};

export const DNS_NUMBER_TO_TYPE = Object.fromEntries(
  Object.entries(DNS_TYPE_TO_NUMBER).map(([k, v]) => [v, k])
);

// Returns the canonical upper-case DNS type string for a given name or number.
export function normalizeType(type) {
  if (!type) return "A";
  const upper = type.toUpperCase();
  if (DNS_TYPE_TO_NUMBER[upper] !== undefined) return upper;
  const num = parseInt(upper, 10);
  if (!isNaN(num) && DNS_NUMBER_TO_TYPE[num]) return DNS_NUMBER_TO_TYPE[num];
  return upper;
}

// Fast ASCII test - avoids URL constructor for pure-ASCII domains (common case)
const ASCII_RE = /^[\x00-\x7F]+$/;

// Converts a domain name to ACE / Punycode lowercase for cache key consistency.
// Implements WHATWG URL Standard SS.3.3 IDN toASCII processing.
export function toASCII(name) {
  if (ASCII_RE.test(name)) return name.toLowerCase();
  try {
    return new URL(`https://${name}`).hostname;
  } catch {
    return name.toLowerCase();
  }
}

export function stripBase64Padding(b64) {
  let end = b64.length;
  while (end > 0 && b64.charCodeAt(end - 1) === 61) end--;
  return end === b64.length ? b64 : b64.substring(0, end);
}

// Returns true for responses classified as blocked or NXDOMAIN-without-SOA.
//
// Block detection rules (per official Quad9 documentation):
//   - Status 3 (NXDOMAIN) with no Authority section -> resolver block
//   - A record with data 0.0.0.0 -> block
//   - AAAA record with data :: or ::0 -> block
export function isBlockedOrNxdomain(json) {
  if (json.Status === 3) {
    // NXDOMAIN + no Authority = block; NXDOMAIN + Authority (SOA) = genuine missing domain
    return !Array.isArray(json.Authority) || json.Authority.length === 0;
  }
  const ans = json.Answer;
  if (Array.isArray(ans)) {
    for (let i = 0; i < ans.length; i++) {
      const d = ans[i].data;
      if (d === "0.0.0.0" || d === "::" || d === "::0") return true;
    }
  }
  return false;
}

export function isServerFailure(json) {
  return json.Status === 2 || json.Status === 5;
}

/**
 * Inspect a DNS wire response for SERVFAIL and blocked status in a single pass.
 *
 * NXDOMAIN (rcode=3) disambiguation per Quad9 documentation:
 *   https://docs.quad9.net/FAQs/#identifying-a-quad9-block
 *
 *   NSCOUNT = 0 -> resolver-generated block (no SOA in authority section)
 *   NSCOUNT >= 1 -> genuine NXDOMAIN (authority section contains SOA)
 *
 * @param {Uint8Array} buf
 * @returns {{ blocked: boolean, servfail: boolean }}
 */
export function inspectWireResponse(buf) {
  if (buf.length < 4) return { blocked: false, servfail: false };
  const flags = (buf[2] << 8) | buf[3];
  const rcode = flags & 0x0f;
  if (rcode === 2) return { blocked: false, servfail: true };
  if (rcode === 5) return { blocked: false, servfail: true };
  if (rcode === 3) {
    const nscount = buf.length >= 10 ? (buf[8] << 8) | buf[9] : 0;
    return { blocked: nscount === 0, servfail: false };
  }

  try {
    const qdcount = (buf[4] << 8) | buf[5];
    const ancount = (buf[6] << 8) | buf[7];
    if (ancount === 0) return { blocked: false, servfail: false };

    let off = 12;
    for (let q = 0; q < qdcount; q++) { off = skipName(buf, off); off += 4; }

    for (let a = 0; a < ancount; a++) {
      off = skipName(buf, off);
      if (off + 10 > buf.length) break;
      const atype    = (buf[off] << 8) | buf[off + 1];
      const rdlength = (buf[off + 8] << 8) | buf[off + 9];
      off += 10;

      if (atype === 1 && rdlength === 4) {
        if (buf[off] === 0 && buf[off+1] === 0 && buf[off+2] === 0 && buf[off+3] === 0)
          return { blocked: true, servfail: false };
      } else if (atype === 28 && rdlength === 16) {
        let z = true;
        for (let i = 0; i < 16; i++) { if (buf[off + i] !== 0) { z = false; break; } }
        if (z) return { blocked: true, servfail: false };
      }
      off += rdlength;
    }
  } catch {}
  return { blocked: false, servfail: false };
}

// ---------------------------------------------------------------------------
// Base32 Extended Hex (RFC 4648 Section 7) - used for NSEC3 hash display
// ---------------------------------------------------------------------------

const BASE32HEX = "0123456789ABCDEFGHIJKLMNOPQRSTUV";

function encodeBase32Hex(bytes) {
  if (!bytes.length) return "";
  let result = "";
  let bits = 0, accum = 0;
  for (let i = 0; i < bytes.length; i++) {
    accum = (accum << 8) | bytes[i];
    bits += 8;
    while (bits >= 5) { bits -= 5; result += BASE32HEX[(accum >>> bits) & 0x1f]; }
  }
  if (bits > 0) result += BASE32HEX[(accum << (5 - bits)) & 0x1f];
  return result;
}

// Standard base64 of a byte range. The char-by-char loop is deliberate: it is
// several times faster than String.fromCharCode(...bytes) and does not risk a
// call-stack overflow on large records.
function bytesToBase64(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += String.fromCharCode(bytes[i]);
  return btoa(out);
}

// Unpadded base64url (RFC 4648 Section 5) of a byte range; the inverse of
// base64urlToBytes.
export function bytesToBase64url(bytes) {
  return stripBase64Padding(bytesToBase64(bytes)).replace(/\+/g, "-").replace(/\//g, "_");
}

// Lower-case hex of a byte range.
export function bytesToHex(bytes) {
  let out = "";
  for (let i = 0; i < bytes.length; i++) out += HEX_TABLE[bytes[i]];
  return out;
}

/**
 * Decode a base64url string into bytes (RFC 4648 Section 5), as used by the
 * ?dns= parameter of RFC 8484 GET requests.
 *
 * Throws RangeError when the decoded length would exceed maxBytes -- checked
 * before the output is allocated, so an oversized payload is rejected without
 * reserving room for it. Invalid base64 throws whatever atob throws. Callers
 * distinguish the two to answer 413 vs 400.
 *
 * @param {string} b64
 * @param {number} [maxBytes=Infinity]
 * @returns {Uint8Array}
 */
export function base64urlToBytes(b64, maxBytes = Infinity) {
  const clean = b64.replace(/-/g, "+").replace(/_/g, "/");
  const bin = atob(clean + "=".repeat((4 - clean.length % 4) % 4));
  if (bin.length > maxBytes) throw new RangeError("base64url payload too large");
  const out = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
  return out;
}

/**
 * Read the header flags a cache key must partition on: opcode, RD and CD.
 * Returns null when the buffer is too short to contain them.
 *
 * @param {Uint8Array} buf
 * @returns {{opcode: number, rd: boolean, cd: boolean}|null}
 */
export function extractHeaderFlags(buf) {
  if (!buf || buf.length < 4) return null;
  return {
    opcode: (buf[2] >> 3) & 0x0f,
    rd: !!(buf[2] & 0x01),
    cd: !!(buf[3] & 0x10),
  };
}

// Advances past a DNS name at offset off and returns the new offset.
export function skipName(buf, off) {
  while (off < buf.length) {
    const len = buf[off];
    if (len === 0) return off + 1;
    if ((len & 0xc0) === 0xc0) return off + 2;
    off += 1 + len;
  }
  return off;
}

/**
 * Extract the qname and qtype from the first question section of a DNS wire
 * message. Returns null if the buffer is too short or malformed.
 *
 * Used to build DO-independent cache keys from wire-format requests.
 *
 * @param {Uint8Array} buf
 * @returns {{ name: string, qtype: number }|null}
 */
export function extractQueryNameType(buf) {
  if (!buf || buf.length < 12) return null;
  try {
    const qdcount = (buf[4] << 8) | buf[5];
    if (qdcount === 0) return null;
    const { name, offset } = readDnsName(buf, 12);
    if (offset + 2 > buf.length) return null;
    const qtype = (buf[offset] << 8) | buf[offset + 1];
    return { name, qtype };
  } catch { return null; }
}

// Canonical text of one label for a cache key. ASCII letters are lower-cased --
// the only case folding DNS performs (RFC 4343 Section 3) -- other printable
// ASCII is kept, "." and "\" are escaped, and every remaining octet is written
// as \DDD (RFC 4343 Section 2.1). Unlike the UTF-8 decoding readDnsName uses for
// display, this is injective: two labels share a form only when a resolver
// treats them as the same label.
function keyLabel(bytes) {
  let s = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i];
    if (b >= 0x41 && b <= 0x5a) s += String.fromCharCode(b | 0x20);
    else if (b === 0x2e || b === 0x5c) s += "\\" + String.fromCharCode(b);
    else if (b > 0x20 && b < 0x7f) s += String.fromCharCode(b);
    else s += "\\" + String(b).padStart(3, "0");
  }
  return s;
}

/**
 * Identity of a wire query for the shared cache key: the canonical question
 * name (no trailing dot) and qtype.
 *
 * Returns null unless the query is a plain one that name and type fully
 * describe: QDCOUNT=1, class IN, no compression in the name, no answer or
 * authority records, nothing in the additional section but OPT (which
 * processEdnsOutgoing replaces), and no header bits set beyond opcode, RD, CD
 * and AD (opcode/RD/CD partition the key; AD is moot as upstreams are always
 * asked with DO=1). Any other shape sends the upstream something the key does
 * not capture, so the caller must key it on its exact bytes instead.
 *
 * The name keeps the raw label octets (see keyLabel): resolvers compare labels
 * octet by octet with ASCII-only case folding, so any wider folding -- Unicode
 * case mapping, IDNA, lossy UTF-8 decoding -- lets one name's answer be cached
 * under another's key.
 *
 * @param {Uint8Array} buf
 * @returns {{ name: string, qtype: number }|null}
 */
export function wireQueryKey(buf) {
  if (!buf || buf.length < 12) return null;
  // QR, AA, TC, Z and RCODE must be clear in a query.
  if ((buf[2] & 0x86) || (buf[3] & 0x4f)) return null;
  if (((buf[4] << 8) | buf[5]) !== 1 || buf[6] || buf[7] || buf[8] || buf[9]) return null;

  const labels = [];
  let off = 12;
  for (;;) {
    if (off >= buf.length) return null;
    const len = buf[off];
    if (len === 0) break;
    if (len > 63) return null; // compression pointer or reserved label type
    if (off + 1 + len > buf.length) return null;
    labels.push(keyLabel(buf.subarray(off + 1, off + 1 + len)));
    off += 1 + len;
  }
  off += 1;
  if (off + 4 > buf.length) return null;
  const qtype = (buf[off] << 8) | buf[off + 1];
  if (((buf[off + 2] << 8) | buf[off + 3]) !== 1) return null; // QCLASS IN
  off += 4;

  const arcount = (buf[10] << 8) | buf[11];
  for (let i = 0; i < arcount; i++) {
    off = skipName(buf, off);
    if (off + 10 > buf.length || ((buf[off] << 8) | buf[off + 1]) !== 41) return null;
    off += 10 + ((buf[off + 8] << 8) | buf[off + 9]);
    if (off > buf.length) return null;
  }
  return { name: labels.length ? labels.join(".") : ".", qtype };
}

// ---------------------------------------------------------------------------
// EDNS OPT record processing (RFC 6891 / RFC 7871 / RFC 7873 / RFC 5001)
// ---------------------------------------------------------------------------

/**
 * Parse the first OPT record (type 41) from the additional section of a DNS
 * wire message. Returns null if no OPT record is present or parsing fails.
 *
 * Returned object fields:
 *   rrStart  {number}  byte offset of the start of the OPT RR (root name label)
 *   rrEnd    {number}  byte offset immediately after the OPT RR
 *   off      {number}  byte offset of the TYPE field within the OPT RR
 *   doBit    {boolean} whether the DNSSEC OK bit is set
 *   options  {Array}   parsed EDNS options: [{code: number, data: Uint8Array}]
 */
function parseOpt(buf) {
  if (buf.length < 12) return null;
  const qdcount = (buf[4] << 8) | buf[5];
  const ancount = (buf[6] << 8) | buf[7];
  const nscount = (buf[8] << 8) | buf[9];
  const arcount = (buf[10] << 8) | buf[11];
  if (arcount === 0) return null;
  try {
    let off = 12;
    for (let q = 0; q < qdcount; q++) { off = skipName(buf, off); off += 4; }
    // Answer and Authority are skipped identically; OPT is only ever in Additional.
    for (let i = 0; i < ancount + nscount; i++) {
      off = skipName(buf, off);
      if (off + 10 > buf.length) return null;
      off += 10 + ((buf[off + 8] << 8) | buf[off + 9]);
    }
    for (let ar = 0; ar < arcount; ar++) {
      const rrStart = off;
      off = skipName(buf, off);
      if (off + 10 > buf.length) return null;
      const rrtype   = (buf[off] << 8) | buf[off + 1];
      const rdlength = (buf[off + 8] << 8) | buf[off + 9];
      const rrEnd    = off + 10 + rdlength;
      // A declared RDLENGTH past the end of the buffer makes rrStart/rrEnd
      // unusable: replaceOpt/removeOpt size their output from that span and
      // would under-allocate, throwing and failing the whole query.
      if (rrEnd > buf.length) return null;
      if (rrtype === 41) {
        // off+6 = high byte of Z field; bit 7 = DO bit
        const doBit = !!(buf[off + 6] & 0x80);
        const options = [];
        let optOff = off + 10;
        while (optOff + 4 <= rrEnd) {
          const code = (buf[optOff] << 8) | buf[optOff + 1];
          const len  = (buf[optOff + 2] << 8) | buf[optOff + 3];
          // An option LENGTH must stay inside the OPT record. Slicing to the
          // buffer end instead would pull in whole following records and copy
          // them back out inside the option's data. The walk stops there
          // rather than discarding the whole OPT: callers rebuild the record
          // from these options, and a null here would make processEdnsIncoming
          // pass the upstream's cookie, NSID and ECS through untouched.
          if (optOff + 4 + len > rrEnd) break;
          // A view, not a copy: every consumer either reads only the code or
          // copies the data into a new record.
          options.push({ code, data: buf.subarray(optOff + 4, optOff + 4 + len) });
          optOff += 4 + len;
        }
        return { rrStart, rrEnd, off, doBit, options };
      }
      off = rrEnd;
    }
  } catch {}
  return null;
}

/** Build flat RDATA bytes from an array of {code, data} options. */
function buildOptRdata(options) {
  let size = 0;
  for (const o of options) size += 4 + o.data.length;
  const out = new Uint8Array(size);
  let w = 0;
  for (const o of options) {
    out[w++] = (o.code >> 8) & 0xff;
    out[w++] =  o.code       & 0xff;
    out[w++] = (o.data.length >> 8) & 0xff;
    out[w++] =  o.data.length       & 0xff;
    out.set(o.data, w);
    w += o.data.length;
  }
  return out;
}

/** Build a complete OPT RR (root label + fixed header + RDATA). */
function buildOptRecord(doBit, options) {
  const rdata = buildOptRdata(options);
  const rec = new Uint8Array(11 + rdata.length);
  let w = 0;
  rec[w++] = 0x00;              // root name
  rec[w++] = 0x00; rec[w++] = 0x29; // TYPE = OPT (41)
  rec[w++] = 0x10; rec[w++] = 0x00; // CLASS = 4096 (UDP payload hint)
  rec[w++] = 0x00;              // extended RCODE = 0
  rec[w++] = 0x00;              // EDNS VERSION = 0
  rec[w++] = doBit ? 0x80 : 0x00; rec[w++] = 0x00; // Z field (DO bit)
  rec[w++] = (rdata.length >> 8) & 0xff;
  rec[w++] =  rdata.length       & 0xff;
  rec.set(rdata, w);
  return rec;
}

/** Replace the OPT RR in buf with newOptRecord (same arcount). */
function replaceOpt(buf, opt, newOptRecord) {
  const out = new Uint8Array(buf.length - (opt.rrEnd - opt.rrStart) + newOptRecord.length);
  out.set(buf.subarray(0, opt.rrStart));
  out.set(newOptRecord, opt.rrStart);
  out.set(buf.subarray(opt.rrEnd), opt.rrStart + newOptRecord.length);
  // arcount unchanged: one OPT removed, one OPT added
  return out;
}

/** Remove the OPT RR from buf and decrement ARCOUNT. */
function removeOpt(buf, opt) {
  const out = new Uint8Array(buf.length - (opt.rrEnd - opt.rrStart));
  out.set(buf.subarray(0, opt.rrStart));
  out.set(buf.subarray(opt.rrEnd), opt.rrStart);
  const newAr = ((buf[10] << 8) | buf[11]) - 1;
  out[10] = (newAr >> 8) & 0xff;
  out[11] = newAr & 0xff;
  return out;
}

// Rebuilds a query containing only the records its header actually counts, with
// every OPT record removed and ARCOUNT corrected.
//
// The privacy modes rebuild a single OPT, but a client controls its own header
// counts, and two shapes slipped past that:
//   - ARCOUNT=0 with an OPT present. The parser skips it, so appending a
//     sanitised OPT sets ARCOUNT=1 and the upstream reads the CLIENT's OPT as
//     the only one.
//   - Several OPTs. Only the first was rewritten; the rest were forwarded
//     verbatim (RFC 6891 Section 6.1.1 permits at most one).
// Either way the client's ECS, cookie or NSID survives a mode that promises to
// remove it. Rebuilding from the counted records drops both, and anything
// trailing the last counted record with it. An OPT is dropped from whichever
// section holds it, and each section's count is rewritten to match.
//
// Falls back to header+question when the records cannot be walked: a message we
// cannot parse is one we cannot sanitise, so nothing after the question is
// forwarded. By the same rule, a question that cannot be walked leaves only the
// header, with every count zeroed. The caller guarantees a 12-byte header.
function stripAllOpts(buf) {
  const qdcount = (buf[4] << 8) | buf[5];
  const ancount = (buf[6] << 8) | buf[7];
  const nscount = (buf[8] << 8) | buf[9];
  const arcount = (buf[10] << 8) | buf[11];

  let off = 12;
  for (let q = 0; q < qdcount; q++) {
    off = skipName(buf, off);
    off += 4;
    if (off > buf.length) {
      const header = buf.slice(0, 12);
      header.fill(0, 4);
      return header;
    }
  }
  const questionEnd = off;

  const kept = [];
  const counts = [0, 0, 0]; // records kept in Answer, Authority, Additional
  for (let i = 0; i < ancount + nscount + arcount; i++) {
    const start = off;
    off = skipName(buf, off);
    const end = off + 10 > buf.length ? -1 : off + 10 + ((buf[off + 8] << 8) | buf[off + 9]);
    if (end < 0 || end > buf.length) { kept.length = 0; counts.fill(0); break; }
    if (((buf[off] << 8) | buf[off + 1]) !== 41) {
      kept.push({ start, end });
      counts[i < ancount ? 0 : i < ancount + nscount ? 1 : 2]++;
    }
    off = end;
  }

  let len = questionEnd;
  for (const k of kept) len += k.end - k.start;
  const out = new Uint8Array(len);
  out.set(buf.subarray(0, questionEnd));
  let w = questionEnd;
  for (const k of kept) { out.set(buf.subarray(k.start, k.end), w); w += k.end - k.start; }

  for (let s = 0; s < 3; s++) {
    out[6 + s * 2] = (counts[s] >> 8) & 0xff;
    out[7 + s * 2] = counts[s] & 0xff;
  }
  return out;
}

/** Append a new OPT RR to buf and increment ARCOUNT. */
function appendOpt(buf, newOptRecord) {
  const out = new Uint8Array(buf.length + newOptRecord.length);
  out.set(buf);
  out.set(newOptRecord, buf.length);
  const newAr = ((buf[10] << 8) | buf[11]) + 1;
  out[10] = (newAr >> 8) & 0xff;
  out[11] = newAr & 0xff;
  return out;
}

/**
 * Build ECS (EDNS Client Subnet, RFC 7871) option RDATA bytes for a CIDR
 * string such as "203.0.113.0/24" (IPv4) or "2001:db8::/32" (IPv6).
 * Returns null if the string cannot be parsed.
 *
 * @param {string} subnetStr
 * @returns {Uint8Array|null}
 */
export function buildEcsOption(subnetStr) {
  if (!subnetStr) return null;
  try {
    const slash = subnetStr.lastIndexOf("/");
    if (slash === -1) return null;
    const addrStr = subnetStr.substring(0, slash);
    const prefix  = parseInt(subnetStr.substring(slash + 1), 10);
    if (isNaN(prefix) || prefix < 0 || prefix > 128) return null;

    let addrBytes;
    let family;
    if (addrStr.includes(":")) {
      // IPv6
      family = 2;
      // Normalise using URL trick, then expand
      const normalized = new URL(`https://[${addrStr}]`).hostname.slice(1, -1);
      let groups;
      if (normalized.includes("::")) {
        const [l, r] = normalized.split("::");
        const lg = l ? l.split(":") : [];
        const rg = r ? r.split(":") : [];
        groups = [...lg, ...new Array(8 - lg.length - rg.length).fill("0"), ...rg];
      } else {
        groups = normalized.split(":");
      }
      addrBytes = new Uint8Array(16);
      for (let i = 0; i < 8; i++) {
        const v = parseInt(groups[i] || "0", 16);
        addrBytes[i * 2]     = (v >> 8) & 0xff;
        addrBytes[i * 2 + 1] =  v       & 0xff;
      }
    } else {
      // IPv4
      family = 1;
      const parts = addrStr.split(".");
      if (parts.length !== 4) return null;
      addrBytes = new Uint8Array(4);
      for (let i = 0; i < 4; i++) {
        const val = parseInt(parts[i], 10);
        if (isNaN(val) || val < 0 || val > 255) return null;
        addrBytes[i] = val;
      }
    }

    // Only include the bytes covered by the prefix length
    const bytesNeeded = Math.ceil(prefix / 8);
    const addr = addrBytes.subarray(0, bytesNeeded);

    // ECS RDATA: FAMILY(2) + SOURCE-PREFIX-LEN(1) + SCOPE-PREFIX-LEN(1) + ADDRESS
    const rdata = new Uint8Array(4 + addr.length);
    rdata[0] = 0;      rdata[1] = family; // FAMILY
    rdata[2] = prefix; rdata[3] = 0;      // SOURCE-PREFIX-LEN, SCOPE-PREFIX-LEN=0
    rdata.set(addr, 4);
    return rdata;
  } catch { return null; }
}

/**
 * Process the EDNS OPT record in an outgoing DNS wire query before forwarding
 * it to an upstream resolver.
 *
 * Behaviour per option:
 *   DO bit is ALWAYS forced to 1 (RFC 4035 Section 3.2.1) so the cache is
 *   always populated with DNSSEC-signed records; handler.js strips DNSSEC RRs
 *   from responses to non-DO clients.
 *   ECS  (code 8)  cfg.PRIVACY_ECS_MODE:  "strip" removes it; "forward" passes it
 *                  through if present; "substitute" injects a fixed subnet.
 *   Cookie (code 10) cfg.PRIVACY_COOKIES_MODE: "strip" removes it; "reoriginate"
 *                  replaces it with the proxy's own per-upstream cookie (cookieBytes).
 *   NSID (code 3)  cfg.PRIVACY_NSID_MODE: "strip" removes it; "forward" passes it
 *                  through; "substitute" removes it (proxy handles NSID at response time).
 *   All other options are stripped (privacy-by-default for unknown options).
 *
 * @param {Uint8Array} buf - Outgoing DNS wire query
 * @param {object} cfg - Runtime config object from getConfig()
 * @param {Uint8Array|null} cookieBytes - Pre-computed cookie bytes for reoriginate mode
 * @returns {Uint8Array}
 */
export function processEdnsOutgoing(buf, cfg, cookieBytes) {
  if (buf.length < 12) return buf;
  // Only the forward modes read the client's options.
  const forwarding  = cfg.PRIVACY_ECS_MODE === "forward" || cfg.PRIVACY_NSID_MODE === "forward";
  const opt         = forwarding ? parseOpt(buf) : null;
  const addCookie   = cfg.PRIVACY_COOKIES_MODE === "reoriginate" && cookieBytes != null;
  const addSubstEcs = cfg.PRIVACY_ECS_MODE     === "substitute"  && !!cfg.PRIVACY_ECS_SUBNET;

  const newOptions = [];

  // ECS
  if (cfg.PRIVACY_ECS_MODE === "forward" && opt) {
    const ecsOpt = opt.options.find(o => o.code === 8);
    if (ecsOpt) newOptions.push(ecsOpt);
  } else if (addSubstEcs) {
    const ecsData = buildEcsOption(cfg.PRIVACY_ECS_SUBNET);
    if (ecsData) newOptions.push({ code: 8, data: ecsData });
  }

  // Cookie
  if (addCookie) {
    newOptions.push({ code: 10, data: cookieBytes });
  }

  // NSID
  if (cfg.PRIVACY_NSID_MODE === "forward" && opt) {
    const nsidOpt = opt.options.find(o => o.code === 3);
    if (nsidOpt) newOptions.push(nsidOpt);
  }
  // An OPT record with DO=1 is always emitted in outgoing queries. Every OPT the
  // client sent is removed first, so nothing it attached can reach the upstream
  // regardless of what its header counts claimed.
  return appendOpt(stripAllOpts(buf), buildOptRecord(true, newOptions));
}

// ---------------------------------------------------------------------------
// DNSSEC response filtering (RFC 4035 Section 3.1.4.1)
// ---------------------------------------------------------------------------

// DNSSEC authentication record types that MUST NOT be included in responses
// to queries that did not set the DO bit (RFC 4035 SS.3.1.4.1).
// Exception: a type IS included if it is the explicitly queried type.
const DNSSEC_AUTH_TYPES = new Set([46, 47, 48, 50]); // RRSIG, NSEC, DNSKEY, NSEC3

/**
 * Strip DNSSEC authentication records from a DNS wire response when the
 * client did not set the DO (DNSSEC OK) bit (RFC 4035 Section 3.1.4.1).
 *
 * RRSIG/NSEC/NSEC3/DNSKEY records are removed from the Answer section unless
 * their type equals queryQtype (explicit request exception); in the Authority
 * section they are always removed. ANCOUNT/NSCOUNT are updated accordingly.
 * Returns the original buffer if no records need to be removed.
 *
 * @param {Uint8Array} buf - DNS wire response
 * @param {number} queryQtype - Numeric query type from the original DNS question
 * @returns {Uint8Array}
 */
export function stripDnssecFromWire(buf, queryQtype) {
  if (buf.length < 12) return buf;
  try {
    const qdcount = (buf[4] << 8) | buf[5];
    const ancount = (buf[6] << 8) | buf[7];
    const nscount = (buf[8] << 8) | buf[9];

    let off = 12;
    for (let q = 0; q < qdcount; q++) { off = skipName(buf, off); off += 4; }
    const qSectionEnd = off;

    const parts = [];
    let newAn = 0, newNs = 0;

    // A record we cannot fully parse makes every following offset meaningless:
    // continuing would splice bytes out of the middle of a record and emit a
    // message whose section counts disagree with its contents. Rebuilding is
    // only safe when the whole Answer and Authority run parses cleanly, so any
    // truncation returns the input untouched.
    for (let i = 0; i < ancount + nscount; i++) {
      const isAnswer = i < ancount;
      const start = off;
      off = skipName(buf, off);
      if (off + 10 > buf.length) return buf;
      const rrtype = (buf[off] << 8) | buf[off + 1];
      const rdlen  = (buf[off + 8] << 8) | buf[off + 9];
      const end    = off + 10 + rdlen;
      if (end > buf.length) return buf; // rdlength runs past the buffer
      // Answer keeps the type actually asked for (RFC 4035 S3.1.4.1);
      // Authority strips unconditionally.
      const keep = isAnswer
        ? (!DNSSEC_AUTH_TYPES.has(rrtype) || rrtype === queryQtype)
        : !DNSSEC_AUTH_TYPES.has(rrtype);
      if (keep) { if (isAnswer) newAn++; else newNs++; }
      parts.push({ start, end, keep });
      off = end;
    }

    if (newAn === ancount && newNs === nscount) return buf; // nothing to strip

    const addStart = off;
    let newLen = qSectionEnd;
    for (const p of parts) if (p.keep) newLen += p.end - p.start;
    newLen += buf.length - addStart;

    const out = new Uint8Array(newLen);
    out.set(buf.subarray(0, qSectionEnd));
    let w = qSectionEnd;
    for (const p of parts) {
      if (p.keep) { out.set(buf.subarray(p.start, p.end), w); w += p.end - p.start; }
    }
    out.set(buf.subarray(addStart), w);
    out[6] = (newAn >> 8) & 0xff; out[7] = newAn & 0xff;
    out[8] = (newNs >> 8) & 0xff; out[9] = newNs & 0xff;
    return out;
  } catch { return buf; }
}

/**
 * Strip DNSSEC authentication records from a JSON DoH response when the
 * client did not set the DO bit. Same rules as stripDnssecFromWire.
 * Returns the original object unchanged if no records need to be removed.
 *
 * @param {object} json - Parsed JSON DoH response object
 * @param {number} queryQtype - Numeric query type from the original DNS question
 * @returns {object}
 */
export function stripDnssecFromJson(json, queryQtype) {
  const hasStrippable = (arr, forAuth) =>
    Array.isArray(arr) && arr.some(rr =>
      DNSSEC_AUTH_TYPES.has(rr.type) && (forAuth || rr.type !== queryQtype)
    );
  if (!hasStrippable(json.Answer, false) && !hasStrippable(json.Authority, true)) return json;
  const result = { ...json };
  if (Array.isArray(result.Answer)) {
    result.Answer = result.Answer.filter(rr =>
      !DNSSEC_AUTH_TYPES.has(rr.type) || rr.type === queryQtype
    );
  }
  if (Array.isArray(result.Authority)) {
    result.Authority = result.Authority.filter(rr => !DNSSEC_AUTH_TYPES.has(rr.type));
  }
  return result;
}

/**
 * Process the EDNS OPT record in an upstream wire response before caching or
 * returning it to the client.
 *
 * Behaviour per option:
 *   ECS    (code 8)  Strip unless cfg.PRIVACY_ECS_MODE === "forward".
 *   Cookie (code 10) Always stripped from response (proxy manages cookie state).
 *                    If cfg.PRIVACY_COOKIES_MODE === "reoriginate" and the response
 *                    carries a server cookie, onServerCookie is called with those bytes.
 *   NSID   (code 3)  Strip unless cfg.PRIVACY_NSID_MODE === "forward".
 *                    In "substitute" mode the NSID is stripped here; the proxy
 *                    injects its own identifier at response time (see injectNsidToResponse).
 *   EDE    (code 15) Always passed through (RFC 8914 diagnostic info for clients).
 *   All other options are stripped.
 *
 *   OPT is removed entirely when no options remain and DO bit is unset.
 *
 * @param {Uint8Array} buf - Upstream DNS wire response
 * @param {object} cfg - Runtime config object from getConfig()
 * @param {function|null} onServerCookie - Called with server cookie Uint8Array when found
 * @returns {Uint8Array}
 */
export function processEdnsIncoming(buf, cfg, onServerCookie) {
  if (buf.length < 12) return buf;
  const opt = parseOpt(buf);
  if (!opt) return buf;

  const newOptions = [];
  for (const o of opt.options) {
    switch (o.code) {
      case 8: // ECS
        if (cfg.PRIVACY_ECS_MODE === "forward") newOptions.push(o);
        break;
      case 10: // Cookie
        // Server cookie (RFC 7873 SS.4): client cookie is always 8 bytes; server
        // cookie is 8-32 bytes. Only store the server cookie when the combined
        // option data is in the valid range [16, 40] bytes.
        if (onServerCookie && o.data.length >= 16 && o.data.length <= 40) {
          onServerCookie(o.data.subarray(8));
        }
        // Always strip cookies from client-facing response
        break;
      case 3: // NSID
        if (cfg.PRIVACY_NSID_MODE === "forward") newOptions.push(o);
        // "strip" or "substitute": remove (substitute injects own value later)
        break;
      case 15: // EDE (RFC 8914) - always pass through
        newOptions.push(o);
        break;
      default:
        // Strip unknown options
        break;
    }
  }

  const keepOpt = newOptions.length > 0 || opt.doBit;
  if (!keepOpt) return removeOpt(buf, opt);
  return replaceOpt(buf, opt, buildOptRecord(opt.doBit, newOptions));
}

/**
 * Clear the DNSSEC OK (DO) bit in a DNS wire response OPT record when the
 * originating client did not set DO=1 in its query (RFC 6891 Section 6.1.4 /
 * RFC 3225: the DO bit of the query must be mirrored in the response; cached
 * copies always carry DO=1). Returns the original buffer unchanged when no
 * OPT record is present or the DO bit is already cleared.
 *
 * @param {Uint8Array} buf - DNS wire response
 * @returns {Uint8Array}
 */
export function clearDoBitInResponse(buf) {
  if (buf.length < 12) return buf;
  const opt = parseOpt(buf);
  if (!opt || !opt.doBit) return buf;
  return replaceOpt(buf, opt, buildOptRecord(false, opt.options));
}

/**
 * Returns true if the DNS wire message has the DNSSEC OK (DO) bit set in its
 * EDNS OPT record (RFC 6891 Section 6.1.4). Returns false if there is no OPT
 * record or the DO bit is not set.
 *
 * @param {Uint8Array|null} buf
 * @returns {boolean}
 */
export function hasDoBit(buf) {
  if (!buf || buf.length < 12) return false;
  const opt = parseOpt(buf);
  return !!opt && opt.doBit;
}

/**
 * True when the query carries an EDNS Client Subnet option (RFC 7871, code 8).
 * Used to keep subnet-specific answers out of the shared edge cache.
 *
 * @param {Uint8Array} buf
 * @returns {boolean}
 */
export function hasEcsOption(buf) {
  const opt = parseOpt(buf);
  return !!opt && opt.options.some(o => o.code === 8);
}

/**
 * Returns true if the DNS wire query contains an NSID request option (code 3).
 * Returns false for null/short buffers or when no NSID option is found.
 *
 * @param {Uint8Array|null} buf
 * @returns {boolean}
 */
export function hasNsidRequest(buf) {
  if (!buf || buf.length < 12) return false;
  const opt = parseOpt(buf);
  return !!opt && opt.options.some(o => o.code === 3);
}

/**
 * Inject an NSID response option (code 3) into a DNS wire response buffer.
 * The NSID value is encoded as raw ASCII bytes of the identifier string.
 * If an OPT record already exists, the NSID is added to it (any existing
 * NSID option is replaced). If no OPT exists, a new minimal OPT is appended.
 * Returns the original buffer unchanged if nsidValue is empty/null.
 *
 * @param {Uint8Array} buf - DNS wire response
 * @param {string} nsidValue - The human-readable NSID string (e.g. "dnsieve-cfw-01")
 * @returns {Uint8Array}
 */
export function injectNsidToResponse(buf, nsidValue) {
  if (!nsidValue || buf.length < 12) return buf;
  // Encode NSID as raw ASCII bytes
  const valueBytes = new Uint8Array(nsidValue.length);
  for (let i = 0; i < nsidValue.length; i++) valueBytes[i] = nsidValue.charCodeAt(i) & 0xff;
  const nsidOption = { code: 3, data: valueBytes };

  const opt = parseOpt(buf);
  if (opt) {
    const filteredOpts = opt.options.filter(o => o.code !== 3);
    filteredOpts.push(nsidOption);
    return replaceOpt(buf, opt, buildOptRecord(opt.doBit, filteredOpts));
  }
  return appendOpt(buf, buildOptRecord(false, [nsidOption]));
}

// Reads a DNS name (including pointer compression) starting at off.
// Returns { name: string, offset: number } where offset is after the name.
export function readDnsName(buf, off) {
  const labels = [];
  let jumped = false;
  let returnOffset = off;
  let hops = 0;

  while (off < buf.length) {
    // Guard against malformed packets with circular compression pointers (RFC 1035 SS.4.1.4)
    if (++hops > 128) throw new RangeError("DNS name compression pointer loop detected");
    const len = buf[off];
    if (len === 0) {
      if (!jumped) returnOffset = off + 1;
      break;
    }
    if ((len & 0xc0) === 0xc0) {
      if (!jumped) returnOffset = off + 2;
      off = ((len & 0x3f) << 8) | buf[off + 1];
      jumped = true;
      continue;
    }
    off += 1;
    // RFC 4343 Section 2.1: a label may legally contain a dot, so escape it in
    // the presentation form. Joining raw labels with "." would map the single
    // label "example.com" onto the same string as the two labels
    // "example" + "com", while the upstream resolves the name the wire bytes
    // actually encode -- letting a cache key built from this string collide
    // with an unrelated query.
    labels.push(TEXT_DECODER.decode(buf.subarray(off, off + len))
      .replace(/\\/g, "\\\\").replace(/\./g, "\\."));
    off += len;
    if (!jumped) returnOffset = off;
  }

  return { name: labels.join(".") + ".", offset: returnOffset };
}

// Parse the DNS type bit maps field used in NSEC (RFC 4034) and NSEC3 (RFC 5155)
// into an array of type name strings. Processing stops at endOff.
function parseBitmap(buf, startOff, endOff) {
  const types = [];
  let p = startOff;
  while (p + 2 <= endOff) {
    const windowBlock = buf[p];
    const bitmapLen   = buf[p + 1];
    p += 2;
    for (let i = 0; i < bitmapLen && p + i < buf.length; i++) {
      const byte = buf[p + i];
      for (let bit = 7; bit >= 0; bit--) {
        if (byte & (1 << bit)) {
          const rrtype = windowBlock * 256 + i * 8 + (7 - bit);
          types.push(DNS_NUMBER_TO_TYPE[rrtype] || rrtype.toString());
        }
      }
    }
    p += bitmapLen;
  }
  return types;
}

// Parses an RDATA field into a human-readable string.
// Falls back to hex encoding for unknown or malformed types.
export function parseRdata(buf, off, rrtype, rdlength) {
  try {
    switch (rrtype) {
      case 1: // A (RFC 1035)
        if (rdlength === 4) return `${buf[off]}.${buf[off+1]}.${buf[off+2]}.${buf[off+3]}`;
        break;
      case 28: { // AAAA (RFC 3596)
        if (rdlength === 16) {
          const p = new Array(8);
          for (let i = 0; i < 8; i++) p[i] = ((buf[off+i*2]<<8)|buf[off+i*2+1]).toString(16);
          return p.join(":");
        }
        break;
      }
      case 2: case 5: case 12: // NS, CNAME, PTR (RFC 1035)
        return readDnsName(buf, off).name;
      case 6: { // SOA (RFC 1035)
        const mname = readDnsName(buf, off);
        const rname = readDnsName(buf, mname.offset);
        let p = rname.offset;
        const s  = ((buf[p]<<24)|(buf[p+1]<<16)|(buf[p+2]<<8)|buf[p+3])>>>0; p+=4;
        const rf = ((buf[p]<<24)|(buf[p+1]<<16)|(buf[p+2]<<8)|buf[p+3])>>>0; p+=4;
        const rt = ((buf[p]<<24)|(buf[p+1]<<16)|(buf[p+2]<<8)|buf[p+3])>>>0; p+=4;
        const ex = ((buf[p]<<24)|(buf[p+1]<<16)|(buf[p+2]<<8)|buf[p+3])>>>0; p+=4;
        const mn = ((buf[p]<<24)|(buf[p+1]<<16)|(buf[p+2]<<8)|buf[p+3])>>>0;
        return `${mname.name} ${rname.name} ${s} ${rf} ${rt} ${ex} ${mn}`;
      }
      case 15: { // MX (RFC 1035)
        const pref = (buf[off] << 8) | buf[off + 1];
        return `${pref} ${readDnsName(buf, off + 2).name}`;
      }
      case 16: { // TXT (RFC 1035)
        let txt = "";
        let p = off;
        const end = off + rdlength;
        while (p < end) {
          const slen = buf[p++];
          for (let i = 0; i < slen && p < end; i++) txt += String.fromCharCode(buf[p++]);
        }
        return `"${txt}"`;
      }
      case 33: { // SRV (RFC 2782)
        if (rdlength >= 6) {
          const prio   = (buf[off]     << 8) | buf[off + 1];
          const weight = (buf[off + 2] << 8) | buf[off + 3];
          const port   = (buf[off + 4] << 8) | buf[off + 5];
          const { name: target } = readDnsName(buf, off + 6);
          return `${prio} ${weight} ${port} ${target}`;
        }
        break;
      }
      case 39: // DNAME (RFC 6672)
        return readDnsName(buf, off).name;
      case 43: { // DS (RFC 4034 Section 5.1)
        if (rdlength >= 4) {
          const tag   = (buf[off] << 8) | buf[off + 1];
          const alg   = buf[off + 2];
          const dtype = buf[off + 3];
          return `${tag} ${alg} ${dtype} ${bytesToHex(buf.subarray(off + 4, off + rdlength))}`;
        }
        break;
      }
      case 46: { // RRSIG (RFC 4034 Section 3.1)
        if (rdlength >= 18) {
          const tc     = (buf[off] << 8) | buf[off + 1];
          const alg    =  buf[off + 2];
          const labels =  buf[off + 3];
          const origTtl = ((buf[off+4]<<24)|(buf[off+5]<<16)|(buf[off+6]<<8)|buf[off+7])>>>0;
          const sigExp  = ((buf[off+8]<<24)|(buf[off+9]<<16)|(buf[off+10]<<8)|buf[off+11])>>>0;
          const sigInc  = ((buf[off+12]<<24)|(buf[off+13]<<16)|(buf[off+14]<<8)|buf[off+15])>>>0;
          const keyTag  = (buf[off+16] << 8) | buf[off+17];
          const signerR = readDnsName(buf, off + 18);
          const sigBytes = buf.subarray(signerR.offset, off + rdlength);
          const sigB64 = bytesToBase64(sigBytes);
          const tcName = DNS_NUMBER_TO_TYPE[tc] || String(tc);
          return `${tcName} ${alg} ${labels} ${origTtl} ${sigExp} ${sigInc} ${keyTag} ${signerR.name} ${sigB64}`;
        }
        break;
      }
      case 47: { // NSEC (RFC 4034 Section 4.1)
        const nextDom = readDnsName(buf, off);
        const types = parseBitmap(buf, nextDom.offset, off + rdlength);
        return `${nextDom.name} ${types.join(" ")}`;
      }
      case 48: { // DNSKEY (RFC 4034 Section 2.1)
        if (rdlength >= 4) {
          const flags = (buf[off] << 8) | buf[off + 1];
          const proto =  buf[off + 2];
          const alg   =  buf[off + 3];
          const keyBytes = buf.subarray(off + 4, off + rdlength);
          const keyB64 = bytesToBase64(keyBytes);
          return `${flags} ${proto} ${alg} ${keyB64}`;
        }
        break;
      }
      case 50: { // NSEC3 (RFC 5155 Section 3.2)
        if (rdlength >= 5) {
          const hashAlg = buf[off];
          const flags   = buf[off + 1];
          const iters   = (buf[off + 2] << 8) | buf[off + 3];
          const saltLen = buf[off + 4];
          let p = off + 5;
          const salt = saltLen === 0 ? "-" : bytesToHex(buf.subarray(p, p + saltLen));
          p += saltLen;
          if (p + 1 > off + rdlength) break;
          const hashLen = buf[p++];
          const nextHash = encodeBase32Hex(buf.subarray(p, p + hashLen));
          p += hashLen;
          const types = parseBitmap(buf, p, off + rdlength);
          return `${hashAlg} ${flags} ${iters} ${salt} ${nextHash} ${types.join(" ")}`;
        }
        break;
      }
      case 257: { // CAA (RFC 8659 Section 4)
        if (rdlength >= 2) {
          const flagByte = buf[off];
          const tagLen   = buf[off + 1];
          if (off + 2 + tagLen <= off + rdlength) {
            const tag   = TEXT_DECODER.decode(buf.subarray(off + 2, off + 2 + tagLen));
            const value = TEXT_DECODER.decode(buf.subarray(off + 2 + tagLen, off + rdlength));
            return `${flagByte} ${tag} "${value}"`;
          }
        }
        break;
      }
    }
  } catch {}
  // Unknown or malformed: return hex
  return bytesToHex(buf.subarray(off, off + rdlength));
}

/**
 * Convert a DNS wire-format response into a Google/Cloudflare JSON DoH object.
 * Returns null if the buffer is too short or malformed.
 *
 * @param {Uint8Array} buf
 * @returns {object|null}
 */
export function wireToJson(buf) {
  try {
    if (buf.length < 12) return null;
    const flags = (buf[2] << 8) | buf[3];
    const rcode = flags & 0x0f;
    const tc = !!(flags & 0x0200);
    const rd = !!(flags & 0x0100);
    const ra = !!(flags & 0x0080);
    const ad = !!(flags & 0x0020);
    const cd = !!(flags & 0x0010);
    const qdcount = (buf[4] << 8) | buf[5];
    const ancount = (buf[6] << 8) | buf[7];
    const nscount = (buf[8] << 8) | buf[9];

    let off = 12;
    const questions = [];
    for (let q = 0; q < qdcount && off < buf.length; q++) {
      const { name, offset } = readDnsName(buf, off);
      off = offset;
      const qtype = (buf[off] << 8) | buf[off + 1];
      off += 4;
      questions.push({ name, type: qtype });
    }

    function parseRRs(count) {
      const rrs = [];
      for (let i = 0; i < count; i++) {
        const { name, offset } = readDnsName(buf, off);
        off = offset;
        if (off + 10 > buf.length) break;
        const rrtype   = (buf[off] << 8) | buf[off + 1];
        const ttl      = ((buf[off+4]<<24)|(buf[off+5]<<16)|(buf[off+6]<<8)|buf[off+7])>>>0;
        const rdlength = (buf[off + 8] << 8) | buf[off + 9];
        off += 10;
        const data = parseRdata(buf, off, rrtype, rdlength);
        rrs.push({ name, type: rrtype, TTL: ttl, data });
        off += rdlength;
      }
      return rrs;
    }

    const answers     = parseRRs(ancount);
    const authorities = parseRRs(nscount);

    const result = { Status: rcode, TC: tc, RD: rd, RA: ra, AD: ad, CD: cd };
    if (questions.length)   result.Question  = questions;
    if (answers.length)     result.Answer    = answers;
    if (authorities.length) result.Authority = authorities;
    return result;
  } catch {
    return null;
  }
}

// Returns the minimum TTL value across all Answer and Authority records in a JSON response.
export function extractMinTtl(json) {
  let min = Infinity;
  const a = json.Answer;
  if (Array.isArray(a)) for (let i = 0; i < a.length; i++) { const t = a[i].TTL; if (typeof t === "number" && t < min) min = t; }
  const u = json.Authority;
  if (Array.isArray(u)) for (let i = 0; i < u.length; i++) { const t = u[i].TTL; if (typeof t === "number" && t < min) min = t; }
  return min === Infinity ? null : min;
}

// Coerce a TTL into the 0..2^31-1 range DNS allows (RFC 2181 Section 8).
// Config values arrive as bare Number(env.X), so non-integers are possible.
function clampTtl(ttl) {
  return Math.max(0, Math.min(0x7fffffff, Math.floor(ttl)));
}

/**
 * Rewrite every resource-record TTL in a DNS wire response to `ttl`.
 *
 * OS-level DoH clients cache on the record TTL and ignore Cache-Control, so the
 * message body is the only place this value takes effect. Answer, Authority and
 * Additional are rewritten; the OPT pseudo-record (type 41) is skipped because
 * RFC 6891 Section 6.1.3 repurposes its TTL field as rcode/version/flags.
 *
 * Returns the buffer unchanged when it is too short or cannot be parsed.
 *
 * @param {Uint8Array} buf - DNS wire response
 * @param {number} ttl - TTL in seconds
 * @returns {Uint8Array}
 */
export function setTtlWire(buf, ttl) {
  if (!buf || buf.length < 12) return buf;
  const value = clampTtl(ttl);
  try {
    const qdcount = (buf[4] << 8) | buf[5];
    const ancount = (buf[6] << 8) | buf[7];
    const nscount = (buf[8] << 8) | buf[9];
    const arcount = (buf[10] << 8) | buf[11];

    let off = 12;
    for (let q = 0; q < qdcount; q++) { off = skipName(buf, off); off += 4; }

    const b1 = (value >>> 24) & 0xff, b2 = (value >>> 16) & 0xff;
    const b3 = (value >>> 8) & 0xff,  b4 = value & 0xff;

    // Copy lazily: when every record already carries the target TTL the input
    // is returned as-is. The input is never written to.
    let out = buf;
    const total = ancount + nscount + arcount;
    for (let r = 0; r < total; r++) {
      off = skipName(out, off);
      if (off + 10 > out.length) break;
      const rrtype = (out[off] << 8) | out[off + 1];
      // RFC 6891 S.6.1.3: OPT reuses the TTL field for rcode/version/flags.
      if (rrtype !== 41 &&
          (out[off + 4] !== b1 || out[off + 5] !== b2 ||
           out[off + 6] !== b3 || out[off + 7] !== b4)) {
        if (out === buf) out = new Uint8Array(buf);
        out[off + 4] = b1;
        out[off + 5] = b2;
        out[off + 6] = b3;
        out[off + 7] = b4;
      }
      const rdlength = (out[off + 8] << 8) | out[off + 9];
      off += 10 + rdlength;
    }
    return out;
  } catch { return buf; }
}

/**
 * Rewrite every record TTL in a JSON DoH response to `ttl`.
 * Mirrors setTtlWire for the application/dns-json representation.
 *
 * @param {object} json - Parsed JSON DoH response
 * @param {number} ttl - TTL in seconds
 * @returns {object} A new object; the input is not mutated.
 */
export function setTtlJson(json, ttl) {
  if (!json || typeof json !== "object") return json;
  const value = clampTtl(ttl);
  const out = { ...json };
  for (const section of ["Answer", "Authority", "Additional"]) {
    const rrs = out[section];
    if (!Array.isArray(rrs)) continue;
    out[section] = rrs.map(rr => (rr && typeof rr === "object" && typeof rr.TTL === "number")
      ? { ...rr, TTL: value }
      : rr);
  }
  return out;
}

// Returns the minimum TTL from a DNS wire response by scanning Answer + Authority RRs.
export function extractMinTtlWire(buf) {
  if (buf.length < 12) return null;
  try {
    const qdcount = (buf[4] << 8) | buf[5];
    const ancount = (buf[6] << 8) | buf[7];
    const nscount = (buf[8] << 8) | buf[9];
    let off = 12;
    for (let q = 0; q < qdcount; q++) { off = skipName(buf, off); off += 4; }
    let min = Infinity;
    const total = ancount + nscount;
    for (let r = 0; r < total; r++) {
      off = skipName(buf, off);
      if (off + 10 > buf.length) break;
      const ttl = ((buf[off+4]<<24)|(buf[off+5]<<16)|(buf[off+6]<<8)|buf[off+7])>>>0;
      const rdlength = (buf[off + 8] << 8) | buf[off + 9];
      if (ttl < min) min = ttl;
      off += 10 + rdlength;
    }
    return min === Infinity ? null : min;
  } catch { return null; }
}

/**
 * Build a minimal DNS wire-format query for a given name and type.
 * Used in tests to construct synthetic request bodies.
 *
 * @param {string} name - Domain name (e.g. "example.com")
 * @param {number} qtype - DNS type number (e.g. 1 for A)
 * @param {number} [id=0] - DNS transaction ID
 * @returns {Uint8Array}
 */
export function buildDnsQuery(name, qtype, id = 0) {
  const labels = name.replace(/\.$/, "").split(".");
  let nameBytes = 0;
  for (const l of labels) nameBytes += 1 + l.length;
  nameBytes += 1; // root label

  const buf = new Uint8Array(12 + nameBytes + 4);
  buf[0] = (id >> 8) & 0xff;
  buf[1] = id & 0xff;
  buf[2] = 0x01; // QR=0, Opcode=0, RD=1
  buf[3] = 0x00;
  buf[4] = 0x00; buf[5] = 0x01; // QDCOUNT=1
  buf[6] = 0x00; buf[7] = 0x00;
  buf[8] = 0x00; buf[9] = 0x00;
  buf[10] = 0x00; buf[11] = 0x00;

  let off = 12;
  for (const label of labels) {
    buf[off++] = label.length;
    for (let i = 0; i < label.length; i++) buf[off++] = label.charCodeAt(i);
  }
  buf[off++] = 0; // root
  buf[off++] = (qtype >> 8) & 0xff;
  buf[off++] = qtype & 0xff;
  buf[off++] = 0x00; // QCLASS IN high
  buf[off++] = 0x01; // QCLASS IN low
  return buf;
}

/**
 * Build a minimal DNS wire-format A-record response.
 *
 * @param {string} name - Query name
 * @param {string} ip - IPv4 address string (e.g. "1.2.3.4") or "0.0.0.0" for block
 * @param {number} [ttl=300] - TTL
 * @param {number} [rcode=0] - Response code
 * @param {number} [nscount=0] - Authority record count (for NXDOMAIN disambiguation)
 * @returns {Uint8Array}
 */
export function buildDnsResponse(name, ip, ttl = 300, rcode = 0, nscount = 0) {
  const labels = name.replace(/\.$/, "").split(".");
  let nameBytes = 0;
  for (const l of labels) nameBytes += 1 + l.length;
  nameBytes += 1;

  const isNxdomain = rcode === 3;
  const ancount = isNxdomain ? 0 : 1;
  const rdlength = 4;

  // Header(12) + Question(nameBytes + 4) + pointer(2) + type/class/ttl/rdlen(10) + rdata(4)
  const totalSize = 12 + nameBytes + 4 + (isNxdomain ? 0 : (2 + 10 + rdlength));
  const buf = new Uint8Array(totalSize);

  // Header
  buf[0] = 0; buf[1] = 0; // ID = 0
  buf[2] = 0x81; // QR=1, RD=1
  buf[3] = 0x80 | (rcode & 0x0f); // RA=1, rcode
  buf[4] = 0x00; buf[5] = 0x01; // QDCOUNT=1
  buf[6] = (ancount >> 8) & 0xff; buf[7] = ancount & 0xff;
  buf[8] = 0x00; buf[9] = nscount & 0xff; // NSCOUNT
  buf[10] = 0x00; buf[11] = 0x00;

  let off = 12;
  for (const label of labels) {
    buf[off++] = label.length;
    for (let i = 0; i < label.length; i++) buf[off++] = label.charCodeAt(i);
  }
  buf[off++] = 0;
  buf[off++] = 0x00; buf[off++] = 0x01; // QTYPE A
  buf[off++] = 0x00; buf[off++] = 0x01; // QCLASS IN

  if (!isNxdomain) {
    // Pointer to question name
    buf[off++] = 0xc0; buf[off++] = 0x0c;
    // TYPE A
    buf[off++] = 0x00; buf[off++] = 0x01;
    // CLASS IN
    buf[off++] = 0x00; buf[off++] = 0x01;
    // TTL
    buf[off++] = (ttl >> 24) & 0xff;
    buf[off++] = (ttl >> 16) & 0xff;
    buf[off++] = (ttl >> 8)  & 0xff;
    buf[off++] = ttl & 0xff;
    // RDLENGTH
    buf[off++] = 0x00; buf[off++] = 0x04;
    // RDATA
    const parts = ip.split(".");
    buf[off++] = parseInt(parts[0], 10);
    buf[off++] = parseInt(parts[1], 10);
    buf[off++] = parseInt(parts[2], 10);
    buf[off++] = parseInt(parts[3], 10);
  }

  return buf;
}

/**
 * Build a SERVFAIL (rcode=2) wire-format response for a given query, used
 * when all upstreams fail (RFC 8484 s4.2.1: returned with HTTP 200, never a
 * bare 502). The question section from queryBytes is mirrored into the
 * response; if queryBytes is absent or malformed a header-only SERVFAIL is
 * returned.
 *
 * @param {Uint8Array|null} queryBytes - Original query wire bytes (ID already zeroed)
 * @returns {Uint8Array}
 */
export function buildServfailResponse(queryBytes) {
  const makeHeader = () => {
    const buf = new Uint8Array(12);
    buf[2] = 0x81; // QR=1, RD=1
    buf[3] = 0x82; // RA=1, rcode=2 (SERVFAIL)
    return buf;
  };

  if (!queryBytes || queryBytes.length < 12) return makeHeader();

  try {
    const qdcount = (queryBytes[4] << 8) | queryBytes[5];
    let off = 12;
    for (let q = 0; q < qdcount; q++) {
      off = skipName(queryBytes, off);
      off += 4; // QTYPE + QCLASS
    }
    // A question that runs past the query is dropped, as in buildBlockedResponse:
    // copying it short would leave QDCOUNT claiming bytes the message lacks.
    const truncated = off > queryBytes.length;
    const questionLen = truncated ? 0 : off - 12;
    const buf = new Uint8Array(12 + questionLen);
    buf[0] = queryBytes[0]; buf[1] = queryBytes[1]; // ID (0 per RFC 8484; restored by applyClientEdns)
    // RFC 1035 S4.1.1: OPCODE and RD bits MUST be copied from the request into the response.
    // RFC 4035 S3.1.6: CD bit MUST be copied from the request into the response.
    buf[2] = 0x80 | (queryBytes[2] & 0x79); // QR=1, OPCODE+RD mirrored from query
    buf[3] = 0x80 | (queryBytes[3] & 0x10) | 0x02; // RA=1, CD mirrored, SERVFAIL rcode=2
    if (!truncated) { buf[4] = queryBytes[4]; buf[5] = queryBytes[5]; } // QDCOUNT
    buf.set(queryBytes.subarray(12, 12 + questionLen), 12);
    return buf;
  } catch {
    return makeHeader();
  }
}

/**
 * Build a minimal DNS wire-format query that includes an EDNS OPT record with
 * the DO (DNSSEC OK) bit set to the supplied value.
 *
 * Convenience wrapper used in tests to verify DO-bit handling without having
 * to manually craft OPT records.
 *
 * @param {string} name - Domain name (e.g. "example.com")
 * @param {number} qtype - DNS type number (e.g. 1 for A)
 * @param {number} [id=0] - DNS transaction ID
 * @param {boolean} [doBit=true] - Value of the DO bit in the OPT record
 * @returns {Uint8Array}
 */
export function buildDnsQueryWithDo(name, qtype, id = 0, doBit = true) {
  return appendOpt(buildDnsQuery(name, qtype, id), buildOptRecord(doBit, []));
}

// ---------------------------------------------------------------------------
// DNSSEC data detection (for upstream preference)
// ---------------------------------------------------------------------------

/**
 * Check whether a DNS wire response contains DNSSEC data: the AD (Authenticated
 * Data) flag set in the header, OR any RRSIG (type 46) records in the Answer
 * or Authority sections.
 *
 * Used to prefer DNSSEC-signed upstream responses over unsigned ones.
 *
 * @param {Uint8Array} buf - DNS wire response
 * @returns {boolean}
 */
export function hasDnssecData(buf) {
  if (!buf || buf.length < 12) return false;
  // Check AD bit (bit 5 of byte 3)
  if (buf[3] & 0x20) return true;
  try {
    const qdcount = (buf[4] << 8) | buf[5];
    const ancount = (buf[6] << 8) | buf[7];
    const nscount = (buf[8] << 8) | buf[9];
    let off = 12;
    for (let q = 0; q < qdcount; q++) { off = skipName(buf, off); off += 4; }
    const total = ancount + nscount;
    for (let r = 0; r < total; r++) {
      off = skipName(buf, off);
      if (off + 10 > buf.length) break;
      const rrtype = (buf[off] << 8) | buf[off + 1];
      if (rrtype === 46) return true; // RRSIG
      const rdlength = (buf[off + 8] << 8) | buf[off + 9];
      off += 10 + rdlength;
    }
  } catch {}
  return false;
}

/**
 * Check whether a JSON DoH response contains DNSSEC data: the AD flag set,
 * OR any RRSIG (type 46) records in the Answer or Authority arrays.
 *
 * @param {object} json - Parsed JSON DoH response
 * @returns {boolean}
 */
export function hasDnssecDataJson(json) {
  if (!json) return false;
  if (json.AD) return true;
  const hasRrsig = (arr) =>
    Array.isArray(arr) && arr.some(rr => rr.type === 46);
  return hasRrsig(json.Answer) || hasRrsig(json.Authority);
}

// ---------------------------------------------------------------------------
// EDE (Extended DNS Errors, RFC 8914) option building
// ---------------------------------------------------------------------------

/**
 * Build an EDE EDNS option (code 15) with the given info-code and optional
 * extra text. Returns an option object suitable for use with buildOptRecord.
 *
 * RFC 8914 Section 2:
 *   INFO-CODE (2 bytes) + EXTRA-TEXT (variable, UTF-8)
 *
 * @param {number} infoCode - EDE info code (e.g. 15 = Blocked)
 * @param {string} [extraText=""] - Human-readable extra text
 * @returns {{ code: number, data: Uint8Array }}
 */
export function buildEdeOption(infoCode, extraText = "") {
  const textBytes = TEXT_ENCODER.encode(extraText);
  const data = new Uint8Array(2 + textBytes.length);
  data[0] = (infoCode >> 8) & 0xff;
  data[1] = infoCode & 0xff;
  data.set(textBytes, 2);
  return { code: 15, data };
}

/**
 * Inject an EDE option into a DNS wire response. Adds to existing OPT record
 * or appends a new one. Does not duplicate if an EDE option already exists.
 *
 * @param {Uint8Array} buf - DNS wire response
 * @param {number} infoCode - EDE info code
 * @param {string} [extraText=""] - Extra text for the EDE option
 * @returns {Uint8Array}
 */
export function injectEdeToResponse(buf, infoCode, extraText = "") {
  if (!buf || buf.length < 12) return buf;
  const edeOpt = buildEdeOption(infoCode, extraText);
  const opt = parseOpt(buf);
  if (opt) {
    // Don't add a duplicate EDE
    if (opt.options.some(o => o.code === 15)) return buf;
    const newOpts = [...opt.options, edeOpt];
    return replaceOpt(buf, opt, buildOptRecord(opt.doBit, newOpts));
  }
  return appendOpt(buf, buildOptRecord(false, [edeOpt]));
}

// ---------------------------------------------------------------------------
// Blocked response builders
// ---------------------------------------------------------------------------

/**
 * Build a DNS wire response for a blocked domain.
 *
 * Modes:
 *   "null"      - NOERROR with A=0.0.0.0 / AAAA=:: (Pi-hole NULL mode)
 *   "nxdomain"  - NXDOMAIN (rcode=3) with empty answer, no authority
 *   "nodata"    - NOERROR with empty answer section
 *   "refused"   - REFUSED (rcode=5)
 *
 * @param {Uint8Array} queryBuf - Original DNS wire query (for ID and question copy)
 * @param {string} mode - Blocking mode
 * @param {object} [opts] - Optional: { edeText }
 * @returns {Uint8Array}
 */
export function buildBlockedResponse(queryBuf, mode, opts = {}) {
  if (!queryBuf || queryBuf.length < 12) return queryBuf;

  const queryInfo = extractQueryNameType(queryBuf);
  const qtype = queryInfo ? queryInfo.qtype : 1;

  // Extract question section from query for inclusion in response
  let qdcount = (queryBuf[4] << 8) | queryBuf[5];
  let qEnd = 12;
  for (let q = 0; q < qdcount; q++) { qEnd = skipName(queryBuf, qEnd); qEnd += 4; }
  // subarray clamps silently, so a truncated question would be emitted with
  // QDCOUNT still claiming a full one -- and the answer's 0xc00c owner-name
  // pointer would then run off the end of the question into the answer itself.
  if (qEnd > queryBuf.length) { qdcount = 0; qEnd = 12; }
  const questionSection = queryBuf.subarray(12, qEnd);

  let rcode = 0;
  let answerSection = new Uint8Array(0);
  let ancount = 0;

  switch (mode) {
    case "nxdomain":
      rcode = 3;
      break;
    case "nodata":
      rcode = 0;
      break;
    case "refused":
      rcode = 5;
      break;
    case "null":
    default:
      rcode = 0;
      // The synthesised answer names itself with a 0xc00c pointer to the
      // question, so without a question there is nothing valid to point at.
      if (qdcount === 0) break;
      // Generate A=0.0.0.0 or AAAA=:: depending on query type
      if (qtype === 28) {
        // AAAA response: ::
        answerSection = new Uint8Array(2 + 10 + 16);
        let w = 0;
        answerSection[w++] = 0xc0; answerSection[w++] = 0x0c; // pointer to question name
        answerSection[w++] = 0x00; answerSection[w++] = 0x1c; // TYPE AAAA
        answerSection[w++] = 0x00; answerSection[w++] = 0x01; // CLASS IN
        answerSection[w++] = 0x00; answerSection[w++] = 0x00;
        answerSection[w++] = 0x00; answerSection[w++] = 0x00; // TTL=0; stamped by setTtlWire at egress
        answerSection[w++] = 0x00; answerSection[w++] = 0x10; // RDLENGTH=16
        // 16 zero bytes for ::
        ancount = 1;
      } else if (qtype === 1) {
        // A response: 0.0.0.0
        answerSection = new Uint8Array(2 + 10 + 4);
        let w = 0;
        answerSection[w++] = 0xc0; answerSection[w++] = 0x0c; // pointer to question name
        answerSection[w++] = 0x00; answerSection[w++] = 0x01; // TYPE A
        answerSection[w++] = 0x00; answerSection[w++] = 0x01; // CLASS IN
        answerSection[w++] = 0x00; answerSection[w++] = 0x00;
        answerSection[w++] = 0x00; answerSection[w++] = 0x00; // TTL=0; stamped by setTtlWire at egress
        answerSection[w++] = 0x00; answerSection[w++] = 0x04; // RDLENGTH=4
        // 4 zero bytes for 0.0.0.0
        ancount = 1;
      }
      // For other query types in null mode, return empty answer (NODATA-like)
      break;
  }

  // Build the response
  const headerSize = 12;
  const buf = new Uint8Array(headerSize + questionSection.length + answerSection.length);
  // Header
  buf[0] = queryBuf[0]; buf[1] = queryBuf[1]; // copy DNS ID
  // RFC 1035 S4.1.1: OPCODE and RD bits MUST be copied from the request into the response.
  // RFC 4035 S3.1.6: CD bit MUST be copied from the request into the response.
  buf[2] = 0x80 | (queryBuf[2] & 0x79); // QR=1, OPCODE+RD mirrored from query
  buf[3] = 0x80 | (queryBuf[3] & 0x10) | (rcode & 0x0f); // RA=1, CD mirrored, rcode
  buf[4] = (qdcount >> 8) & 0xff; buf[5] = qdcount & 0xff;
  buf[6] = (ancount >> 8) & 0xff; buf[7] = ancount & 0xff;
  buf[8] = 0x00; buf[9] = 0x00; // NSCOUNT=0
  buf[10] = 0x00; buf[11] = 0x00; // ARCOUNT=0

  buf.set(questionSection, headerSize);
  if (answerSection.length > 0) {
    buf.set(answerSection, headerSize + questionSection.length);
  }

  // Inject EDE if requested
  if (opts.edeText) {
    return injectEdeToResponse(buf, 15, opts.edeText); // 15 = Blocked
  }
  return buf;
}
