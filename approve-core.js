"use strict";
export const ENVELOPE_VERSION = "junia-approve-envelope/1";
export const RETURN_VERSION = "junia-approve-return/1";
export const CHALLENGE_VERSION = "junia-passkey-challenge/1.0";
export const PASTE_PREFIX = "JUNIA-APPROVE:";
export const SENDDATA_MAX = 4096;
export const b64u = (buf) => {
  const u = buf instanceof Uint8Array ? buf : new Uint8Array(buf);
  let s = "";
  for (let i = 0; i < u.length; i += 32768) s += String.fromCharCode(...u.subarray(i, i + 32768));
  return btoa(s).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
};
export const unb64u = (s) => {
  if (!/^[A-Za-z0-9_-]*$/.test(s)) throw new Error("not base64url");
  return Uint8Array.from(atob(s.replace(/-/g, "+").replace(/_/g, "/") + "=".repeat((4 - s.length % 4) % 4)), (c) => c.charCodeAt(0));
};
export function canonicalJson(v) {
  if (v === null || v === void 0) return "null";
  if (typeof v === "boolean") return v ? "true" : "false";
  if (typeof v === "number") {
    if (!Number.isInteger(v) || !Number.isSafeInteger(v)) throw new Error("non-integer number in envelope");
    return String(v);
  }
  if (typeof v === "string") return JSON.stringify(v);
  if (Array.isArray(v)) return "[" + v.map(canonicalJson).join(",") + "]";
  if (typeof v === "object") {
    return "{" + Object.keys(v).sort().map((k) => JSON.stringify(k) + ":" + canonicalJson(v[k])).join(",") + "}";
  }
  throw new Error("not JSON");
}
const enc = new TextEncoder();
export async function sha256(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}
export const hex = (u) => Array.from(u, (b) => b.toString(16).padStart(2, "0")).join("");
export async function contentHash(v) {
  return hex(await sha256(enc.encode(canonicalJson(v))));
}
export async function challengeOf(statement, ceremonyId, displayHash, authorityKeyId) {
  const sd = await contentHash(statement);
  return b64u(await sha256(enc.encode(canonicalJson({ schemaVersion: CHALLENGE_VERSION, statementDigest: sd, ceremonyId, displayHash, authorityKeyId }))));
}
export async function decodeEnvelope(s) {
  const ds = new DecompressionStream("deflate-raw");
  const stream = new Blob([unb64u(s)]).stream().pipeThrough(ds);
  const text = await new Response(stream).text();
  if (text.length > 65536) throw new Error("ENVELOPE_TOO_LARGE");
  const env = JSON.parse(text);
  if (!env || env.v !== ENVELOPE_VERSION) throw new Error("ENVELOPE_VERSION");
  return env;
}
export async function verifyEnvelope(env, nowMs, pageHost) {
  try {
    if (typeof env.st !== "object" || typeof env.d !== "object" || !/^cer-[0-9a-f]{32}$/.test(env.cer) || !/^[A-Za-z0-9_-]{1,2048}$/.test(env.ch)) {
      return { ok: false, code: "ENVELOPE_MALFORMED" };
    }
    if (pageHost !== void 0 && env.rp !== pageHost) return { ok: false, code: "ENVELOPE_WRONG_SITE" };
    const dh = await contentHash(env.d);
    const expected = await challengeOf(env.st, env.cer, dh, env.akid);
    if (expected !== env.ch) return { ok: false, code: "ENVELOPE_CONTENT_MISMATCH" };
    const facts = Object.fromEntries((env.d.facts || []).filter((r) => Array.isArray(r) && r.length === 2));
    const sd = await contentHash(env.st);
    const fp = sd.slice(0, 24).match(/.{4}/g).join(" ");
    if (facts["Approval id"] !== env.st.approvalId || env.d.fingerprint !== fp) return { ok: false, code: "ENVELOPE_CONTENT_MISMATCH" };
    if (nowMs !== void 0 && nowMs > Number(env.exp || 0)) return { ok: false, code: "ENVELOPE_EXPIRED" };
    return { ok: true, code: "ENVELOPE_OK" };
  } catch (e) {
    return { ok: false, code: "ENVELOPE_MALFORMED" };
  }
}
export function buildReturn(kind, env, assertion) {
  const body = { v: RETURN_VERSION, k: kind, cer: env.cer, aid: env.st.approvalId };
  if (assertion) body.a = assertion;
  const s = JSON.stringify(body);
  if (enc.encode(s).length > SENDDATA_MAX) throw new Error("RETURN_TOO_LARGE");
  return s;
}
export const pasteText = (returnJson) => PASTE_PREFIX + b64u(enc.encode(returnJson));
const WORDING = [["Windows Hello 1회", "휴대폰 패스키(Face ID·Touch ID) 1회"], ["one Windows Hello", "one phone passkey (Face ID / Touch ID)"], ["Windows Hello", "Face ID / Touch ID"]];
export const deviceNeutral = (t) => WORDING.reduce((s, [a, b]) => s.split(a).join(b), String(t));
export function envelopeParam(hash) {
  for (const part of String(hash || "").replace(/^#/, "").split("&")) {
    if (part.startsWith("e=")) return part.slice(2);
  }
  return "";
}
const INAPP_RE = /Telegram|FBAN|FBAV|Instagram|Line\/|KAKAOTALK|NAVER\(inapp|DaumApps|Twitter|GSA\/|WhatsApp/i;
const OTHER_IOS_BROWSER_RE = /CriOS|FxiOS|EdgiOS|OPiOS|YaBrowser|DuckDuckGo|Brave/;
export function browserContext({ ua = "", hash = "", hasTgProxy = false } = {}) {
  const ios = /iPhone|iPad|iPod/.test(ua) || /Macintosh/.test(ua) && /Mobile\//.test(ua);
  if (hasTgProxy || /(^|[#&])tgWebApp(Data|Version|Platform)=/.test(String(hash))) return { kind: "telegram_miniapp", ios, reason: "telegram-webview" };
  if (!ios) return { kind: "other", ios, reason: "not-ios" };
  if (INAPP_RE.test(ua)) return { kind: "inapp", ios, reason: "app-token-in-ua" };
  if (OTHER_IOS_BROWSER_RE.test(ua)) return { kind: "ios_browser", ios, reason: "ios-browser" };
  if (/Version\/[\d.]+/.test(ua) && /Safari\//.test(ua)) return { kind: "safari", ios, reason: "safari-ua" };
  return { kind: "inapp", ios, reason: "webview-ua-without-safari-token" };
}
export const FAST_FAIL_MS = 1500;
export function classifyWebauthnError(name, elapsedMs, kind) {
  if (name === "NotAllowedError") {
    if (kind === "inapp" || kind === "telegram_miniapp" || elapsedMs < FAST_FAIL_MS) return "open_in_safari";
    return "cancelled";
  }
  if (name === "SecurityError") return "wrong_site";
  if (name === "InvalidStateError") return "already_registered";
  return "error";
}
export function safariHandoffUrl(href) {
  const s = String(href || "");
  return s.startsWith("https://") ? "x-safari-" + s : "";
}
const BOT_RE = /^[A-Za-z][A-Za-z0-9_]{3,31}$/;
export function returnLinks(bot, text) {
  if (!BOT_RE.test(String(bot || ""))) return { tme: "", tg: "" };
  const t = encodeURIComponent(String(text || ""));
  return { tme: `https://t.me/${bot}` + (t ? `?text=${t}` : ""), tg: `tg://resolve?domain=${bot}` + (t ? `&text=${t}` : "") };
}
export function fragParam(hash, key) {
  for (const part of String(hash || "").replace(/^#/, "").split("&")) {
    if (part.startsWith(key + "=")) return part.slice(key.length + 1);
  }
  return "";
}
export const ENROLL_VERSION = "junia-enroll-envelope/1";
export const ENROLL_RETURN_VERSION = "junia-enroll-return/1";
export const ENROLL_PREFIX = "JUNIA-ENROLL:";
export async function decodeEnroll(s) {
  const ds = new DecompressionStream("deflate-raw");
  const text = await new Response(new Blob([unb64u(s)]).stream().pipeThrough(ds)).text();
  if (text.length > 65536) throw new Error("ENVELOPE_TOO_LARGE");
  const env = JSON.parse(text);
  if (!env || env.v !== ENROLL_VERSION) throw new Error("ENVELOPE_VERSION");
  return env;
}
export function verifyEnroll(env, nowMs, pageHost) {
  try {
    const pk = env.pk;
    if (!/^[0-9a-f]{16}$/.test(env.sid) || typeof pk !== "object" || !pk.rp || !pk.user || !/^[A-Za-z0-9_-]{16,128}$/.test(pk.challenge)) {
      return { ok: false, code: "ENVELOPE_MALFORMED" };
    }
    if (pageHost !== void 0 && (env.rp !== pageHost || pk.rp.id !== pageHost)) return { ok: false, code: "ENVELOPE_WRONG_SITE" };
    const sel = pk.authenticatorSelection || {};
    if (sel.userVerification !== "required") return { ok: false, code: "ENVELOPE_UV_NOT_REQUIRED" };
    if (nowMs !== void 0 && nowMs > Number(env.exp || 0)) return { ok: false, code: "ENVELOPE_EXPIRED" };
    return { ok: true, code: "ENVELOPE_OK" };
  } catch (e) {
    return { ok: false, code: "ENVELOPE_MALFORMED" };
  }
}
export function creationOptions(pk) {
  return {
    rp: pk.rp,
    user: { id: unb64u(pk.user.id), name: pk.user.name, displayName: pk.user.displayName },
    challenge: unb64u(pk.challenge),
    pubKeyCredParams: pk.pubKeyCredParams,
    authenticatorSelection: pk.authenticatorSelection,
    attestation: pk.attestation || "none",
    timeout: pk.timeout || 12e4,
    excludeCredentials: (pk.excludeCredentials || []).map((c) => ({ type: "public-key", id: unb64u(c.id) }))
  };
}
export function buildEnrollReturn(env, attestationObject, clientDataJSON) {
  const s = JSON.stringify({ v: ENROLL_RETURN_VERSION, sid: env.sid, ao: attestationObject, cdj: clientDataJSON });
  if (enc.encode(s).length > SENDDATA_MAX) throw new Error("RETURN_TOO_LARGE");
  return s;
}
export const enrollPasteText = (returnJson) => ENROLL_PREFIX + b64u(enc.encode(returnJson));
