import * as C from "./approve-core.js";
const $ = (id) => document.getElementById(id);
const show = (id, on = true) => {
  $(id).hidden = !on;
};
const say = (text, ok) => {
  const el = $("result");
  el.textContent = text;
  el.className = ok ? "ok" : "bad";
};
function tgPost(eventType, eventData) {
  const data = JSON.stringify(eventData || {});
  if (window.TelegramWebviewProxy && window.TelegramWebviewProxy.postEvent) {
    window.TelegramWebviewProxy.postEvent(eventType, data);
    return true;
  }
  if (window.external && "notify" in window.external) {
    window.external.notify(JSON.stringify({ eventType, eventData }));
    return true;
  }
  if (window.parent !== window) {
    window.parent.postMessage(JSON.stringify({ eventType, eventData }), "https://web.telegram.org");
    return true;
  }
  return false;
}
const ctx = C.browserContext({ ua: navigator.userAgent, hash: location.hash, hasTgProxy: !!window.TelegramWebviewProxy });
let env = null;
let mode = "";
function row(k, v) {
  const tr = document.createElement("tr");
  const a = document.createElement("td");
  a.className = "k";
  a.textContent = k;
  const b = document.createElement("td");
  b.textContent = C.deviceNeutral(v);
  tr.append(a, b);
  return tr;
}
function diag(extra) {
  $("diag").textContent = `context=${ctx.kind} (${ctx.reason}) ios=${ctx.ios} mode=${mode}${extra ? " " + extra : ""}
UA=${navigator.userAgent}`;
}
function safariStep() {
  const href = C.safariHandoffUrl(location.href);
  $("safari-link").href = href || location.href;
  show("state-pending", false);
  show("state-enroll", false);
  show("state-safari");
  if (ctx.kind === "telegram_miniapp") $("safari-link").addEventListener("click", (e) => {
    if (tgPost("web_app_open_link", { url: location.href })) e.preventDefault();
  }, { once: true });
}
async function deliverText(text, returnJson) {
  if (ctx.kind === "telegram_miniapp" && tgPost("web_app_data_send", { data: returnJson })) return "telegram";
  if (env.mb) {
    try {
      const r = await fetch(env.mb, { method: "POST", mode: "cors", credentials: "omit", headers: { "content-type": "text/plain" }, body: returnJson });
      if (r.ok) return "mailbox";
    } catch (e) {
    }
  }
  $("paste").value = text;
  const links = C.returnLinks(env.bot, text);
  if (links.tme) $("tg-draft").href = links.tme;
  show("fallback");
  try {
    await navigator.clipboard.writeText(text);
  } catch (e) {
  }
  return "paste";
}
const deliver = (kind, assertion) => {
  const ret = C.buildReturn(kind, env, assertion);
  return deliverText(C.pasteText(ret), ret);
};
function failed(e, t0) {
  const how = C.classifyWebauthnError(e && e.name, performance.now() - t0, ctx.kind);
  diag(`lastError=${e && e.name} after=${Math.round(performance.now() - t0)}ms -> ${how}`);
  if (how === "open_in_safari") {
    say("이 화면에서는 Face ID를 쓸 수 없습니다. Safari로 열어 주세요. 아무것도 승인되지 않았습니다. / Face ID is not available here - open in Safari. Nothing was approved.", false);
    safariStep();
    return;
  }
  const msg = {
    cancelled: "Face ID가 취소되었습니다. 다시 누를 수 있습니다. / Cancelled - you can try again.",
    wrong_site: "이 사이트에서는 이 패스키를 쓸 수 없습니다. / This passkey is not for this site.",
    already_registered: "이 iPhone에는 이미 등록된 패스키가 있습니다. / A passkey is already registered on this iPhone."
  }[how];
  say("승인되지 않음 / NOT approved: " + (msg || e && e.message || "error"), false);
}
async function mainApprove(p) {
  mode = "approve";
  try {
    env = await C.decodeEnvelope(p);
  } catch (e) {
    show("state-bad");
    return;
  }
  const v = await C.verifyEnvelope(env, Date.now(), location.hostname);
  if (!v.ok && v.code !== "ENVELOPE_EXPIRED") {
    $("bad-code").textContent = v.code;
    show("state-bad");
    return;
  }
  $("title").textContent = C.deviceNeutral(env.d.title || "");
  const t = $("facts");
  for (const r of env.d.actionFacts || []) if (Array.isArray(r)) t.append(row(r[0], r[1]));
  for (const r of env.d.facts || []) if (Array.isArray(r)) t.append(row(r[0], r[1]));
  $("fp").textContent = env.d.fingerprint;
  if (env.t) $("tenant").textContent = env.t;
  if (env.d.residualRisk) show("risk");
  show("content");
  if (v.code === "ENVELOPE_EXPIRED") {
    const l = C.returnLinks(env.bot, "");
    if (l.tme) $("back-to-bot").href = l.tme;
    show("state-expired");
    return;
  }
  if (ctx.kind === "inapp") {
    safariStep();
    return;
  }
  show("state-pending");
}
async function mainEnroll(p) {
  mode = "enroll";
  try {
    env = await C.decodeEnroll(p);
  } catch (e) {
    show("state-bad");
    return;
  }
  const v = C.verifyEnroll(env, Date.now(), location.hostname);
  if (!v.ok) {
    $("bad-code").textContent = v.code;
    show("state-bad");
    return;
  }
  $("title").textContent = `패스키 등록 / Register a passkey: ${env.pk.rp.name}`;
  $("content-lead").textContent = "이 iPhone에 아래 사이트용 패스키를 만듭니다. PC 화면에 같은 확인 번호가 보여야 합니다. / Creates a passkey for this site on this iPhone; the PC shows the same check number.";
  const t = $("facts");
  t.append(row("Site (rpId)", env.rp), row("User", env.pk.user.name), row("Device label", env.label || ""));
  $("fp").textContent = env.sid.match(/.{4}/g).join(" ");
  if (env.t) $("tenant").textContent = env.t;
  show("content");
  if (ctx.kind === "inapp") {
    safariStep();
    return;
  }
  show("state-enroll");
}
$("approve").addEventListener("click", async () => {
  $("approve").disabled = true;
  const t0 = performance.now();
  try {
    const v = await C.verifyEnvelope(env, Date.now(), location.hostname);
    if (!v.ok) throw new Error(v.code);
    const a = await navigator.credentials.get({ publicKey: {
      challenge: C.unb64u(env.ch),
      rpId: env.rp,
      userVerification: "required",
      timeout: 9e4,
      allowCredentials: env.allow.map((id) => ({ type: "public-key", id: C.unb64u(id) }))
    } });
    const how = await deliver("assert", {
      credentialId: C.b64u(a.rawId),
      authenticatorData: C.b64u(a.response.authenticatorData),
      clientDataJSON: C.b64u(a.response.clientDataJSON),
      signature: C.b64u(a.response.signature)
    });
    show("state-pending", false);
    say(how === "paste" ? "Face ID 서명 완료. 아직 승인 전입니다: 아래 버튼으로 텔레그램에 보내면 PC가 확인합니다. / Signed - not approved yet: send it via Telegram below; your PC verifies it." : "서명을 PC로 보냈습니다. PC의 승인 서비스가 확인합니다. / Sent to your PC for verification.", true);
  } catch (e) {
    failed(e, t0);
    $("approve").disabled = false;
  }
});
$("enroll").addEventListener("click", async () => {
  $("enroll").disabled = true;
  const t0 = performance.now();
  try {
    const c = await navigator.credentials.create({ publicKey: C.creationOptions(env.pk) });
    const ret = C.buildEnrollReturn(env, C.b64u(c.response.attestationObject), C.b64u(c.response.clientDataJSON));
    await deliverText(C.enrollPasteText(ret), ret);
    show("state-enroll", false);
    say("패스키를 만들었습니다. 텔레그램에 보낸 뒤 PC 화면에서 확인하세요. / Passkey created - send it via Telegram, then confirm on the PC.", true);
  } catch (e) {
    failed(e, t0);
    $("enroll").disabled = false;
  }
});
$("reject").addEventListener("click", async () => {
  $("reject").disabled = true;
  await deliver("reject");
  show("state-pending", false);
  say("거절 문구를 준비했습니다 / Rejection prepared.", true);
});
$("try-here").addEventListener("click", (e) => {
  e.preventDefault();
  show("state-safari", false);
  show(mode === "enroll" ? "state-enroll" : "state-pending");
});
$("copy-link").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText(location.href);
    say("주소 복사됨 / Link copied", true);
  } catch (e) {
    say(location.href, true);
  }
});
$("copy").addEventListener("click", async () => {
  try {
    await navigator.clipboard.writeText($("paste").value);
    say("복사됨 / Copied", true);
  } catch (e) {
    $("paste").select();
  }
});
(async () => {
  if (location.protocol !== "https:") {
    $("bad-code").textContent = "HTTPS_REQUIRED";
    show("state-bad");
    diag();
    return;
  }
  const n = C.fragParam(location.hash, "n");
  const e = C.envelopeParam(location.hash);
  if (n) await mainEnroll(n);
  else if (e) await mainApprove(e);
  else show("state-empty");
  diag();
})();
