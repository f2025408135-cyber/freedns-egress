#!/usr/bin/env node
import fs from "node:fs";
import crypto from "node:crypto";

const PHASE = (process.env.PHASE || "probe").trim();
const PAYLOAD = (() => {
  try { return JSON.parse(Buffer.from((process.env.PAYLOAD_B64 || "").trim(), "base64").toString("utf8") || "{}"); }
  catch { return {}; }
})();
const OUT = "out";
fs.mkdirSync(OUT, { recursive: true });

const BASE = "https://freedns.afraid.org";
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/153.0.0.0 Safari/537.36";
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));

const jars = new Map();
function jar(name) { if (!jars.has(name)) jars.set(name, new Map()); return jars.get(name); }
function cookieHeader(name) { return [...jar(name).entries()].map(([k, v]) => k + "=" + v).join("; "); }
function storeCookies(name, res) {
  let list = [];
  try { list = res.headers.getSetCookie ? res.headers.getSetCookie() : []; } catch {}
  if (!list.length) { const raw = res.headers.get("set-cookie"); if (raw) list = [raw]; }
  for (const c of list) {
    const pair = (c.split(";")[0] || "").trim();
    const i = pair.indexOf("=");
    if (i > 0) jar(name).set(pair.slice(0, i).trim(), pair.slice(i + 1).trim());
  }
}

async function req(sess, url, opts = {}) {
  const headers = { "User-Agent": UA, "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8", ...(opts.headers || {}) };
  if (opts.cookies !== false) { const ch = cookieHeader(sess); if (ch && !headers["Cookie"]) headers["Cookie"] = ch; }
  const res = await fetch(url, {
    method: opts.method || "GET",
    headers,
    body: opts.body,
    redirect: opts.redirect || "follow",
    signal: AbortSignal.timeout(opts.timeout || 45000),
  });
  storeCookies(sess, res);
  const body = await res.text();
  return { status: res.status, url: res.url, server: res.headers.get("server") || "", ct: (res.headers.get("content-type") || "").split(";")[0], len: body.length, location: res.headers.get("location") || "", body };
}

async function reqBin(sess, url, opts = {}) {
  const headers = { "User-Agent": UA, "Accept": "image/avif,image/webp,image/apng,image/*,*/*;q=0.8", ...(opts.headers || {}) };
  const ch = cookieHeader(sess);
  if (ch) headers["Cookie"] = ch;
  const res = await fetch(url, { method: opts.method || "GET", headers, redirect: opts.redirect || "follow", signal: AbortSignal.timeout(opts.timeout || 45000) });
  storeCookies(sess, res);
  const buf = Buffer.from(await res.arrayBuffer());
  return { status: res.status, url: res.url, ct: (res.headers.get("content-type") || "").split(";")[0], buf };
}

function stripHtml(html) {
  return html
    .replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ")
    .replace(/<br\s*\/?>/gi, "\n").replace(/<\/(p|div|tr|li|h\d|table|form|td)>/gi, "\n")
    .replace(/<[^>]+>/g, " ")
    .replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/&quot;/g, '"').replace(/&#39;|&apos;/g, "'")
    .replace(/[ \t]+/g, " ").replace(/\n\s*\n+/g, "\n").trim();
}

function attrMap(tag) {
  const m = {};
  for (const a of tag.matchAll(/([a-zA-Z_:][\w:.-]*)\s*=\s*("([^"]*)"|'([^']*)'|([^\s>]+))/g)) m[a[1].toLowerCase()] = a[3] ?? a[4] ?? a[5] ?? "";
  return m;
}

function dumpForms(html) {
  const forms = [];
  const fre = /<form\b[^>]*>[\s\S]*?<\/form>/gi;
  let mm;
  while ((mm = fre.exec(html))) {
    const block = mm[0];
    const open = block.match(/<form\b[^>]*>/i)[0];
    const fa = attrMap(open);
    const fields = [];
    for (const inp of block.matchAll(/<input\b[^>]*>/gi)) {
      const a = attrMap(inp[0]);
      fields.push({ kind: "input", name: a.name || "", type: (a.type || "text").toLowerCase(), value: a.value !== undefined ? a.value : "", checked: "checked" in a });
    }
    for (const sel of block.matchAll(/<select\b[^>]*>[\s\S]*?(?:<\/select>|$)/gi)) {
      const a = attrMap(sel[0].match(/<select\b[^>]*>/i)[0]);
      const opts = [];
      let total = 0;
      for (const o of sel[0].matchAll(/<option\b([^>]*)>([\s\S]*?)(?:<\/option>|(?=<option|$))/gi)) {
        total++;
        const oa = attrMap("<option " + o[1] + ">");
        const txt = o[2].replace(/<[^>]+>/g, " ").replace(/\s+/g, " ").trim();
        if (opts.length < 250) opts.push({ value: oa.value !== undefined ? oa.value : "", text: txt.slice(0, 70), selected: "selected" in oa });
      }
      fields.push({ kind: "select", name: a.name || "", totalOptions: total, options: opts, truncated: total > 250 });
    }
    for (const ta of block.matchAll(/<textarea\b[^>]*>([\s\S]*?)(?:<\/textarea>|$)/gi)) {
      const a = attrMap(ta[0].match(/<textarea\b[^>]*>/i)[0]);
      fields.push({ kind: "textarea", name: a.name || "", sample: ta[1].replace(/<[^>]+>/g, "").trim().slice(0, 120) });
    }
    forms.push({ action: fa.action || "", method: (fa.method || "get").toLowerCase(), id: fa.id || "", name: fa.name || "", fields });
    if (forms.length >= 20) break;
  }
  return forms;
}

function captchaScan(html) {
  const hits = [];
  const rx = /captcha|security code|security question|human|robot|bot\b|anti-?spam|challenge|what is|how many|which (color|number|word)|solve|sum of|interest|verification/i;
  const lines = html.split(/\r?\n/);
  for (let i = 0; i < lines.length; i++) {
    if (rx.test(lines[i])) hits.push({ line: i + 1, text: lines[i].replace(/\s+/g, " ").trim().slice(0, 300) });
    if (hits.length >= 50) break;
  }
  return hits;
}

function findOption(html, domainName) {
  const esc = domainName.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const re = new RegExp("<option[^>]*value\\s*=\\s*[\"']?([^\"'>\\s]+)[\"']?[^>]*>\\s*([^<]*" + esc + "[^<]*)<\\/option>", "i");
  const m = html.match(re);
  return m ? { value: m[1], text: m[2].trim().slice(0, 90) } : null;
}

function findMathQuestion(html) {
  const text = stripHtml(html);
  const anchors = [...text.matchAll(/what is|how much|how many|solve|calculate|=|\?/gi)];
  for (const an of anchors) {
    const seg = text.slice(Math.max(0, an.index - 40), an.index + 160);
    const m = seg.match(/(\d{1,3})\s*([+\-*x×])\s*(\d{1,3})/);
    if (m) {
      const a = parseInt(m[1], 10), op = m[2], b = parseInt(m[3], 10);
      let answer;
      if (op === "+") answer = a + b; else if (op === "-") answer = a - b; else answer = a * b;
      return { a, op, b, answer, context: seg.replace(/\s+/g, " ").trim().slice(0, 220) };
    }
  }
  return null;
}

function findCaptchaFieldName(form) {
  const f = form.fields.find((x) => x.kind === "input" && /captcha|security|question|answer|human|code/i.test(x.name));
  return f ? f.name : null;
}

function redact(s, secret) {
  if (!secret) return s;
  return s.split(secret).join("***").split(encodeURIComponent(secret)).join("***");
}

function summary(obj) { console.log("SUMMARY " + JSON.stringify(obj)); }

const EMAILNATOR_H = {
  "Content-Type": "application/json",
  "Accept": "application/json",
  "User-Agent": UA,
  "X-Requested-With": "XMLHttpRequest",
  "Origin": "https://www.emailnator.com",
  "Referer": "https://www.emailnator.com/inbox",
};

async function emailnatorList(email) {
  const r = await fetch("https://www.emailnator.com/api/message-list", { method: "POST", headers: EMAILNATOR_H, body: JSON.stringify({ email, limit: 20 }), signal: AbortSignal.timeout(30000) });
  const t = await r.text();
  let j = null; try { j = JSON.parse(t); } catch {}
  return { status: r.status, json: j, raw: t.slice(0, 400) };
}

async function emailnatorBody(id) {
  const r = await fetch("https://www.emailnator.com/api/message/" + encodeURIComponent(id), { headers: { ...EMAILNATOR_H, "Content-Type": undefined }, signal: AbortSignal.timeout(30000) });
  const t = await r.text();
  let j = null; try { j = JSON.parse(t); } catch {}
  return { status: r.status, json: j, raw: t.slice(0, 800) };
}

async function pollEmailForLink(email, minutes) {
  const deadline = Date.now() + (minutes || 20) * 60000;
  while (Date.now() < deadline) {
    try {
      const el = await emailnatorList(email);
      const msgs = (el.json && el.json.messages) || [];
      console.log("EMAIL_POLL " + JSON.stringify({ status: el.status, count: msgs.length, subjects: msgs.slice(0, 10).map((m) => ((m.from || "").slice(0, 50)) + " | " + ((m.subject || "").slice(0, 70))) }));
      const hit = msgs.find((m) => /afraid|freedns/i.test((m.from || "") + " " + (m.subject || "")));
      if (hit) {
        const b = await emailnatorBody(hit.id);
        const html = String((b.json && (b.json.content || b.json.html || b.json.body)) || b.raw || "");
        const links = [...html.matchAll(/https?:\/\/[^\s"'<>)\]]+/g)].map((x) => x[0]).map((u) => u.replace(/&amp;/g, "&"));
        const al = links.filter((u) => /afraid\.org/i.test(u));
        fs.writeFileSync(OUT + "/activation-mail.json", JSON.stringify({ subject: hit.subject, from: hit.from, links }, null, 2));
        console.log("ACTIVATION_MAIL " + JSON.stringify({ subject: hit.subject, from: hit.from, links: al.slice(0, 10) }));
        return al.find((u) => /activ|verify|zc\.php|confirm|step/i.test(u)) || al[0] || null;
      }
    } catch (e) { console.log("EMAIL_POLL_ERR " + e.message); }
    await sleep(30000);
  }
  return null;
}

async function loginAndHosts({ username, password }) {
  const lp = await req("session", BASE + "/zc.php?step=2");
  const forms = dumpForms(lp.body);
  const lf = forms.find((x) => x.fields.some((y) => /pass/i.test(y.name))) || forms[0];
  const action = new URL((lf && lf.action) || "/zc.php?step=2", BASE + "/zc.php").toString();
  const params = new URLSearchParams();
  for (const ff of ((lf && lf.fields) || [])) {
    if (ff.kind !== "input" || ["submit", "button", "image", "reset"].includes(ff.type)) continue;
    if (!ff.name) continue;
    if (ff.type === "checkbox" || ff.type === "radio") { if (ff.checked) params.set(ff.name, ff.value || "on"); continue; }
    params.set(ff.name, ff.value || "");
  }
  let setU = false, setP = false;
  for (const ff of ((lf && lf.fields) || [])) {
    if (ff.kind !== "input") continue;
    if (/user|email|login/i.test(ff.name) && params.has(ff.name)) { params.set(ff.name, username); setU = true; }
    if (/pass/i.test(ff.name) && params.has(ff.name)) { params.set(ff.name, password); setP = true; }
  }
  if (!setU) params.set("username", username);
  if (!setP) params.set("password", password);
  const post = await req("session", action, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Referer": BASE + "/zc.php?step=2" }, body: params.toString() });
  fs.writeFileSync(OUT + "/login-after.html", post.body);
  console.log("LOGIN_POST " + JSON.stringify({ status: post.status, url: post.url, loc: post.location, len: post.len }));
  console.log("LOGIN_TEXT " + stripHtml(post.body).slice(0, 1000));

  const check = await req("session", BASE + "/subdomain/");
  fs.writeFileSync(OUT + "/subdomain.html", check.body);
  const ct = stripHtml(check.body);
  const loggedIn = /add a subdomain|logout|log out|my account|domains you|subdomains/i.test(ct);
  console.log("LOGGED_IN_GUESS " + loggedIn);
  const forms2 = dumpForms(check.body);
  console.log("SUBDOMAIN_FORMS " + JSON.stringify(forms2, null, 2));
  const addForm = forms2.find((x) => x.fields.some((y) => /^subdomain$/i.test(y.name)) && x.fields.some((y) => /type/i.test(y.name))) ||
    forms2.find((x) => x.fields.some((y) => /address|destination|dest/i.test(y.name)));
  console.log("ADD_FORM " + (addForm ? JSON.stringify({ action: addForm.action, method: addForm.method, id: addForm.id }) : "NOT_FOUND"));
  if (!addForm) { summary({ phase: "login_hosts", ok: false, reason: "no-add-form", loggedIn }); return; }
  await createHosts(addForm, check.body);
}

async function createHosts(addForm, listingHtml) {
  const p = PAYLOAD;
  const action = new URL(addForm.action || "/subdomain/", BASE + (addForm.action && addForm.action.startsWith("/") ? "" : "/subdomain/")).toString();
  const forwardTo = p.forward_to || "anonysusarchiver@gmail.com";
  const recordSpecs = [
    { type: "MX", address: "0 mx1.forwardemail.net" },
    { type: "MX", address: "0 mx2.forwardemail.net" },
    { type: "TXT", address: "forward-email=" + forwardTo },
    { type: "TXT", address: "v=spf1 a include:spf.forwardemail.net -all" },
  ];
  const results = [];
  for (const d of p.domains || []) {
    const opt = (p.blind_domain_id && null) || findOption(listingHtml, d.name);
    const domainId = (opt && opt.value) || d.id || null;
    console.log("DOMAIN_OPT " + JSON.stringify({ name: d.name, found: opt, used: domainId }));
    if (!domainId) { console.log("DOMAIN_NO_ID " + d.name); results.push({ domain: d.name, error: "no-domain-id" }); continue; }
    for (const spec of recordSpecs) {
      const params = new URLSearchParams();
      for (const ff of addForm.fields) {
        if (!ff.name) continue;
        if (ff.kind === "input") {
          if (["submit", "button", "image", "reset", "checkbox", "radio"].includes(ff.type)) continue;
          params.set(ff.name, ff.value || "");
        } else if (ff.kind === "select") {
          const sel = ff.options.find((o) => o.selected) || ff.options[0];
          if (sel) params.set(ff.name, sel.value);
        } else if (ff.kind === "textarea" && ff.sample) {
          params.set(ff.name, ff.sample);
        }
      }
      for (const ff of addForm.fields) {
        if (!ff.name) continue;
        const n = ff.name.toLowerCase();
        if (/^(type|recordtype|record_type)$/.test(n) || n === "type") params.set(ff.name, spec.type);
        else if (/subdomain|^host$|^name$/.test(n)) params.set(ff.name, d.host || "mail");
        else if (/domain/.test(n) && !/^domain$/.test(n)) params.set(ff.name, domainId);
        else if (/^domain$/.test(n)) params.set(ff.name, domainId);
        else if (/address|destination|dest|content|^value$|target/.test(n)) params.set(ff.name, spec.address);
      }
      await sleep(1600);
      const label = (d.host || "mail") + "." + d.name;
      try {
        const post = await req("session", action, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Referer": BASE + "/subdomain/" }, body: params.toString() });
        const text = stripHtml(post.body);
        const bad = /you have reached|maximum|limit|error|already (taken|exists|in use|registered)|invalid|denied|not allowed|banned|abuse/i.test(text);
        const flag = bad ? "ERR" : "OK?";
        console.log("RECORD_POST " + JSON.stringify({ label, type: spec.type, address: spec.address, status: post.status, url: post.url, flag }));
        console.log("RECORD_TEXT " + text.slice(0, 400));
        fs.appendFileSync(OUT + "/records.log", JSON.stringify({ label, type: spec.type, address: spec.address, status: post.status, url: post.url, flag, text: text.slice(0, 700) }) + "\n");
        results.push({ host: label, type: spec.type, address: spec.address, status: post.status, flag });
      } catch (e) {
        console.log("RECORD_ERR " + JSON.stringify({ label, type: spec.type, error: e.message }));
        results.push({ host: label, type: spec.type, error: e.message });
      }
    }
  }
  fs.writeFileSync(OUT + "/records-results.json", JSON.stringify(results, null, 2));
  await sleep(1200);
  const after = await req("session", BASE + "/subdomain/");
  fs.writeFileSync(OUT + "/subdomain-after.html", after.body);
  const at = stripHtml(after.body);
  for (const d of p.domains || []) {
    const label = (d.host || "mail") + "." + d.name;
    console.log("LISTING_HAS " + label + " = " + new RegExp(label.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i").test(at));
  }
  if (p.verify_after) await dohVerify((p.domains || []).map((d) => (d.host || "mail") + "." + d.name));
  summary({ phase: "hosts", ok: results.some((r) => r.flag === "OK?"), results });
}

async function dohVerify(hosts) {
  const results = {};
  for (const h of hosts) {
    results[h] = {};
    for (const t of ["MX", "TXT"]) {
      try {
        const r = await fetch("https://dns.google/resolve?name=" + encodeURIComponent(h) + "&type=" + t, { headers: { "Accept": "application/json", "User-Agent": UA }, signal: AbortSignal.timeout(20000) });
        const j = await r.json();
        results[h][t] = { status: j.Status, answer: (j.Answer || []).map((a) => a.data) };
        console.log("DOH " + h + " " + t + " " + JSON.stringify(results[h][t]));
      } catch (e) { results[h][t] = { error: e.message }; console.log("DOH_ERR " + h + " " + t + " " + e.message); }
    }
  }
  fs.writeFileSync(OUT + "/doh.json", JSON.stringify(results, null, 2));
  const ok = Object.values(results).some((v) => v.MX && v.MX.answer && v.MX.answer.some((a) => /forwardemail\.net/i.test(a)));
  summary({ phase: "verify", ok, results });
  return ok;
}

async function probe() {
  const out = { reach: null, signup: null, login: null, faq: null, emailnator: null };
  try {
    const home = await req("probe", BASE + "/");
    out.reach = { status: home.status, url: home.url, server: home.server, ct: home.ct, len: home.len };
    fs.writeFileSync(OUT + "/home.html", home.body);
    console.log("REACH " + JSON.stringify(out.reach));
    console.log("HOME_TITLE " + ((home.body.match(/<title[^>]*>([\s\S]*?)<\/title>/i) || [])[1] || "").trim().slice(0, 120));
    const links = [...home.body.matchAll(/href\s*=\s*"([^"]+)"/gi)].map((x) => x[1]).filter((h) => /faq|help|knowledge|support/i.test(h));
    console.log("HELP_LINKS " + JSON.stringify([...new Set(links)].slice(0, 12)));
  } catch (e) {
    out.reach = { error: e.message };
    console.log("REACH_ERROR " + e.message);
    summary({ phase: "probe", ok: false, reason: "unreachable", error: e.message });
    process.exitCode = 3;
    return;
  }
  try {
    const su = await req("probe", BASE + "/signup/");
    fs.writeFileSync(OUT + "/signup.html", su.body);
    out.signup = { status: su.status, url: su.url, len: su.len };
    console.log("SIGNUP_PAGE " + JSON.stringify(out.signup));
    console.log("SIGNUP_FORMS " + JSON.stringify(dumpForms(su.body), null, 2));
    console.log("SIGNUP_TEXT_BEGIN\n" + stripHtml(su.body).slice(0, 4500) + "\nSIGNUP_TEXT_END");
    console.log("CAPTCHA_HITS " + JSON.stringify(captchaScan(su.body), null, 2));
  } catch (e) { out.signup = { error: e.message }; console.log("SIGNUP_PAGE_ERROR " + e.message); }
  try {
    const lp = await req("probe", BASE + "/zc.php?step=2");
    fs.writeFileSync(OUT + "/login.html", lp.body);
    out.login = { status: lp.status, url: lp.url, len: lp.len };
    console.log("LOGIN_PAGE " + JSON.stringify(out.login));
    console.log("LOGIN_FORMS " + JSON.stringify(dumpForms(lp.body), null, 2));
    console.log("LOGIN_TEXT " + stripHtml(lp.body).slice(0, 900));
  } catch (e) { out.login = { error: e.message }; console.log("LOGIN_PAGE_ERROR " + e.message); }
  try {
    const faq = await req("probe", BASE + "/faq/");
    out.faq = { status: faq.status, len: faq.len };
    fs.writeFileSync(OUT + "/faq.html", faq.body);
    console.log("FAQ_PAGE " + JSON.stringify(out.faq));
    if (faq.status === 200) console.log("FAQ_TEXT " + stripHtml(faq.body).slice(0, 3000));
  } catch (e) { out.faq = { error: e.message }; }
  if (PAYLOAD.email) {
    try {
      const el = await emailnatorList(PAYLOAD.email);
      out.emailnator = { status: el.status, count: el.json && el.json.messages ? el.json.messages.length : null, raw: el.raw.slice(0, 160) };
      console.log("EMAILNATOR_RUNNER " + JSON.stringify(out.emailnator));
    } catch (e) { out.emailnator = { error: e.message }; console.log("EMAILNATOR_RUNNER_ERROR " + e.message); }
  }
  summary({ phase: "probe", ok: out.reach && out.reach.status === 200, out });
}

async function captcha() {
  const count = Math.max(1, Math.min(12, PAYLOAD.count || 1));
  const list = [];
  for (let i = 1; i <= count; i++) {
    const jarName = "cap" + i;
    const su = await req(jarName, BASE + "/signup/");
    if (i === 1) fs.writeFileSync(OUT + "/signup.html", su.body);
    const img = await reqBin(jarName, BASE + "/securimage/securimage_show.php");
    fs.writeFileSync(OUT + "/captcha-" + i + ".png", img.buf);
    if (i === 1) fs.writeFileSync(OUT + "/captcha.png", img.buf);
    const cookies = Object.fromEntries(jar(jarName).entries());
    fs.writeFileSync(OUT + "/cookies-" + i + ".json", JSON.stringify(cookies, null, 2));
    if (i === 1) fs.writeFileSync(OUT + "/cookies.json", JSON.stringify(cookies, null, 2));
    const rec = { i, status: img.status, ct: img.ct, bytes: img.buf.length, md5: crypto.createHash("md5").update(img.buf).digest("hex"), cookieNames: Object.keys(cookies) };
    console.log("CAPTCHA_IMG " + JSON.stringify(rec));
    list.push(rec);
    if (i < count) await sleep(1200);
  }
  summary({ phase: "captcha", ok: list.every((r) => r.status === 200 && r.bytes > 500), count, list });
}

async function signup() {
  const p = PAYLOAD;
  if (p.cookies) { for (const [k, v] of Object.entries(p.cookies)) jar("session").set(k, v); }
  let f = null;
  if (p.fixed_fields) {
    const names = ["firstname", "lastname", "username", "password", "password2", "email", "captcha_code", "PROCID", "TRANSPRE", "action"];
    f = { action: "/signup/?step=2", method: "post", id: "", name: "joinfrm", fields: names.map((n) => ({ kind: "input", name: n, type: "text", value: "" })) };
    console.log("SIGNUP_FIXED_FIELDS_MODE");
  } else {
    const su = await req("session", BASE + "/signup/");
    fs.writeFileSync(OUT + "/signup-before.html", su.body);
    console.log("SIGNUP_GET " + JSON.stringify({ status: su.status, len: su.len }));
    const forms = dumpForms(su.body);
    console.log("SIGNUP_FORMS " + JSON.stringify(forms, null, 2));
    f = forms.find((x) => x.fields.some((y) => /pass/i.test(y.name))) || forms[0];
  }
  if (!f) { console.log("NO_FORM"); summary({ phase: "signup", ok: false, reason: "no-form" }); process.exitCode = 1; return; }
  const action = new URL(f.action || "/signup/", BASE + "/signup/").toString();
  const params = new URLSearchParams();
  for (const ff of f.fields) {
    if (ff.kind !== "input" || !ff.name) continue;
    if (["submit", "button", "image", "reset"].includes(ff.type)) continue;
    if (ff.type === "checkbox" || ff.type === "radio") { if (ff.checked) params.set(ff.name, ff.value || "on"); continue; }
    params.set(ff.name, ff.value || "");
  }
  for (const [k, v] of Object.entries(p.fields || {})) {
    if (params.has(k) || p.allow_extra_fields) params.set(k, String(v));
  }
  for (const [k, v] of Object.entries(p.extra_fields || {})) params.set(k, String(v));
  if (p.captcha_math) {
    const q = findMathQuestion(su.body);
    const cf = p.captcha_field || findCaptchaFieldName(f);
    if (q && cf) {
      console.log("CAPTCHA_MATH " + JSON.stringify({ field: cf, context: q.context, computed: q.a + " " + q.op + " " + q.b + " = " + q.answer }));
      params.set(cf, String(q.answer));
    } else {
      console.log("CAPTCHA_MATH_UNRESOLVED " + JSON.stringify({ q: q || null, field: cf || null }));
    }
  }
  const bodyStr = params.toString();
  console.log("SIGNUP_POST " + JSON.stringify({ action, fields: redact(bodyStr, p.password).slice(0, 800) }));
  const post = await req("session", action, { method: "POST", headers: { "Content-Type": "application/x-www-form-urlencoded", "Referer": BASE + "/signup/" }, body: bodyStr });
  fs.writeFileSync(OUT + "/signup-after.html", post.body);
  const text = stripHtml(post.body);
  console.log("SIGNUP_POST_RESULT " + JSON.stringify({ status: post.status, url: post.url, loc: post.location, len: post.len }));
  console.log("SIGNUP_RESULT_TEXT_BEGIN\n" + redact(text.slice(0, 3500), p.password) + "\nSIGNUP_RESULT_TEXT_END");
  const okGuess = /check your email|activation|verify|welcome|success|created|thank/i.test(text) && !/already (taken|in use|registered)|invalid|error|incorrect|must be|try again/i.test(text);
  const captchaErr = /captcha|security code/i.test(text) && /incorrect|invalid|does not match|wrong|try again/i.test(text);
  summary({ phase: "signup", ok: okGuess, postStatus: post.status, postUrl: post.url, captchaErr });
  if (!p.auto || !okGuess) return;
  const link = await pollEmailForLink(p.email, p.poll_minutes || 20);
  if (link) {
    const r = await req("session", link);
    console.log("ACTIVATE " + JSON.stringify({ status: r.status, url: r.url, len: r.len }));
    console.log("ACTIVATE_TEXT " + stripHtml(r.body).slice(0, 1200));
    fs.writeFileSync(OUT + "/activate.html", r.body);
  } else {
    console.log("NO_ACTIVATION_MAIL");
  }
  await loginAndHosts({ username: p.username, password: p.password });
}

async function activate() {
  const url = PAYLOAD.url;
  if (!url) { summary({ phase: "activate", ok: false, reason: "no-url" }); process.exitCode = 1; return; }
  const r = await req("session", url);
  fs.writeFileSync(OUT + "/activate.html", r.body);
  console.log("ACTIVATE " + JSON.stringify({ status: r.status, url: r.url, len: r.len }));
  console.log("ACTIVATE_TEXT " + stripHtml(r.body).slice(0, 1500));
  summary({ phase: "activate", ok: r.status === 200 });
}

async function resume() {
  const p = PAYLOAD;
  const link = await pollEmailForLink(p.email, p.poll_minutes || 20);
  if (link) {
    const r = await req("session", link);
    console.log("ACTIVATE " + JSON.stringify({ status: r.status, url: r.url, len: r.len }));
    console.log("ACTIVATE_TEXT " + stripHtml(r.body).slice(0, 1200));
    fs.writeFileSync(OUT + "/activate.html", r.body);
  } else {
    console.log("NO_ACTIVATION_MAIL");
  }
  await loginAndHosts({ username: p.username, password: p.password });
}

async function main() {
  console.log("PHASE=" + PHASE + " PAYLOAD_KEYS=" + JSON.stringify(Object.keys(PAYLOAD)));
  if (PHASE === "probe") await probe();
  else if (PHASE === "captcha") await captcha();
  else if (PHASE === "signup") await signup();
  else if (PHASE === "activate") await activate();
  else if (PHASE === "resume") await resume();
  else if (PHASE === "login_hosts") await loginAndHosts({ username: PAYLOAD.username, password: PAYLOAD.password });
  else if (PHASE === "verify") await dohVerify(PAYLOAD.hosts || []);
  else { console.log("UNKNOWN_PHASE"); process.exitCode = 1; }
}

main().catch((e) => {
  console.log("FATAL " + e.stack || e.message);
  summary({ phase: PHASE, ok: false, fatal: String(e.message || e) });
  process.exitCode = 1;
});
