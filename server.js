#!/usr/bin/env node
// Token Limit Explorer — paste Claude OAuth tokens, see each one's plan usage limits.
// Zero dependencies (Node 18+). Tokens + names are kept on disk in data/tokens.json (0600),
// written atomically with a .bak of the previous version, so the list survives restarts.
'use strict';
const http = require('http');
const https = require('https');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const PORT = +process.env.PORT || 8740;
const HOST = process.env.HOST || '0.0.0.0';
const LOGIN_ID = process.env.TLE_USER || 'admin';
const LOGIN_PASS = process.env.TLE_PASS || 'admin';   // CHANGE THIS: set TLE_USER / TLE_PASS
const MAX_TOKENS = 100;
const CONCURRENCY = 6;                 // parallel probes during "refresh all"
const SESSION_DAYS = 30;
const PROBE_MODEL = process.env.PROBE_MODEL || 'claude-haiku-4-5-20251001';
const DATA_DIR = process.env.TLE_DATA_DIR || path.join(__dirname, 'data');
const DB_FILE = path.join(DATA_DIR, 'tokens.json');
const SECRET_FILE = path.join(DATA_DIR, 'secret');
const INDEX_HTML = path.join(__dirname, 'public', 'index.html');

fs.mkdirSync(DATA_DIR, { recursive: true, mode: 0o700 });

// ── storage ────────────────────────────────────────────────────────────────
function readJSON(f) { try { return JSON.parse(fs.readFileSync(f, 'utf8')); } catch { return null; } }

function loadDb() {
  for (const f of [DB_FILE, DB_FILE + '.bak']) {
    const d = readJSON(f);
    if (d && Array.isArray(d.tokens)) return d;
  }
  // never silently drop an unreadable list: keep a copy before starting fresh
  if (fs.existsSync(DB_FILE)) fs.copyFileSync(DB_FILE, `${DB_FILE}.unreadable-${Date.now()}`);
  return { settings: {}, tokens: [] };
}

const db = loadDb();
db.settings = Object.assign({ autoRefresh: true, intervalMin: 30, lastRefreshAll: null }, db.settings);

function save() {
  const tmp = DB_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(db, null, 1), { mode: 0o600 });
  if (fs.existsSync(DB_FILE)) { fs.copyFileSync(DB_FILE, DB_FILE + '.bak'); fs.chmodSync(DB_FILE + '.bak', 0o600); }
  fs.renameSync(tmp, DB_FILE);
}
save();

// ── login session (signed cookie, survives restarts) ───────────────────────
const SECRET = (() => {
  try { const s = fs.readFileSync(SECRET_FILE, 'utf8').trim(); if (s.length >= 32) return s; } catch {}
  const s = crypto.randomBytes(32).toString('hex');
  fs.writeFileSync(SECRET_FILE, s, { mode: 0o600 });
  return s;
})();
const sign = v => crypto.createHmac('sha256', SECRET).update(v).digest('base64url');
function newSession() {
  const v = `${Date.now() + SESSION_DAYS * 864e5}.${crypto.randomBytes(8).toString('hex')}`;
  return `${v}.${sign(v)}`;
}
function sessionOk(c) {
  if (!c) return false;
  const i = c.lastIndexOf('.');
  if (i < 0) return false;
  const v = c.slice(0, i), s = Buffer.from(c.slice(i + 1)), good = Buffer.from(sign(v));
  return s.length === good.length && crypto.timingSafeEqual(s, good) && +v.split('.')[0] > Date.now();
}
function cookies(req) {
  const out = {};
  for (const p of (req.headers.cookie || '').split(';')) {
    const i = p.indexOf('=');
    if (i > 0) out[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim());
  }
  return out;
}
const fails = new Map();               // ip -> {n, until}: slow down password guessing

// ── limit probe ────────────────────────────────────────────────────────────
const UNI = 'anthropic-ratelimit-unified-';
const LABELS = {
  '5h': '5-hour session', '7d': 'Weekly · all models', '7d_opus': 'Weekly · Opus',
  '7d_sonnet': 'Weekly · Sonnet', '7d_oauth_apps': 'Weekly · OAuth apps',
};
const USAGE_KEYS = { five_hour: '5h', seven_day: '7d', seven_day_opus: '7d_opus', seven_day_sonnet: '7d_sonnet', seven_day_oauth_apps: '7d_oauth_apps' };
const ORDER = ['5h', '7d', '7d_opus', '7d_sonnet', '7d_oauth_apps'];
const usageBackoff = new Map();        // token -> ms until we try /api/oauth/usage again

const apiHeaders = token => ({
  Authorization: `Bearer ${token}`, 'anthropic-beta': 'oauth-2025-04-20',
  'anthropic-version': '2023-06-01', 'content-type': 'application/json',
});

// A 1-token call: the answer's unified rate-limit headers carry the plan windows
// (a used-up token answers 429 and its headers still say why).
async function probeMessages(token) {
  const out = { raw: {} };
  try {
    const r = await fetch('https://api.anthropic.com/v1/messages', {
      method: 'POST', headers: apiHeaders(token), signal: AbortSignal.timeout(30000),
      body: JSON.stringify({
        model: PROBE_MODEL, max_tokens: 1, messages: [{ role: 'user', content: 'hi' }],
        system: "You are Claude Code, Anthropic's official CLI for Claude.",
      }),
    });
    out.http = r.status;
    for (const [k, v] of r.headers) if (k.startsWith(UNI)) out.raw[k.slice(UNI.length)] = v;
    out.orgId = r.headers.get('anthropic-organization-id') || null;
    const body = await r.text();
    if (!r.ok) {
      let m = body;
      try { const j = JSON.parse(body); m = (j.error && j.error.message) || j.message || body; } catch {}
      out.apiError = String(m).slice(0, 300);
    }
  } catch (e) {
    out.netError = e.name === 'TimeoutError' ? 'Timed out reaching api.anthropic.com' : `${e.name}: ${e.message}`.slice(0, 200);
  }
  return out;
}

// Richer data where the token's scope allows it (setup-tokens usually get 429/403 here: back off).
async function probeUsage(token) {
  const until = usageBackoff.get(token);
  if (until && until > Date.now()) return null;
  try {
    const r = await fetch('https://api.anthropic.com/api/oauth/usage', { headers: apiHeaders(token), signal: AbortSignal.timeout(15000) });
    if (r.ok) return await r.json();
    if ([401, 403, 429].includes(r.status)) usageBackoff.set(token, Date.now() + 6 * 3600e3);
  } catch {}
  return null;
}

async function probe(token) {
  const [m, u] = await Promise.all([probeMessages(token), probeUsage(token)]);
  return buildLimits(m, u);
}

// m: {raw (unified headers without prefix), http, orgId, apiError?, netError?}; u: /api/oauth/usage JSON or null
function buildLimits(m, u, liveSource) {
  const raw = m.raw;
  const win = {};
  for (const k of Object.keys(raw)) {
    const mm = k.match(/^(.+)-utilization$/);
    if (!mm) continue;
    const key = mm[1].replace(/-/g, '_');
    const f = parseFloat(raw[k]);
    const reset = parseInt(raw[`${mm[1]}-reset`], 10);
    win[key] = { key, pct: Number.isFinite(f) ? f * 100 : null, status: raw[`${mm[1]}-status`] || null, resetsAt: Number.isFinite(reset) ? reset * 1000 : null };
  }
  const source = [];
  if (Object.keys(win).length) source.push(liveSource || 'rate-limit headers');
  let extraUsage = null;
  if (u && typeof u === 'object') {
    let any = false;
    for (const [k, v] of Object.entries(u)) {
      if (!v || typeof v !== 'object' || typeof v.utilization !== 'number') continue;
      const key = USAGE_KEYS[k] || k;
      const w = win[key] || (win[key] = { key, status: null, resetsAt: null });
      w.pct = v.utilization;                         // this endpoint already reports percent
      if (v.resets_at) w.resetsAt = Date.parse(v.resets_at);
      any = true;
    }
    if (u.extra_usage && typeof u.extra_usage === 'object') extraUsage = u.extra_usage;
    if (any) source.push('oauth/usage');
  }
  for (const k of ['5h', '7d']) if (!win[k]) win[k] = { key: k, pct: null, status: null, resetsAt: null };
  const rank = k => (ORDER.indexOf(k) + 1) || 99;
  const reset = parseInt(raw.reset, 10);
  const res = {
    checkedAt: Date.now(),
    http: m.http ?? null,
    orgId: m.orgId ?? null,
    status: raw.status || null,
    resetAt: Number.isFinite(reset) ? reset * 1000 : null,
    representativeClaim: raw['representative-claim'] || null,
    overageStatus: raw['overage-status'] || null,
    overageReason: raw['overage-disabled-reason'] || null,
    extraUsage,
    windows: Object.values(win).sort((a, b) => rank(a.key) - rank(b.key)).map(w => ({ ...w, label: LABELS[w.key] || w.key })),
    source,
    raw,
  };
  res.ok = source.length > 0;
  if (m.netError) res.error = m.netError;
  else if (m.http === 401) res.error = `Invalid or expired token (HTTP 401)${m.apiError ? ': ' + m.apiError : ''}`;
  else if (!res.ok) res.error = `No limit info returned (HTTP ${m.http})${m.apiError ? ': ' + m.apiError : ''}`;
  else if (m.apiError && m.http !== 429) res.note = `HTTP ${m.http}: ${m.apiError}`;
  return res;
}

// ── refresh ────────────────────────────────────────────────────────────────
const checking = new Set();
async function refreshOne(id) {
  const t = db.tokens.find(x => x.id === id);
  if (!t || checking.has(id)) return;
  checking.add(id);
  try {
    let r;
    try { r = await probe(t.token); } catch (e) { r = { checkedAt: Date.now(), ok: false, error: String(e).slice(0, 200), windows: [] }; }
    const cur = db.tokens.find(x => x.id === id);
    if (cur && cur.token === t.token) {
      cur.limits = r;
      if (r && r.status === 'rejected') cur.blockedUntil = r.resetAt || Date.now() + 5 * 60e3;
      else if (r && r.ok) cur.blockedUntil = null;    // the window recovered
      if (r && (r.http === 401 || r.http === 403)) cur.authBad = true;   // revoked / org-blocked → keep it out
      else if (r && r.ok) delete cur.authBad;         // owner re-authorized / org re-enabled → back in rotation
      save();
    }
  } finally { checking.delete(id); }
}
async function refreshMany(ids) {
  const q = [...ids];
  await Promise.all(Array.from({ length: Math.min(CONCURRENCY, q.length) }, async () => { while (q.length) await refreshOne(q.shift()); }));
}
let allRun = null;
function refreshAll() {
  if (allRun) return allRun;
  db.settings.lastRefreshAll = Date.now();
  save();
  allRun = refreshMany(db.tokens.map(t => t.id)).finally(() => { allRun = null; });
  return allRun;
}

// ── adding tokens ──────────────────────────────────────────────────────────
const TOKEN_RE = /sk-ant-[A-Za-z0-9_-]{20,}/g;
const cleanName = s => String(s || '').replace(/\s+/g, ' ').trim().slice(0, 80);
function parseTokens(text, givenName) {
  const found = [];
  for (const line of String(text || '').split(/\r?\n/)) {
    let m, first = true;
    TOKEN_RE.lastIndex = 0;
    while ((m = TOKEN_RE.exec(line))) {
      let label = first ? line.slice(0, m.index).replace(/^[\s"'`#*-]+|[\s:=,;|>"'`–—-]+$/g, '') : '';
      if (/^(export\s+)?[A-Z0-9_]*TOKEN[A-Z0-9_]*$/i.test(label) || /^(key|oauth)$/i.test(label)) label = '';
      found.push({ token: m[0], label: cleanName(label) });
      first = false;
    }
  }
  const name = cleanName(givenName);
  return found.map((f, i) => ({
    token: f.token,
    name: found.length === 1 ? (name || f.label) : (f.label || (name ? `${name} ${i + 1}` : '')),
  }));
}

// ── master token + proxy ───────────────────────────────────────────────────
// Apps set ANTHROPIC_BASE_URL=http://<host>:PORT/proxy and use the master token as their Claude token.
// Each request goes on to api.anthropic.com with the token picked in the dashboard ("Use"); a switch
// applies to the next request, while answers already streaming finish on the token they started on.
const newMaster = () => 'sk-ant-oat01-master-' + crypto.randomBytes(30).toString('base64url');
db.master = Object.assign({ token: null, activeId: null, auto: false, holdId: null }, db.master);
if (!db.master.token) { db.master.token = newMaster(); save(); }
const proxyStats = { total: 0, inflight: 0, errors: 0, failovers: 0, lastAt: null, lastStatus: null, lastPath: null, lastTokenId: null };
const HOP = new Set(['connection', 'keep-alive', 'proxy-connection', 'transfer-encoding', 'upgrade', 'te', 'trailer', 'proxy-authorization', 'host']);
let saveTimer = null;
const saveSoon = () => { if (!saveTimer) saveTimer = setTimeout(() => { saveTimer = null; save(); }, 5000); };

function masterOk(req) {
  const auth = String(req.headers.authorization || '');
  const given = /^bearer /i.test(auth) ? auth.slice(7).trim() : String(req.headers['x-api-key'] || '').trim();
  const a = Buffer.from(given), b = Buffer.from(db.master.token);
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
function apiErr(res, code, type, message) {
  if (res.headersSent) return res.destroy();
  res.writeHead(code, { 'content-type': 'application/json' });
  res.end(JSON.stringify({ type: 'error', error: { type, message } }));
}

// Every answer carries the token's rate-limit headers: keep the dashboard current for free.
function noteLimits(t, ur) {
  const raw = {};
  for (const [k, v] of Object.entries(ur.headers)) if (k.startsWith(UNI)) raw[k.slice(UNI.length)] = String(v);
  if (!Object.keys(raw).length) return;
  const cur = db.tokens.find(x => x.id === t.id);
  if (!cur || cur.token !== t.token) return;
  const L = buildLimits({ raw, http: ur.statusCode, orgId: ur.headers['anthropic-organization-id'] || (cur.limits && cur.limits.orgId) || null }, null, 'live app traffic');
  if (cur.limits && cur.limits.extraUsage) L.extraUsage = cur.limits.extraUsage;
  cur.limits = L;
  saveSoon();
}

// ── account selection (auto mode) ────────────────────────────────────────────
// Goal: never stop, be efficient, be polite. All same-org tokens share prompt cache, so switching
// among them is free; only a different org re-reads. Politeness = leave the owner headroom, but
// relax it as a window's RESET approaches (a short lockout) and at night (owners asleep). Weekly
// budget is use-it-or-lose-it: near its reset, drain it fully, and spend the soonest-expiring first.
const PREMIUM_NAMES = new Set((process.env.TLE_PREMIUM || '').split(',').map(x => x.trim().toLowerCase()).filter(Boolean));  // optional: names to treat as 'premium'
const CAPS = {   // fractions 0..1; base headroom before the reset-ramp and night relax are applied
  premium:  { day5: 0.75, day7: 0.85, night5: 1.0, night7: 0.95 },
  standard: { day5: 0.45, day7: 0.65, night5: 1.0, night7: 0.90 },
  fallback: { day5: 1.0,  day7: 0.90, night5: 1.0, night7: 0.95 },
};
const winOf = (t, k) => ((t.limits && t.limits.windows) || []).find(w => w.key === k) || null;
const utilOf = (t, k) => { const w = winOf(t, k); return w && typeof w.pct === 'number' ? w.pct / 100 : null; };
const resetInOf = (t, k) => { const w = winOf(t, k); return w && w.resetsAt ? w.resetsAt - Date.now() : null; };
const istHour = () => ((Date.now() + 5.5 * 3600e3) / 3600e3) % 24;
const quiet = () => { const h = istHour(); return h >= 21 || h < 9; };   // 21:00–09:00 IST: owners mostly away
const ramp = (ms, soonMin, farMin) => {                                  // 1 when reset is near, 0 when far
  if (ms == null) return 0;
  const m = ms / 60000;
  if (m <= soonMin) return 1;
  if (m >= farMin) return 0;
  return (farMin - m) / (farMin - soonMin);
};
function primaryOrg() {
  const c = {};
  for (const t of db.tokens) { const o = t.limits && t.limits.orgId; if (o) c[o] = (c[o] || 0) + 1; }
  let best = null, n = -1;
  for (const [o, k] of Object.entries(c)) if (k > n) { n = k; best = o; }
  return best;
}
function effRole(t) {                                     // explicit role wins; else infer from org/name
  if (t.role) return t.role;
  const po = primaryOrg(), o = t.limits && t.limits.orgId;
  if (po && o && o !== po) return 'fallback';
  if (PREMIUM_NAMES.has((t.name || '').toLowerCase())) return 'premium';
  return 'standard';
}
const isFallback = t => effRole(t) === 'fallback';
// ── usage-pattern learner ────────────────────────────────────────────────────
// Learns each owner's own daily/weekly rhythm — WHEN they use their account — and reserves headroom to match,
// so the system is polite where an owner is usually active and drains harder where they're idle, improving by
// itself over time. Cheap: one snapshot every 30 min, an EWMA per 3-hour block (weekday vs weekend), tiny state.
// Signal: between two snapshots in which WE sent that token no traffic, any rise in its weekly utilisation is
// the owner's own use — attributed to that time-block. Resets (a drop) are ignored.
const USAGE_DIR = path.join(DATA_DIR, 'usage');
const PROFILE_FILE = path.join(USAGE_DIR, 'profile.json');
const SAMPLE_MS = 30 * 60e3, NBUCKET = 16, EWMA_A = 0.15, MIN_SAMPLES = 8;
let profile = (() => { try { fs.mkdirSync(USAGE_DIR, { recursive: true }); } catch {} const p = readJSON(PROFILE_FILE); return p && p.tok ? p : { tok: {} }; })();
const reqCount = {};                              // id -> cumulative successful proxied requests
const lastSnap = {};                             // id -> { u7, reqs, b } from the previous snapshot
function istParts() { const d = new Date(Date.now() + 5.5 * 3600e3); return { wd: d.getUTCDay(), h: d.getUTCHours() }; }
function bucketIdx() { const { wd, h } = istParts(); return ((wd === 0 || wd === 6) ? 8 : 0) + Math.floor(h / 3); }
function saveProfile() { try { const tmp = PROFILE_FILE + '.tmp'; fs.writeFileSync(tmp, JSON.stringify(profile)); fs.renameSync(tmp, PROFILE_FILE); } catch (e) { console.error(new Date().toISOString(), 'profile save:', e.message); } }
function recordSample() {
  const b = bucketIdx();
  for (const t of db.tokens) {
    const u7 = utilOf(t, '7d'), reqs = reqCount[t.id] || 0, prev = lastSnap[t.id];
    if (prev && u7 != null && prev.u7 != null && reqs - prev.reqs === 0) {   // interval we did NOT use this token
      const d = u7 - prev.u7;
      if (d >= 0 && d < 0.5) {                                               // owner's own use (not a reset)
        const p = profile.tok[t.id] || (profile.tok[t.id] = { ol: Array(NBUCKET).fill(0), n: 0 });
        p.ol[prev.b] = (1 - EWMA_A) * p.ol[prev.b] + EWMA_A * d; p.n++;
      }
    }
    lastSnap[t.id] = { u7, reqs, b };
  }
  saveProfile();
}
// How much of its window to keep free for the owner right now (fraction). Defaults reproduce the old static
// caps until enough data; then it follows the learned rhythm, bounded by role. Fallback is not learned.
// Daytime owner headroom to keep free (fraction). Bounds set the DAY session ceiling: standard ≤ 80% used
// (reserve ≥ 0.20), premium ≤ 90% (reserve ≥ 0.10). The learner may reserve MORE where an owner is active,
// never less — so a daytime session never exceeds its ceiling even right before its reset.
function learnedReserve(t) {
  const role = effRole(t);
  const minR = role === 'premium' ? 0.10 : role === 'fallback' ? 0.10 : 0.20;
  const maxR = role === 'premium' ? 0.40 : 0.70;
  const p = profile.tok[t.id];
  if (!p || p.n < MIN_SAMPLES) return minR;              // default = the ceiling (standard 80% / premium 90%)
  const need = (p.ol[bucketIdx()] || 0) * 4 * 1.5;       // ~the owner's typical use over the next 2h, with margin
  return Math.max(minR, Math.min(maxR, need));
}
function capsOf(t) {
  const role = effRole(t), C = CAPS[role] || CAPS.standard, q = quiet();
  // Day: cap at the politeness ceiling (leave the owner headroom), NO 5h ramp — never fully drain a session
  // during the day, even just before its reset. Night: owners are away, so drain the session fully.
  let cap5 = q ? C.night5 : (role === 'fallback' ? C.day5 : 1 - learnedReserve(t));
  // Weekly gets NO night boost — a weekly reset is days away, so draining it locks the owner out for days.
  // Keep the owner's week protected at all hours; only as the weekly's OWN reset nears does it open toward full.
  const base7 = C.day7;
  let cap7 = base7 + (1 - base7) * ramp(resetInOf(t, '7d'), 60, 360);
  if (typeof t.cap5 === 'number') cap5 = t.cap5;   // explicit per-account ceiling (dashboard) overrides everything
  if (typeof t.cap7 === 'number') cap7 = t.cap7;
  return { cap5, cap7 };
}
function blocked(t) { return t.blockedUntil && t.blockedUntil > Date.now(); }
function remaining(t) {                                   // min headroom we may still use across both windows
  const { cap5, cap7 } = capsOf(t);
  const u5 = utilOf(t, '5h'), u7 = utilOf(t, '7d');
  return Math.min(u5 == null ? 1 : Math.max(0, cap5 - u5), u7 == null ? 1 : Math.max(0, cap7 - u7));
}
function eligible(t) {
  if (t.exempt) return false;                     // manually held out of auto-cycle until un-exempted
  if (effRole(t) === 'off') return false;
  if (t.authBad || (t.limits && (t.limits.http === 401 || t.limits.http === 403))) return false;   // revoked / org-blocked — never route to it
  if (blocked(t)) return false;
  if (t.limits && t.limits.status === 'rejected') return false;
  return remaining(t) > 0.001;
}
// A manually chosen account (Use / manual mode): usable even if it's over a politeness CAP — the user explicitly
// picked it. Only a real block stops it: exempt/off, revoked, rate-limited (429), or genuinely at the API limit.
function heldUsable(t) {
  if (!t || t.exempt || effRole(t) === 'off') return false;
  if (t.authBad || (t.limits && (t.limits.http === 401 || t.limits.http === 403))) return false;
  if (blocked(t)) return false;
  if (t.limits && t.limits.status === 'rejected') return false;
  return true;
}
// A window (5h session OR 7d weekly) that resets soon with budget left is use-it-or-lose-it: spend it
// before it resets — any account, premium / standard / fallback alike, so nothing is wasted. Because each
// account's windows reset at different times, this naturally rotates through the whole fleet, draining each
// one just before its reset. A fallback is a different org (one cache re-read), so it needs more left to
// qualify; once chosen it stays top until drained/reset, so the re-read is paid once.
const PERISH_5H_MS = 90 * 60e3;                           // 5h window "about to reset" = within 90 min
const PERISH_7D_MS = 3 * 3600e3;                          // weekly "about to reset" = within 3h
function perishParts(t) {
  if (remaining(t) <= 0.05) return [];   // no usable combined budget (e.g. weekly near its cap) → don't promote/drain it
  const { cap5, cap7 } = capsOf(t);
  const u5 = utilOf(t, '5h'), u7 = utilOf(t, '7d');
  const r5 = resetInOf(t, '5h'), r7 = resetInOf(t, '7d');
  const min = isFallback(t) ? 0.12 : 0.05;
  const when = [];
  if (r5 != null && r5 < PERISH_5H_MS && u5 != null && cap5 - u5 > min) when.push(r5);
  if (r7 != null && r7 < PERISH_7D_MS && u7 != null && cap7 - u7 > min) when.push(r7);
  return when;
}
const perishable = t => perishParts(t).length > 0;
const perishIn = t => { const w = perishParts(t); return w.length ? Math.min(...w) : Infinity; };
// Fallback accounts (a different org/subscription) may be large. Below a soft cap (30% of
// their window) a fallback is pulled into rotation AHEAD of the primary pool and used up to that 30%;
// past 30% it reverts to a true last-resort fallback, keeping the rest as reserve (and not over-competing with
// whatever else may share that token). After its window resets it drops below 30% again and
// is preferred anew.
const SOFT_FB = 0.30;
function fbUtil(t) { const u5 = utilOf(t, '5h'), u7 = utilOf(t, '7d'); return Math.max(u5 == null ? 0 : u5, u7 == null ? 0 : u7); }
function fallbackSoft(t) { return isFallback(t) && fbUtil(t) < SOFT_FB; }
// Ordered list of tokens to try, best first:
//   0 perishable (soon-to-reset budget, any account) → 1 soft fallback (20x account under 30%, drain to 30%) →
//   2 primary (most headroom, spreads the fleet) → 3 fallback past 30% (last resort). No rigid premium-first.
function candidates() {
  const elig = db.tokens.filter(eligible);
  // A pinned account is forced to the very front of auto-cycle (failover still applies) until un-pinned.
  const tier = t => t.pin ? -1 : perishable(t) ? 0 : fallbackSoft(t) ? 1 : isFallback(t) ? 3 : 2;
  elig.sort((a, b) => {
    const ta = tier(a), tb = tier(b);
    if (ta !== tb) return ta - tb;
    if (ta === 0) {                                        // both perishable: soonest-expiring first; near-tie → primary
      const d = perishIn(a) - perishIn(b);
      if (Math.abs(d) > 10 * 60e3) return d;
      const fa = isFallback(a), fb = isFallback(b);
      if (fa !== fb) return fa ? 1 : -1;
      return d;
    }
    if (ta === -1) {                                      // pinned: by priority (numeric pin, lower first), then list order
      const po = x => typeof x.pin === 'number' ? x.pin : 0;
      return (po(a) - po(b)) || (db.tokens.indexOf(a) - db.tokens.indexOf(b));
    }
    if (ta === 1 || ta === 3) return db.tokens.indexOf(a) - db.tokens.indexOf(b);   // fallback groups: list order
    return remaining(b) - remaining(a);                   // primary: most headroom
  });
  return elig;
}
const MANUAL_SWITCH = 0.95;   // manual mode: when the chosen token's 5h session passes this, switch automatically
const HOLD_UNTIL = 0.75;      // a manual "Use" sticks to that account (any mode) until its 5h session reaches 75%
function attemptOrder() {
  // Manual "Use" hold: in ANY mode, keep using the chosen account (a FIXED id, not the live activeId which the
  // proxy updates) until its 5h session hits 70%, then release and resume normal behaviour. Beats the pins/chain —
  // an explicit click wins. Failover still applies if the held account errors.
  if (db.master.holdId) {
    const held = db.tokens.find(t => t.id === db.master.holdId);
    const u5 = held ? utilOf(held, '5h') : null;
    if (heldUsable(held) && (u5 == null || u5 < HOLD_UNTIL)) {   // overrides politeness caps — user picked it
      return [held, ...candidates().filter(x => x.id !== held.id)];
    }
    db.master.holdId = null; saveSoon();   // reached 70%, or the account became truly unusable → release the hold
  }
  if (!db.master.auto) {
    // Manual mode: use the chosen token, but never let work stop — fail over to the auto order if it errors,
    // and switch away once its 5h session reaches 95% (so a manual pick also keeps going forever).
    const t = db.tokens.find(x => x.id === db.master.activeId);
    const auto = candidates();
    if (heldUsable(t)) {
      const u5 = utilOf(t, '5h');
      if (u5 == null || u5 < MANUAL_SWITCH) return [t, ...auto.filter(x => x.id !== t.id)];
    }
    return auto.length ? auto : (t ? [t] : []);   // chosen token at/over 95% or unusable → move to the next
  }
  const cands = candidates();
  if (!cands.length) return [];
  // Hysteresis (avoid flipping between similar accounts every request) — but never hold back a perishable
  // pick: if the best is about to reset, switch to it at once.
  const cur = db.tokens.find(t => t.id === db.master.activeId);
  if (cur && eligible(cur) && !isFallback(cur) && !perishable(cur) && !perishable(cands[0]) && !isFallback(cands[0]) &&
      remaining(cur) >= remaining(cands[0]) - 0.03) {
    return [cur, ...cands.filter(t => t.id !== cur.id)];
  }
  return cands;
}

// ── proxy with transparent failover ──────────────────────────────────────────
function collectBody(req, cap = 48 * 1024 * 1024) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', c => { n += c.length; if (n > cap) { reject(new Error('body too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks)));
    req.on('error', reject);
  });
}
// Reuse TLS connections to api.anthropic.com: no per-request handshake (~saves 30–50ms/request), and a
// pool big enough for many parallel workflow requests at once.
const upstreamAgent = new https.Agent({ keepAlive: true, keepAliveMsecs: 30000, maxSockets: 256, maxFreeSockets: 64, scheduling: 'fifo', timeout: 120000 });
function sendUpstream(method, path, headers, body) {
  return new Promise((resolve, reject) => {
    const up = https.request({ host: 'api.anthropic.com', port: 443, method, path, headers, agent: upstreamAgent }, ur => resolve({ ur, up }));
    up.on('error', reject);
    if (body && body.length) up.end(body); else up.end();
  });
}
function pipeResponse(res, ur) {
  const out = {};
  for (const [k, v] of Object.entries(ur.headers)) if (!HOP.has(k)) out[k] = v;
  res.writeHead(ur.statusCode, out);
  ur.pipe(res);
  ur.on('error', () => res.destroy());
}
function blockedUntilFrom(h) {
  const ra = parseInt(h['retry-after'], 10);
  if (Number.isFinite(ra)) return Date.now() + ra * 1000;
  const resets = [];
  for (const [k, v] of Object.entries(h)) {
    if (k.startsWith(UNI) && k.endsWith('-status') && v === 'rejected') {
      const rs = parseInt(h[k.slice(0, -'-status'.length) + '-reset'], 10);
      if (Number.isFinite(rs)) resets.push(rs * 1000);
    }
  }
  return resets.length ? Math.min(...resets) : Date.now() + 5 * 60e3;
}

async function proxy(req, res, url) {
  if (!masterOk(req)) return apiErr(res, 401, 'authentication_error', 'Token Limit Explorer: wrong or missing master token');
  let body;
  try { body = await collectBody(req); }
  catch { return apiErr(res, 413, 'invalid_request_error', 'Token Limit Explorer: request body too large to proxy'); }

  const base = {};
  for (const [k, v] of Object.entries(req.headers)) if (!HOP.has(k) && k !== 'authorization' && k !== 'x-api-key') base[k] = v;
  base.host = 'api.anthropic.com';
  const betas = String(base['anthropic-beta'] || '').split(',').map(s => s.trim()).filter(Boolean);
  if (!betas.includes('oauth-2025-04-20')) betas.push('oauth-2025-04-20');
  base['anthropic-beta'] = betas.join(',');
  const upPath = (url.pathname.slice('/proxy'.length) || '/') + url.search;

  const list = attemptOrder();
  if (!list.length) return apiErr(res, 503, 'api_error',
    db.master.auto ? 'Token Limit Explorer: all tokens are at their limit right now.'
                   : 'Token Limit Explorer: no token selected. Click "Use" on a token, or turn on Auto.');

  proxyStats.total++; proxyStats.inflight++;
  let settled = false; const fin = () => { if (!settled) { settled = true; proxyStats.inflight--; } };
  let curUp = null;
  res.on('close', () => { if (!res.writableFinished && curUp) curUp.destroy(); fin(); });

  const SERVER_ERR = new Set([500, 502, 503, 504, 529]);   // transient: a server/overload error, worth another token
  let serverTries = 0;                                      // but cap these so one bad request can't burn every token
  try {
    for (let i = 0; i < list.length; i++) {
      const tok = list[i];
      const headers = { ...base, authorization: `Bearer ${tok.token}` };
      let r;
      try { r = await sendUpstream(req.method, upPath, headers, body); }
      catch (e) {
        proxyStats.errors++;
        if (i === list.length - 1) return apiErr(res, 502, 'api_error', `Token Limit Explorer could not reach api.anthropic.com: ${e.message}`);
        continue;
      }
      const { ur, up } = r; curUp = up;
      const code = ur.statusCode;
      Object.assign(proxyStats, { lastStatus: code, lastTokenId: tok.id, lastAt: Date.now(), lastPath: upPath.split('?')[0] });
      const more = i < list.length - 1;
      if (more) {                                           // fail over in BOTH auto and manual — work must never stop
        if (code === 429) {                                 // rate limited: block this token until its reset, move on
          tok.blockedUntil = blockedUntilFrom(ur.headers);  // a pin persists (ongoing priority) — it just gets skipped
          noteLimits(tok, ur);                              // while blocked, and resumes priority after its reset
          proxyStats.failovers++; ur.resume(); saveSoon(); continue;
        }
        if (code === 401 || code === 403) {                 // token revoked / org-auth-blocked → exclude it and move on
          tok.authBad = true;                               // skipped until a probe (owner re-auth / org re-enable) clears it
          proxyStats.failovers++; ur.resume(); saveSoon(); continue;
        }
        if (SERVER_ERR.has(code) && serverTries < 2) {      // transient server error: try the next token
          serverTries++; proxyStats.failovers++; ur.resume(); continue;
        }
      }
      if (code < 400) {
        if (tok.blockedUntil) tok.blockedUntil = null;
        if (tok.authBad) delete tok.authBad;
        reqCount[tok.id] = (reqCount[tok.id] || 0) + 1;    // our usage, so the learner can tell it from the owner's
        if (db.master.activeId !== tok.id) { db.master.activeId = tok.id; saveSoon(); }
        noteLimits(tok, ur);                               // refresh this token's util from the answer's headers
      }
      pipeResponse(res, ur);
      return;
    }
    apiErr(res, 429, 'rate_limit_error', 'Token Limit Explorer: all tokens are rate limited right now.');
  } finally { fin(); }
}

// ── http ───────────────────────────────────────────────────────────────────
function send(res, code, obj, extra = {}) {
  const body = JSON.stringify(obj);
  res.writeHead(code, { 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store', ...extra });
  res.end(body);
}
function readBody(req) {
  return new Promise((resolve, reject) => {
    let n = 0; const chunks = [];
    req.on('data', c => { n += c.length; if (n > 1e6) { reject(new Error('too large')); req.destroy(); } else chunks.push(c); });
    req.on('end', () => { try { resolve(chunks.length ? JSON.parse(Buffer.concat(chunks).toString('utf8')) : {}); } catch { resolve({}); } });
    req.on('error', reject);
  });
}
const publicState = () => ({
  now: Date.now(), max: MAX_TOKENS, settings: db.settings, refreshingAll: !!allRun,
  master: db.master, proxy: proxyStats, quiet: quiet(), nowBucket: bucketIdx(),
  tokens: db.tokens.map(t => {
    const p = profile.tok[t.id];
    return {
      ...t, checking: checking.has(t.id),
      role: effRole(t), eligible: eligible(t), blocked: blocked(t),
      headroom: Math.round(remaining(t) * 100),
      reserve: Math.round(learnedReserve(t) * 100),
      pattern: p ? p.ol : null, patternN: p ? p.n : 0,
    };
  }),
});

async function handle(req, res) {
  const url = new URL(req.url, 'http://x');
  const p = url.pathname;
  const ip = req.socket.remoteAddress || '?';

  if (req.method === 'GET' && (p === '/' || p === '/index.html')) {
    res.writeHead(200, { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store', 'x-frame-options': 'DENY', 'referrer-policy': 'no-referrer' });
    return res.end(fs.readFileSync(INDEX_HTML));
  }
  if (p === '/proxy' || p.startsWith('/proxy/')) return proxy(req, res, url);
  if (!p.startsWith('/api/')) return send(res, 404, { error: 'Not found' });

  if (p === '/api/login' && req.method === 'POST') {
    const f = fails.get(ip);
    if (f && f.until > Date.now()) return send(res, 429, { error: 'Too many wrong attempts. Try again in a few minutes.' });
    const b = await readBody(req);
    if (String(b.id || '').trim() === LOGIN_ID && String(b.pass || '') === LOGIN_PASS) {
      fails.delete(ip);
      return send(res, 200, { ok: true }, { 'set-cookie': `tle=${newSession()}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${SESSION_DAYS * 86400}` });
    }
    const n = (f && !f.until ? f.n : 0) + 1;   // an expired lockout starts the count again
    fails.set(ip, { n, until: n >= 8 ? Date.now() + 10 * 60e3 : 0 });
    return send(res, 401, { error: 'Wrong ID or password' });
  }
  if (p === '/api/logout' && req.method === 'POST') {
    return send(res, 200, { ok: true }, { 'set-cookie': 'tle=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0' });
  }
  if (!sessionOk(cookies(req).tle)) return send(res, 401, { error: 'Login required' });

  if (p === '/api/state' && req.method === 'GET') return send(res, 200, publicState());

  if (p === '/api/settings' && req.method === 'PUT') {
    const b = await readBody(req);
    if (typeof b.autoRefresh === 'boolean') db.settings.autoRefresh = b.autoRefresh;
    if (typeof b.auto === 'boolean') db.master.auto = b.auto;   // auto account-cycling (never stop)
    save();
    return send(res, 200, publicState());
  }

  if (p === '/api/active' && req.method === 'PUT') {
    const b = await readBody(req);
    if (b.id !== null && !db.tokens.some(t => t.id === b.id)) return send(res, 404, { error: 'Token not found' });
    db.master.activeId = b.id;
    db.master.holdId = b.id || null;   // a manual "Use" holds this exact account (any mode) until its 5h session reaches 70%
    save();
    return send(res, 200, publicState());
  }

  if (p === '/api/master/regenerate' && req.method === 'POST') {
    db.master.token = newMaster();
    save();
    return send(res, 200, publicState());
  }

  if (p === '/api/refresh-all' && req.method === 'POST') {
    if (db.tokens.length) refreshAll();
    return send(res, 200, publicState());
  }

  if (p === '/api/tokens' && req.method === 'POST') {
    const b = await readBody(req);
    const items = parseTokens(b.text, b.name);
    if (!items.length) return send(res, 400, { error: 'No Claude token found. It should start with sk-ant-' });
    const have = new Set(db.tokens.map(t => t.token));
    const added = [], skipped = [];
    for (const it of items) {
      if (it.token === db.master.token) { skipped.push('that is the master token, not a Claude token'); continue; }
      if (have.has(it.token)) { skipped.push(`${it.token.slice(0, 18)}… already in the list`); continue; }
      if (db.tokens.length >= MAX_TOKENS) { skipped.push(`${it.token.slice(0, 18)}… not added: limit of ${MAX_TOKENS} tokens reached`); continue; }
      const t = { id: crypto.randomBytes(6).toString('hex'), name: it.name, token: it.token, addedAt: Date.now(), limits: null };
      db.tokens.push(t); have.add(it.token); added.push(t.id);
    }
    if (added.length) { save(); refreshMany(added); }
    return send(res, added.length ? 200 : 409, { ...publicState(), added: added.length, skipped, error: added.length ? undefined : skipped.join('; ') });
  }

  const m = p.match(/^\/api\/tokens\/([a-f0-9]{12})(\/refresh)?$/);
  if (m) {
    const t = db.tokens.find(x => x.id === m[1]);
    if (!t) return send(res, 404, { error: 'Token not found' });
    if (m[2] && req.method === 'POST') { refreshOne(t.id); return send(res, 200, publicState()); }
    if (!m[2] && req.method === 'PATCH') {
      const b = await readBody(req);
      if (typeof b.name === 'string') t.name = cleanName(b.name);
      if (typeof b.role === 'string' && ['premium', 'standard', 'fallback', 'off'].includes(b.role)) t.role = b.role;
      if (typeof b.exempt === 'boolean') { if (b.exempt) t.exempt = true; else delete t.exempt; }
      if ('pin' in b) {                                 // force to front of auto-cycle; a number sets priority (lower first)
        if (b.pin === false || b.pin === null) delete t.pin;
        else if (b.pin === true) t.pin = true;
        else if (typeof b.pin === 'number' && b.pin >= 0) t.pin = b.pin;
      }
      for (const k of ['cap5', 'cap7']) {              // per-account ceiling as a percent (1–100), or null to clear
        if (k in b) {
          const v = b[k];
          if (v === null || v === '') delete t[k];
          else if (typeof v === 'number' && v >= 1 && v <= 100) t[k] = v / 100;
        }
      }
      save();
      return send(res, 200, publicState());
    }
    if (!m[2] && req.method === 'DELETE') {
      db.tokens = db.tokens.filter(x => x.id !== t.id);
      if (db.master.activeId === t.id) db.master.activeId = null;
      save();
      return send(res, 200, publicState());
    }
  }
  return send(res, 404, { error: 'Not found' });
}

// Stay up no matter what: a stray error in any async path must never take the whole service down.
const ts = () => new Date().toISOString();
process.on('uncaughtException', e => { try { console.error(ts(), 'uncaughtException:', (e && e.stack) || e); } catch {} });
process.on('unhandledRejection', e => { try { console.error(ts(), 'unhandledRejection:', (e && e.stack) || e); } catch {} });

const server = http.createServer((req, res) => {
  handle(req, res).catch(e => { console.error(ts(), 'request error:', (e && e.stack) || e); if (!res.headersSent) send(res, 500, { error: 'Server error' }); });
});
server.on('clientError', (e, sock) => { try { sock.destroy(); } catch {} });   // a malformed client must not crash us
server.keepAliveTimeout = 65000; server.headersTimeout = 70000;                 // long streams (workflows) are fine
server.requestTimeout = 0;                                                      // no cap: big agent turns can run long
server.listen(PORT, HOST, () => console.log(`${ts()} Token Limit Explorer on http://${HOST}:${PORT} (${db.tokens.length} tokens)`));
server.on('error', e => { console.error(ts(), 'listen error:', e.message); process.exit(1); });   // e.g. port busy → let the supervisor retry

// Usage-pattern learner: refresh all tokens' limits then take one snapshot, every 30 min. Keeps the dashboard
// and the learner current even with no dashboard open, at ~one tiny probe per token per half hour.
setTimeout(() => { try { recordSample(); } catch (e) { console.error(ts(), 'sample:', e.message); } }, 15000);  // seed baseline
setInterval(() => {
  Promise.resolve().then(refreshAll).then(() => recordSample()).catch(e => console.error(ts(), 'sample cycle:', e.message));
}, SAMPLE_MS);
