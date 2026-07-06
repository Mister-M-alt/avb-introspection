/*
 * SPDX-FileCopyrightText: 2026 Kebag-Logic
 * SPDX-License-Identifier: MIT
 *
 * AVB Introspection — frontend. Vanilla ES2022, no dependencies, works
 * offline. Talks to the backend API described in docs/API.md via relative
 * URLs.
 */
(() => {
'use strict';

/* ────────────────────────── constants ────────────────────────── */

const PROTOCOLS = ['GPTP', 'MSRP', 'MVRP', 'MAAP', 'ADP', 'AECP', 'ACMP'];
const KINDS = ['packet', 'transition', 'error'];

/* Protocol accent colors — dark-surface categorical palette validated with the
   dataviz skill's checker (adjacent CVD dE 59.2, all >= 3:1 on the surfaces).
   Identity is never color-alone: every lane/chip/badge carries a text label.
   Must stay in sync with the --c-* custom properties in style.css. */
const PROTO_COLORS = {
  GPTP: '#2fa3a8',
  MSRP: '#199e70',
  MVRP: '#3987e5',
  MAAP: '#d95926',
  ADP:  '#9085e9',
  AECP: '#c98500',
  ACMP: '#d55181',
};
const ERROR_COLOR = '#d03b3b';
const OTHER_COLOR = '#8b949e';
const MARKER_COLOR = '#fab219';   /* user marker lines/flags on the timeline */
const MONO_FONT = 'ui-monospace, "SF Mono", "Cascadia Mono", Menlo, Consolas, "Liberation Mono", monospace';

const TOKEN_KEY = 'avb.token';
const USER_KEY = 'avb.user';
const ROLE_KEY = 'avb.role';    /* cached /api/me role: 'admin' | 'user' */
const TIME_MODE_KEY = 'avb.timeMode';   /* 'rel' | 'tod' */
const SPLIT_KEY = 'avb.split';          /* events/inspector pane split, % */
const LANEH_KEY = 'avb.tl.laneH';       /* timeline lane height, px */
const MARKERS_KEY_PREFIX = 'avb.markers.';   /* + session id -> JSON array */
const ROW_H = 24;               /* events table row height, px (matches CSS) */

/* exact 17-char colon-separated MAC (used to decorate inspector field values) */
const MAC_RE = /^[0-9a-fA-F]{2}(:[0-9a-fA-F]{2}){5}$/;

/* ────────────────────────── tiny DOM helper ────────────────────────── */

function h(tag, attrs, ...children) {
  const el = document.createElement(tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.className = v;
      else if (k === 'dataset') Object.assign(el.dataset, v);
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else if (k === 'value') el.value = v;
      else if (k === 'checked') el.checked = true;
      else if (k === 'disabled') el.disabled = true;
      else if (k === 'hidden') el.hidden = true;
      else el.setAttribute(k, v === true ? '' : String(v));
    }
  }
  appendKids(el, children);
  return el;
}

function appendKids(el, kids) {
  for (const c of kids) {
    if (c === null || c === undefined || c === false || c === '') continue;
    if (Array.isArray(c)) appendKids(el, c);
    else if (c instanceof Node) el.appendChild(c);
    else el.appendChild(document.createTextNode(String(c)));
  }
}

/* SVG sibling of h(): the state-machine diagrams need createElementNS so the
   nodes live in the SVG namespace (h() uses createElement and would build
   HTML-namespaced, non-rendering elements). Attributes are all set verbatim. */
const SVG_NS = 'http://www.w3.org/2000/svg';
function svg(tag, attrs, ...children) {
  const el = document.createElementNS(SVG_NS, tag);
  if (attrs) {
    for (const [k, v] of Object.entries(attrs)) {
      if (v === null || v === undefined || v === false) continue;
      if (k === 'class') el.setAttribute('class', v);
      else if (k.startsWith('on')) el.addEventListener(k.slice(2), v);
      else el.setAttribute(k, v === true ? '' : String(v));
    }
  }
  appendKids(el, children);
  return el;
}

/* ────────────────────────── toasts ────────────────────────── */

function toast(msg, kind) {
  const box = document.getElementById('toasts');
  if (!box) return;
  const t = h('div', { class: 'toast' + (kind === 'error' ? ' error' : '') }, String(msg));
  box.appendChild(t);
  while (box.children.length > 5) box.firstChild.remove();
  setTimeout(() => {
    t.classList.add('gone');
    setTimeout(() => t.remove(), 400);
  }, kind === 'error' ? 6000 : 3500);
}

/* ────────────────────────── formatting ────────────────────────── */

function fmtTs(ts) {
  return (typeof ts === 'number' && isFinite(ts)) ? ts.toFixed(4) + ' s' : '—';
}

function fmtInt(x) {
  const v = typeof x === 'number' ? x : 0;
  return v.toLocaleString('en-US');
}

function fmtBytes(b) {
  if (typeof b !== 'number') return '—';
  if (b < 1024) return b + ' B';
  if (b < 1024 * 1024) return (b / 1024).toFixed(1) + ' KB';
  if (b < 1024 * 1024 * 1024) return (b / (1024 * 1024)).toFixed(1) + ' MB';
  return (b / (1024 * 1024 * 1024)).toFixed(2) + ' GB';
}

function fmtDate(iso) {
  if (!iso) return '—';
  const d = new Date(iso);
  if (isNaN(d.getTime())) return String(iso);
  return d.toLocaleString();
}

function fmtDur(s) {
  if (typeof s !== 'number' || !isFinite(s)) return '—';
  return (s >= 10 ? s.toFixed(1) : s.toFixed(3)) + ' s';
}

function fmtUptime(s) {
  if (typeof s !== 'number') return '—';
  if (s < 120) return s.toFixed(0) + ' s';
  if (s < 7200) return (s / 60).toFixed(1) + ' min';
  return (s / 3600).toFixed(1) + ' h';
}

function protoClass(p) {
  return 'p-' + (PROTO_COLORS[p] ? p.toLowerCase() : 'other');
}

/* MAC arithmetic for MAAP range ends (input like "91:e0:f0:00:0e:80"). */
function macAdd(mac, add) {
  try {
    const clean = String(mac).split(':').join('').split('-').join('');
    if (clean.length !== 12) return null;
    const v = BigInt('0x' + clean) + BigInt(add);
    let s = v.toString(16).padStart(12, '0');
    s = s.slice(-12);
    const parts = [];
    for (let k = 0; k < 12; k += 2) parts.push(s.slice(k, k + 2));
    return parts.join(':');
  } catch (err) {
    return null;
  }
}

/* ────────────────────────── minimal markdown (notes) ────────────────────────── */

/* Tiny renderer for investigation notes: #/##/### headings, **bold**, *italic*,
   `inline code`, fenced ``` blocks, "- " lists, [text](url) links, paragraphs.
   Every source line is HTML-escaped BEFORE any transform, so notes content can
   never inject markup. */
function mdEscape(s) {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

function mdInline(s) {
  /* input is already escaped; stash code spans so their contents stay verbatim */
  const codes = [];
  s = s.replace(/`([^`]+)`/g, (m, c) => {
    codes.push(c);
    return '\u0000' + (codes.length - 1) + '\u0000';
  });
  s = s.replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>');
  s = s.replace(/\*([^*]+)\*/g, '<em>$1</em>');
  s = s.replace(/\[([^\]]+)\]\(([^()\s]+)\)/g, (m, txt, url) =>
    /^(https?:\/\/|\/|#|mailto:)/i.test(url)
      ? '<a href="' + url + '" target="_blank" rel="noopener noreferrer">' + txt + '</a>'
      : m);
  return s.replace(/\u0000(\d+)\u0000/g, (m, k) => '<code>' + codes[+k] + '</code>');
}

function mdToHtml(src) {
  const lines = String(src || '').split(/\r?\n/);
  const out = [];
  let para = [];
  let list = [];
  const endPara = () => { if (para.length) { out.push('<p>' + para.join(' ') + '</p>'); para = []; } };
  const endList = () => { if (list.length) { out.push('<ul>' + list.join('') + '</ul>'); list = []; } };
  for (let k = 0; k < lines.length; k++) {
    const raw = lines[k];
    if (/^```/.test(raw)) {
      endPara(); endList();
      const buf = [];
      for (k++; k < lines.length && !/^```/.test(lines[k]); k++) buf.push(mdEscape(lines[k]));
      out.push('<pre><code>' + buf.join('\n') + '</code></pre>');
      continue;                        /* loop's k++ steps past the closing fence */
    }
    const hm = raw.match(/^(#{1,3})\s+(.+)$/);
    if (hm) {
      endPara(); endList();
      const lvl = hm[1].length;
      out.push('<h' + lvl + '>' + mdInline(mdEscape(hm[2])) + '</h' + lvl + '>');
      continue;
    }
    const lm = raw.match(/^\s*-\s+(.+)$/);
    if (lm) {
      endPara();
      list.push('<li>' + mdInline(mdEscape(lm[1])) + '</li>');
      continue;
    }
    if (!raw.trim()) { endPara(); endList(); continue; }
    endList();
    para.push(mdInline(mdEscape(raw)));
  }
  endPara(); endList();
  return out.join('\n');
}

/* ────────────────────────── auth + API ────────────────────────── */

let token = localStorage.getItem(TOKEN_KEY) || '';
let username = localStorage.getItem(USER_KEY) || '';
let role = localStorage.getItem(ROLE_KEY) || '';   /* '' until /api/me answers */
let pendingHash = '';

function setAuth(tok, user) {
  token = tok || '';
  username = user || '';
  if (token) {
    localStorage.setItem(TOKEN_KEY, token);
    localStorage.setItem(USER_KEY, username);
  } else {
    localStorage.removeItem(TOKEN_KEY);
    localStorage.removeItem(USER_KEY);
    setRole('');
  }
  updateUserbox();
}

function setRole(r) {
  role = r || '';
  if (token && role) localStorage.setItem(ROLE_KEY, role);
  else localStorage.removeItem(ROLE_KEY);
  updateUserbox();
}

/* fetch + cache the caller's role (login & boot); re-renders a waiting
   #/admin view once the role becomes known */
async function refreshRole() {
  if (!token) return;
  try {
    const me = await api('/api/me');
    if (!me || !token) return;
    if (me.username && me.username !== username) {
      username = me.username;
      localStorage.setItem(USER_KEY, username);
      updateUserbox();
    }
    const prev = role;
    setRole(me.role || '');
    if (role !== prev && parseRoute().view === 'admin') render();
  } catch (err) { /* 401 already handled by api() */ }
}

function authLost() {
  if (!token) return;
  setAuth('', '');
  if (parseRoute().view !== 'login') {
    pendingHash = location.hash;
    navigate('#/login');
  } else {
    render();
  }
}

/* Path prefix the app is served under ("" at the site root). Lets a reverse
   proxy mount the whole app at e.g. /avb_investigation/ with no rebuild:
   every API/WS request below is made relative to this base. */
const BASE = location.pathname.replace(/[^/]*$/, '').replace(/\/$/, '');

/* api(path, opts) — fetch wrapper.
   opts: method, json (object body), body (raw body), contentType, auth:false to
   skip the bearer header and the 401-redirect (login/register). */
async function api(path, opts) {
  opts = opts || {};
  const headers = Object.assign({}, opts.headers || {});
  const useAuth = opts.auth !== false;
  if (useAuth && token) headers['Authorization'] = 'Bearer ' + token;
  const init = { method: opts.method || 'GET', headers };
  if (opts.json !== undefined) {
    headers['Content-Type'] = 'application/json';
    init.body = JSON.stringify(opts.json);
  } else if (opts.body !== undefined) {
    init.body = opts.body;
    if (opts.contentType) headers['Content-Type'] = opts.contentType;
  }
  let res;
  try {
    res = await fetch(BASE + path, init);
  } catch (err) {
    throw new Error('network error — backend unreachable');
  }
  if (res.status === 401 && useAuth) {
    authLost();
    throw new Error('session expired — please log in again');
  }
  let body = null;
  try { body = await res.json(); } catch (err) { body = null; }
  if (!res.ok) {
    const err = new Error((body && body.error) ? body.error : (res.status + ' ' + res.statusText));
    err.status = res.status;   /* callers branch on 409 (notes conflict flow) */
    err.body = body;
    throw err;
  }
  return body;
}

/* Upload a file with progress. fetch() cannot report upload progress, so use
   XMLHttpRequest. onProgress(fraction|null, sent, total, sendingDone) fires as
   bytes go out (fraction null when the length is unknown); once the last byte
   is sent it fires with sendingDone=true so the UI can show "processing" while
   the server validates/decompresses. Resolves with parsed JSON, or rejects
   with an Error carrying the server's {error} message when present. */
function uploadWithProgress(path, file, contentType, onProgress) {
  return new Promise((resolve, reject) => {
    const xhr = new XMLHttpRequest();
    xhr.open('POST', BASE + path);
    if (token) xhr.setRequestHeader('Authorization', 'Bearer ' + token);
    if (contentType) xhr.setRequestHeader('Content-Type', contentType);
    xhr.upload.addEventListener('progress', (ev) => {
      if (onProgress) onProgress(ev.lengthComputable ? ev.loaded / ev.total : null,
        ev.loaded, ev.total, false);
    });
    xhr.upload.addEventListener('load', () => {
      if (onProgress) onProgress(1, file.size, file.size, true);
    });
    xhr.addEventListener('load', () => {
      let body = null;
      try { body = JSON.parse(xhr.responseText); } catch (e) { body = null; }
      if (xhr.status >= 200 && xhr.status < 300) { resolve(body); return; }
      if (xhr.status === 401) { authLost(); reject(new Error('session expired — please log in again')); return; }
      reject(new Error((body && body.error) ? body.error
        : (xhr.status ? xhr.status + ' ' + (xhr.statusText || 'upload failed') : 'upload failed')));
    });
    xhr.addEventListener('error', () => reject(new Error('network error — backend unreachable')));
    xhr.addEventListener('abort', () => reject(new Error('upload cancelled')));
    xhr.send(file);
  });
}

async function doLogout() {
  try { await api('/api/logout', { method: 'POST' }); } catch (err) { /* best effort */ }
  setAuth('', '');
  navigate('#/login');
}

function updateUserbox() {
  const box = document.getElementById('userbox');
  const name = document.getElementById('user-name');
  if (box && name) {
    box.hidden = !token;
    name.textContent = username;
  }
  const adminLink = document.getElementById('admin-link');
  if (adminLink) adminLink.hidden = !(token && role === 'admin');
  const presenceWrap = document.getElementById('presence-wrap');
  if (presenceWrap) {
    presenceWrap.hidden = !token;
    if (!token) {
      presenceData = [];
      setPresenceOpen(false);
      renderPresence();
    }
  }
}

/* ────────────────────────── presence ──────────────────────────
   Heartbeat (PUT /api/presence {view}) every 10 s while logged in, plus
   immediately on route/tab changes; the topbar chip (#presence) shows the
   online count and its popover (#presence-list) shows who looks at what. */

let presenceViewLabel = '';   /* 'home' | 'session/<id>[:notes]' | 'admin' | '' */
let presenceData = [];        /* last GET /api/presence entries */
let presenceOpen = false;

/* view label -> human wording (kept in sync with the Playwright suite):
   home -> "home" · admin -> "admin panel" · session/s1 -> "session s1"
   session/s1:notes -> "session s1 (notes)" · anything else verbatim */
function humanizeView(v) {
  const s = String(v || '');
  if (s === 'home') return 'home';
  if (s === 'admin') return 'admin panel';
  let m = s.match(/^session\/(.+):notes$/);
  if (m) return 'session ' + m[1] + ' (notes)';
  m = s.match(/^session\/(.+)$/);
  if (m) return 'session ' + m[1];
  return s || '—';
}

function setPresenceView(v) {
  if (v === presenceViewLabel) return;
  presenceViewLabel = v;
  if (token && v) {           /* immediate beat on route/tab change */
    presenceBeat();
    presencePull();
  }
}

async function presenceBeat() {
  if (!token || !presenceViewLabel) return;
  try {
    await api('/api/presence', { method: 'PUT', json: { view: presenceViewLabel } });
  } catch (err) { /* best-effort heartbeat; a 401 already routed to login */ }
}

async function presencePull() {
  if (!token) return;
  try {
    const r = await api('/api/presence');
    presenceData = (r && r.users) || [];
  } catch (err) {
    return;                   /* keep the last good list on transient errors */
  }
  renderPresence();
}

function presenceTick() {     /* 10 s cadence, started once at boot */
  if (!token) return;
  presenceBeat();
  presencePull();
}

function renderPresence() {
  const cnt = document.getElementById('presence-count');
  if (cnt) cnt.textContent = presenceData.length + ' online';
  const list = document.getElementById('presence-list');
  if (!list) return;
  if (!presenceData.length) {
    list.replaceChildren(h('div', { class: 'empty small' }, 'nobody online'));
    return;
  }
  list.replaceChildren(...presenceData.map((u) => h('div', {
    class: 'presence-entry' + (u.username === username ? ' me' : ''),
    dataset: { user: u.username || '', view: u.view || '' },
    title: (u.username || '?') + ' — ' + (u.view || '')
      + (typeof u.idle_s === 'number' ? ' · idle ' + u.idle_s.toFixed(1) + ' s' : ''),
  },
    h('span', { class: 'pe-user' }, u.username || '?'),
    h('span', { class: 'pe-sep' }, ' — '),
    h('span', { class: 'pe-view' }, humanizeView(u.view)),
  )));
}

function setPresenceOpen(open) {
  presenceOpen = !!open && !!token;
  const list = document.getElementById('presence-list');
  const btn = document.getElementById('presence');
  if (list) list.hidden = !presenceOpen;
  if (btn) btn.setAttribute('aria-expanded', presenceOpen ? 'true' : 'false');
  if (presenceOpen) presencePull();   /* refresh whenever the popover opens */
}

/* ────────────────────────── router ────────────────────────── */

let currentView = null;   /* { destroy() } */

function parseRoute() {
  const hash = location.hash || '';
  if (hash.startsWith('#/session/')) {
    return { view: 'session', id: decodeURIComponent(hash.slice('#/session/'.length)) };
  }
  if (hash === '#/home') return { view: 'home' };
  if (hash === '#/admin') return { view: 'admin' };
  if (hash === '#/login') return { view: 'login' };
  return { view: token ? 'home' : 'login' };
}

function navigate(hash) {
  if (location.hash === hash) render();
  else location.hash = hash;
}

function render() {
  if (currentView && currentView.destroy) {
    try { currentView.destroy(); } catch (err) { /* ignore */ }
  }
  currentView = null;
  const app = document.getElementById('app');
  app.replaceChildren();
  const r = parseRoute();
  if (r.view !== 'login' && !token) {
    pendingHash = location.hash;
    navigate('#/login');
    return;
  }
  updateUserbox();
  if (r.view === 'login') {
    setPresenceView('');
    currentView = loginView(app);
  } else if (r.view === 'session') {
    setPresenceView('session/' + r.id);
    currentView = sessionView(app, r.id);
  } else if (r.view === 'admin') {
    setPresenceView('admin');
    currentView = adminView(app);
  } else {
    setPresenceView('home');
    currentView = homeView(app);
  }
}

/* ────────────────────────── login view ────────────────────────── */

function loginView(app) {
  let mode = 'login';
  let busy = false;
  let bootstrap = false;   /* fresh deployment: creating the first admin */

  const errBox = h('div', { class: 'form-error', hidden: true });
  const bootBanner = h('div', { class: 'login-boot', hidden: true },
    h('b', null, 'First-time setup. '),
    'No administrator exists yet — the account you create now becomes the administrator.');
  const userIn = h('input', {
    class: 'input', id: 'f-user', autocomplete: 'username',
    spellcheck: 'false', placeholder: 'username',
  });
  const passIn = h('input', {
    class: 'input', id: 'f-pass', type: 'password',
    autocomplete: 'current-password', placeholder: 'password',
  });
  const submitBtn = h('button', { class: 'btn btn-primary btn-block', type: 'submit' }, 'Log in');
  const hint = h('p', { class: 'form-hint', hidden: true },
    'username: 3–32 chars (letters, digits, _ . -) · password: at least 8 chars');
  const toggle = h('button', {
    class: 'linklike', type: 'button',
    onclick: () => setMode(mode === 'login' ? 'register' : 'login'),
  }, 'No account? Register');

  function setMode(m) {
    mode = m;
    submitBtn.textContent = bootstrap ? 'Create admin account'
      : mode === 'login' ? 'Log in' : 'Register';
    toggle.textContent = mode === 'login' ? 'No account? Register' : 'Have an account? Log in';
    hint.hidden = mode === 'login';
    errBox.hidden = true;
  }

  /* Ask the backend whether it still needs its first admin. */
  (async () => {
    try {
      const b = await api('/api/bootstrap', { auth: false });
      if (b && b.needs_admin) {
        bootstrap = true;
        bootBanner.hidden = false;
        toggle.hidden = true;            /* only path is "create the admin" */
        passIn.autocomplete = 'new-password';
        setMode('register');
      }
    } catch (err) { /* offline / old backend: normal login screen */ }
  })();

  function showErr(msg) {
    errBox.textContent = msg;
    errBox.hidden = false;
  }

  async function submit(ev) {
    ev.preventDefault();
    if (busy) return;
    const u = userIn.value.trim();
    const p = passIn.value;
    if (!u || !p) { showErr('username and password are required'); return; }
    busy = true;
    submitBtn.disabled = true;
    errBox.hidden = true;
    try {
      if (mode === 'register') {
        const reg = await api('/api/register', { method: 'POST', json: { username: u, password: p }, auth: false });
        if (bootstrap && reg && reg.role === 'admin') toast('administrator account created');
      }
      const r = await api('/api/login', { method: 'POST', json: { username: u, password: p }, auth: false });
      setAuth(r.token, r.username || u);
      await refreshRole();   /* role known before routing (e.g. into #/admin) */
      const dest = (pendingHash && pendingHash.startsWith('#/') && pendingHash !== '#/login') ? pendingHash : '#/home';
      pendingHash = '';
      navigate(dest);
    } catch (err) {
      showErr(err.message);
      busy = false;
      submitBtn.disabled = false;
    }
  }

  app.appendChild(
    h('div', { class: 'login-wrap' },
      h('form', { class: 'login-card', onsubmit: submit },
        h('h1', { class: 'login-title' }, 'AVB ', h('span', null, 'Introspection')),
        h('p', { class: 'login-sub' }, 'Milan / AVB protocol analyzer'),
        bootBanner,
        errBox,
        h('label', { class: 'field-label', for: 'f-user' }, 'Username'),
        userIn,
        h('label', { class: 'field-label', for: 'f-pass' }, 'Password'),
        passIn,
        hint,
        submitBtn,
        h('div', { class: 'login-toggle' }, toggle),
      ),
    ),
  );
  userIn.focus();
  return { destroy() {} };
}

/* ────────────────────────── home view ────────────────────────── */

function homeView(app) {
  let alive = true;
  let pollTimer = 0;
  let netErrShown = false;

  const metricsBox = h('div', { class: 'metrics-strip' });
  const pcapList = h('div', { class: 'plist' });
  const sessList = h('div', { class: 'slist' });
  const selectedPcaps = new Set();   /* library pcap ids ticked for combining */
  const combineBtn = h('button', { class: 'btn btn-primary btn-sm', type: 'button' }, 'Combine into a session');
  combineBtn.addEventListener('click', () => combineSelected());
  const combineBar = h('div', { class: 'combine-bar', hidden: true },
    h('span', { class: 'combine-msg dim small' }), h('span', { class: 'toolbar-spacer' }), combineBtn);
  const fileIn = h('input', {
    type: 'file', hidden: true,
    accept: '.pcap,.pcapng,.cap,.gz,.xz,.zst,.zstd,.bz2,.lz4,.lz,.Z,.zip',
    onchange: () => { if (fileIn.files && fileIn.files[0]) uploadFile(fileIn.files[0]); },
  });
  const uploadBtn = h('button', {
    class: 'btn btn-primary', type: 'button',
    title: 'pcap / pcapng, optionally compressed (.gz .xz .zst .bz2 .lz4 .lz .Z .zip)',
    onclick: () => { fileIn.value = ''; fileIn.click(); },
  }, 'Upload pcap…');
  const newFolderBtn = h('button', {
    class: 'btn btn-sm', type: 'button',
    title: 'create a library folder to organise captures',
    onclick: () => newFolder(),
  }, 'New folder…');

  const uploadBox = h('div', { class: 'upbox', hidden: true });
  const sessHead = h('div', { class: 'slist-head' },
    h('span', null, 'Name'), h('span', null, 'Status'), h('span', { class: 'num' }, 'Packets'),
    h('span', { class: 'num' }, 'Events'), h('span', { class: 'num' }, 'Errors'),
    h('span', { class: 'num' }, 'Duration'), h('span', null, 'Created'), h('span', null, ''),
  );
  const sessPanel = h('section', { class: 'panel' },
    h('div', { class: 'panel-head' }, h('h2', null, 'Analysis sessions')),
    sessHead,
    sessList,
  );
  const pcapPanel = h('section', { class: 'panel' },
    h('div', { class: 'panel-head', id: 'pcap-panel-head' },
      h('h2', null, 'Uploaded pcaps'), newFolderBtn, uploadBtn, fileIn),
    uploadBox,
    combineBar,
    pcapList,
  );
  app.appendChild(
    h('div', { class: 'home' },
      metricsBox,
      pcapPanel,
      sessPanel,
    ),
  );
  makeColsResizable(sessHead, sessPanel, '--sesscols', 'sessions');

  /* progress bar / processing state / persistent error, shown in-panel */
  function uploadShow(name) {
    uploadBox.hidden = false;
    uploadBox.className = 'upbox';
    uploadBox.replaceChildren(
      h('div', { class: 'upbox-row' },
        h('span', { class: 'upbox-name', title: name }, name),
        h('span', { class: 'upbox-pct' }, '0%')),
      h('div', { class: 'upbox-track' }, h('div', { class: 'upbox-fill' })));
  }
  function uploadProgress(frac, done) {
    const fill = uploadBox.querySelector('.upbox-fill');
    const pct = uploadBox.querySelector('.upbox-pct');
    if (!fill || !pct) return;
    if (done || frac == null) {
      fill.style.width = '100%';
      uploadBox.classList.add('is-proc');
      pct.textContent = 'processing…';   /* server validating / decompressing */
    } else {
      const p = Math.round(frac * 100);
      fill.style.width = p + '%';
      pct.textContent = p + '%';
    }
  }
  function uploadHide() { uploadBox.hidden = true; uploadBox.replaceChildren(); }
  function uploadError(name, msg) {
    uploadBox.hidden = false;
    uploadBox.className = 'upbox is-error';
    uploadBox.replaceChildren(
      h('div', { class: 'upbox-row' },
        h('span', { class: 'upbox-err' }, '✕ ' + name + ' — ' + msg),
        h('button', {
          class: 'upbox-x', type: 'button', title: 'dismiss', onclick: uploadHide,
        }, '✕')));
  }

  /* upload only adds to the library — the user starts analysis explicitly
     (Analyze / Combine), so bulk uploads don't open a session per file */
  async function uploadFile(file) {
    uploadBtn.disabled = true;
    uploadShow(file.name);
    const folder = pcapCwd;   /* land the upload in the folder being viewed */
    try {
      await uploadWithProgress('/api/pcaps?name=' + encodeURIComponent(file.name)
        + (folder ? '&folder=' + encodeURIComponent(folder) : ''),
        file, 'application/octet-stream',
        (frac, sent, total, done) => uploadProgress(frac, done));
      uploadHide();
      toast(folder ? 'uploaded ' + file.name + ' → ' + folder : 'uploaded ' + file.name);
      /* stay in the current folder — the file landed here, so it's visible */
      refresh();
    } catch (err) {
      uploadError(file.name, err.message);   /* stays until dismissed / next upload */
    } finally {
      uploadBtn.disabled = false;
    }
  }

  async function analyzePcap(pcapId, btn) {
    btn.disabled = true;
    try {
      const s = await api('/api/sessions', { method: 'POST', json: { pcap_id: pcapId } });
      navigate('#/session/' + encodeURIComponent(s.id));
    } catch (err) {
      toast('analyze failed: ' + err.message, 'error');
      btn.disabled = false;
    }
  }

  function updateCombineBar() {
    const n = selectedPcaps.size;
    combineBar.hidden = n < 2;
    if (n >= 2) combineBar.querySelector('.combine-msg').textContent =
      n + ' pcaps selected — merged onto one timeline by capture time (overlapping windows interleave).';
  }

  async function combineSelected() {
    const ids = [...selectedPcaps];
    if (ids.length < 2) return;
    combineBtn.disabled = true;
    try {
      const s = await api('/api/sessions', { method: 'POST', json: { pcap_ids: ids } });
      navigate('#/session/' + encodeURIComponent(s.id));
    } catch (err) {
      /* backend rejects overlapping / relative-timestamp combinations */
      toast('combine failed: ' + err.message, 'error');
      combineBtn.disabled = false;
    }
  }

  async function deleteSession(id) {
    if (!window.confirm('Delete session ' + id + '?')) return;
    try {
      await api('/api/sessions/' + encodeURIComponent(id), { method: 'DELETE' });
      toast('session deleted');
      refresh();
    } catch (err) {
      toast('delete failed: ' + err.message, 'error');
    }
  }

  /* ── library file-explorer (folders are flat, one level under the root) ──
     Navigate into a folder to see its captures; the breadcrumb always starts
     at "root". Move a capture by dragging its row onto a folder (or the
     "root" crumb / panel header), or via the per-row move menu. ── */
  let pcapCwd = '';           // current folder, '' = library root
  let lastPcaps = [], lastFolders = [];

  async function movePcap(pid, folder) {
    try {
      await api('/api/pcaps/' + encodeURIComponent(pid), { method: 'PUT', json: { folder } });
      toast(folder ? 'moved to ' + folder : 'moved to root');
      refresh();
    } catch (err) {
      toast('move failed: ' + err.message, 'error');
    }
  }

  async function newFolder() {
    const name = window.prompt('New folder name:');
    if (!name || !name.trim()) return;
    try {
      await api('/api/pcaps/folders', { method: 'POST', json: { name: name.trim() } });
      pcapCwd = name.trim();   /* open the new folder so it's obvious where it is */
      refresh();
    } catch (err) {
      toast('create folder failed: ' + err.message, 'error');
    }
  }

  async function deleteFolder(name) {
    try {
      await api('/api/pcaps/folders/' + encodeURIComponent(name), { method: 'DELETE' });
      if (pcapCwd === name) pcapCwd = '';
      refresh();
    } catch (err) {
      toast('delete folder failed: ' + err.message, 'error');
    }
  }

  async function deletePcap(p) {
    if (!window.confirm('Delete "' + p.name + '" from the library?\n\n'
        + 'Existing sessions keep their own capture copy and are not affected.')) return;
    try {
      await api('/api/pcaps/' + encodeURIComponent(p.id), { method: 'DELETE' });
      toast('deleted ' + p.name);
      refresh();
    } catch (err) {
      toast('delete failed: ' + err.message, 'error');
    }
  }

  function dropTarget(el, folder) {
    el.addEventListener('dragover', (ev) => { ev.preventDefault(); el.classList.add('is-drop'); });
    el.addEventListener('dragleave', () => el.classList.remove('is-drop'));
    el.addEventListener('drop', (ev) => {
      ev.preventDefault();
      el.classList.remove('is-drop');
      const pid = ev.dataTransfer.getData('text/pcap-id');
      if (pid) movePcap(pid, folder);
    });
  }

  function pcapRow(p, folders) {
    const btn = h('button', { class: 'btn btn-sm prow-analyze', type: 'button' }, 'Analyze');
    btn.addEventListener('click', () => analyzePcap(p.id, btn));
    const chk = h('input', {
      type: 'checkbox', class: 'prow-chk', checked: selectedPcaps.has(p.id),
      title: 'select to combine several pcaps into one session',
    });
    chk.addEventListener('change', () => {
      if (chk.checked) selectedPcaps.add(p.id); else selectedPcaps.delete(p.id);
      updateCombineBar();
    });
    const delBtn = role === 'admin' ? h('button', {
      class: 'btn btn-danger btn-sm prow-del', type: 'button',
      title: 'delete this capture from the library (admin)',
      onclick: () => deletePcap(p),
    }, 'Delete') : null;
    /* grid columns match .plib-head so column widths are resizable together.
       Moving between folders is drag-and-drop (onto a folder or “root”). */
    const row = h('div', {
      class: 'prow', draggable: 'true',
      title: 'drag onto a folder (or “root”) to move',
    },
      h('div', { class: 'prow-name' }, chk, h('span', { class: 'prow-nm', title: p.name }, p.name)),
      h('span', { class: 'prow-size dim mono small' }, fmtBytes(p.size)),
      h('span', { class: 'prow-date dim small' }, fmtDate(p.uploaded_at)),
      h('div', { class: 'prow-actions' }, btn, delBtn),
    );
    row.addEventListener('dragstart', (ev) => {
      ev.dataTransfer.setData('text/pcap-id', p.id);
      ev.dataTransfer.effectAllowed = 'move';
      row.classList.add('is-dragging');
    });
    row.addEventListener('dragend', () => row.classList.remove('is-dragging'));
    return row;
  }

  function libHeader() {
    return h('div', { class: 'plib-head' },
      h('span', null, 'Name'),
      h('span', { class: 'num' }, 'Size'),
      h('span', null, 'Uploaded'),
      h('span', null, ''));
  }

  function folderRow(name, list) {
    const row = h('div', {
      class: 'pexp-folder', role: 'button', tabindex: '0',
      title: 'open folder “' + name + '” · drop a capture here to move it',
    },
      h('span', { class: 'pexp-fico' }, '📂'),
      h('span', { class: 'pexp-fname' }, name),
      h('span', { class: 'dim small' },
        list.length + (list.length === 1 ? ' capture' : ' captures')),
      h('span', { class: 'toolbar-spacer' }),
      !list.length ? h('button', {
        class: 'btn btn-ghost btn-sm', type: 'button',
        title: 'delete this empty folder',
        onclick: (ev) => { ev.stopPropagation(); deleteFolder(name); },
      }, '✕') : null);
    const open = () => { pcapCwd = name; renderLibrary(); };
    row.addEventListener('click', (ev) => { if (ev.target.closest('button')) return; open(); });
    row.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); open(); }
    });
    dropTarget(row, name);
    return row;
  }

  function crumbBar() {
    const root = h('button', {
      class: 'pexp-seg' + (pcapCwd ? '' : ' is-cur'), type: 'button',
      title: pcapCwd ? 'back to the library root' : 'library root',
    }, '📁 root');
    root.addEventListener('click', () => { pcapCwd = ''; renderLibrary(); });
    dropTarget(root, '');   /* drop here to move a capture back to the root */
    const bar = h('div', { class: 'pexp-crumb' }, root);
    if (pcapCwd) {
      bar.appendChild(h('span', { class: 'pexp-sep' }, '›'));
      bar.appendChild(h('span', { class: 'pexp-seg is-cur' }, '📂 ' + pcapCwd));
    }
    return bar;
  }

  function renderPcaps(pcaps, folders) {
    lastPcaps = pcaps;
    lastFolders = folders;
    renderLibrary();
  }

  function renderLibrary() {
    const pcaps = lastPcaps, folders = lastFolders;
    const live = new Set(pcaps.map((p) => p.id));
    for (const id of [...selectedPcaps]) if (!live.has(id)) selectedPcaps.delete(id);
    /* the panel header is a "move back to root" drop zone */
    const panelHead = document.getElementById('pcap-panel-head');
    if (panelHead && !panelHead.dataset.drop) {
      panelHead.dataset.drop = '1';
      dropTarget(panelHead, '');
    }
    if (pcapCwd && !folders.includes(pcapCwd)) pcapCwd = '';   /* folder went away */

    if (!pcaps.length && !folders.length) {
      selectedPcaps.clear();
      updateCombineBar();
      pcapList.replaceChildren(h('div', { class: 'empty' }, 'No pcaps yet — upload one.'));
      return;
    }
    const byFolder = new Map([['', []]]);
    for (const f of folders) byFolder.set(f, []);
    for (const p of pcaps) {
      const key = byFolder.has(p.folder || '') ? (p.folder || '') : '';
      byFolder.get(key).push(p);
    }

    const out = [crumbBar()];
    let header = null;
    const files = pcapCwd ? (byFolder.get(pcapCwd) || []) : byFolder.get('');
    if (!pcapCwd) for (const f of folders) out.push(folderRow(f, byFolder.get(f) || []));
    if (files.length) {
      header = libHeader();
      out.push(header);
      for (const p of files) out.push(pcapRow(p, folders));
    } else if (pcapCwd) {
      out.push(h('div', { class: 'empty small' },
        'This folder is empty — drag captures onto it, or use a row’s move menu.'));
    } else if (!folders.length) {
      out.push(h('div', { class: 'empty small' }, 'Empty library.'));
    }
    pcapList.replaceChildren(...out);
    /* header is in the DOM now — make the columns drag-resizable (shared
       widths across every capture row via the --libcols variable) */
    if (header) makeColsResizable(header, pcapPanel, '--libcols', 'library');
    updateCombineBar();
  }

  function renderSessions(sessions) {
    if (!sessions.length) {
      sessList.replaceChildren(h('div', { class: 'empty' },
        'No sessions yet — upload a pcap or open one by path.'));
      return;
    }
    sessList.replaceChildren(...sessions.map((s) => {
      const delBtn = h('button', { class: 'btn btn-danger btn-sm', type: 'button', title: 'Delete session' }, 'Delete');
      delBtn.addEventListener('click', (ev) => { ev.stopPropagation(); deleteSession(s.id); });
      const row = h('div', {
        class: 'srow', role: 'button', tabindex: '0',
        onkeydown: (ev) => { if (ev.key === 'Enter') navigate('#/session/' + encodeURIComponent(s.id)); },
      },
        h('span', { class: 'srow-name', title: s.name }, s.name || s.id),
        h('span', null, sessionStatusBadge(s)),
        h('span', { class: 'num mono' }, fmtInt(s.packets)),
        h('span', { class: 'num mono' }, fmtInt(s.events)),
        h('span', { class: 'num mono' + (s.decode_errors ? ' errtext' : '') }, fmtInt(s.decode_errors)),
        h('span', { class: 'num mono' }, fmtDur(s.duration)),
        h('span', { class: 'dim small' }, fmtDate(s.created_at)),
        h('span', { class: 'srow-actions' }, delBtn),
      );
      row.addEventListener('click', () => navigate('#/session/' + encodeURIComponent(s.id)));
      return row;
    }));
  }

  function renderMetrics(m) {
    metricsBox.replaceChildren(...metricTiles(m));
  }

  async function refresh() {
    if (!alive) return;
    const results = await Promise.allSettled([
      api('/api/pcaps'),
      api('/api/sessions'),
      api('/api/metrics'),
    ]);
    if (!alive) return;
    let anyRunning = false;
    let anyErr = null;
    if (results[0].status === 'fulfilled') {
      renderPcaps(results[0].value.pcaps || [], results[0].value.folders || []);
    } else anyErr = results[0].reason;
    if (results[1].status === 'fulfilled') {
      const sessions = results[1].value.sessions || [];
      renderSessions(sessions);
      anyRunning = sessions.some((s) => s.status === 'running');
    } else anyErr = results[1].reason;
    if (results[2].status === 'fulfilled') renderMetrics(results[2].value);
    if (anyErr && !netErrShown) {
      netErrShown = true;
      toast(anyErr.message, 'error');
    } else if (!anyErr) {
      netErrShown = false;
    }
    clearTimeout(pollTimer);
    if (alive && anyRunning) pollTimer = setTimeout(refresh, 2000);
  }

  pcapList.replaceChildren(h('div', { class: 'empty' }, 'Loading…'));
  sessList.replaceChildren(h('div', { class: 'empty' }, 'Loading…'));
  refresh();

  return {
    destroy() {
      alive = false;
      clearTimeout(pollTimer);
    },
  };
}

function sessionStatusBadge(s) {
  const st = s.status || '';
  let cls = 'st-neutral';
  if (st === 'running') cls = 'st-run';
  else if (st === 'done') cls = 'st-good';
  else if (st === 'error') cls = 'st-bad';
  return h('span', { class: 'sbadge ' + cls, title: st === 'error' ? (s.error || '') : '' }, st || '?');
}

/* ────────────────────────── shared render helpers ──────────────────────────
   (used by the home, session and admin views) */

function metric(label, value, title) {
  return h('div', { class: 'metric', title: title || '' },
    h('div', { class: 'm-label' }, label),
    h('div', { class: 'm-value mono' }, value),
  );
}

/* GET /api/metrics payload -> the home/admin metrics-strip tiles */
function metricTiles(m) {
  if (!m || !m.process) return [];
  const pr = m.process;
  const pool = m.pool || {};
  const cpu = (pr.cpu_user_s || 0) + (pr.cpu_sys_s || 0);
  return [
    metric('CPU', cpu.toFixed(1) + ' s', 'user ' + (pr.cpu_user_s || 0) + ' s + sys ' + (pr.cpu_sys_s || 0) + ' s'),
    metric('RSS', ((pr.rss_kb || 0) / 1024).toFixed(1) + ' MB'),
    metric('Uptime', fmtUptime(pr.uptime_s)),
    metric('Threads', String(pr.threads !== undefined ? pr.threads : '—')),
    metric('Pool', (pool.active || 0) + ' active / ' + (pool.threads || 0) + ' (max ' + (pool.max_threads || 0) + ')'),
    metric('Queued', fmtInt(pool.queued)),
    metric('Clients', fmtInt((m.clients || []).length)),
    metric('Sessions', fmtInt((m.sessions || []).length)),
  ];
}

function stateClass(sName) {
  const u = String(sName || '').toUpperCase();
  if (u.includes('FAIL') || u.includes('TIMED_OUT') || u === 'LOST'
    || u === 'MISMATCH' || u === 'PRIORITY_INVERSION' || u === 'NOT_AS_CAPABLE'
    || u.includes('ERROR')) return 'st-bad';
  if (u === 'TIEBREAK') return 'st-warn';
  if (u === 'DEFENDING') return 'st-serious';
  if (u === 'AVAILABLE' || u === 'ESTABLISHED' || u === 'REGISTERED' || u === 'ACQUIRED'
    || u === 'CONNECTED' || u === 'READY' || u === 'SUCCESS' || u === 'ADVERTISE'
    || u === 'HEALTHY' || u === 'MATCH' || u === 'GM_PRESENT'
    || u === 'AS_CAPABLE' || u === 'MASTER' || u === 'CONVERGED'
    || u === 'GPTP_CAPABLE' || u === 'RECEIVED') return 'st-good';
  if (u === 'PENDING' || u === 'PROBING' || u === 'CONNECTING' || u === 'LEAVING'
    || u === 'DEPARTING' || u === 'DISCONNECTING' || u === 'NO_GM'
    || u === 'AGED' || u.includes('ASKING')) return 'st-warn';
  return 'st-neutral';
}

function stateBadge(sName, small) {
  return h('span', { class: 'sbadge ' + stateClass(sName) + (small ? ' sm' : '') }, String(sName));
}

function kvList(pairs) {
  const kids = [];
  for (const pair of pairs) {
    if (!pair) continue;
    const [k, v] = pair;
    if (v === undefined || v === null || v === '') continue;
    kids.push(h('span', { class: 'kv' },
      h('span', { class: 'kv-k' }, k + ' '),
      v instanceof Node ? v : h('span', { class: 'kv-v mono' }, String(v))));
  }
  return kids.length ? h('div', { class: 'sobj-kv' }, kids) : null;
}

/* ────────────────────────── state-machine diagrams ──────────────────────────
   drawMachine(container, def, live) renders one Milan/AVB state machine as an
   SVG the way it appears in the spec, with the live reconstructed state
   overlaid. Pure, module-level, theme-driven (see the .sm-* rules in the CSS).

   def  = { title, subtitle, accent, view:{x,y,w,h}, minW, reference,
            states:[{id,label?,sub?,x,y}], edges:[...], note? }
   edge = { from, to, label?, labelAt?,
            fromSide?/fromT?, toSide?/toT?,   // 'L'|'R'|'T'|'B' + 0..1 along it
            curve?,                            // quadratic bend magnitude (signed)
            via? }                             // [{x,y}] orthogonal waypoints
   live = { current:'<stateId>'|null, history:[{from,to,...}], visited:Set } */

const SM_NW = 152;    /* node width (user units) */
const SM_NH = 46;     /* node height */
let smUid = 0;        /* per-diagram id prefix so <marker> ids stay unique */
/* hooks set once by sessionView so drawMachine's edge-trigger popover can
   format times and jump to a triggering packet (both live in that closure) */
let smFmtTime = (t) => String(t);
let smJumpToPacket = null;
let smJumpToEvent = null;    /* jump to a transition event by index (sessionView) */
let smTransEventIdx = null;  /* map a trigger transition -> event index, or -1 */
let smEdgePop = null;   /* the single open edge-trigger popover, if any */

let smEdgePopDoc = null;   /* document holding the popover (may be a popup window's) */
function closeEdgePop() {
  if (smEdgePop) { smEdgePop.remove(); smEdgePop = null; }
  const d = smEdgePopDoc || document;
  d.removeEventListener('mousedown', onEdgePopAway, true);
  d.removeEventListener('keydown', onEdgePopKey, true);
  smEdgePopDoc = null;
}
function onEdgePopAway(ev) { if (smEdgePop && !smEdgePop.contains(ev.target)) closeEdgePop(); }
function onEdgePopKey(ev) { if (ev.key === 'Escape') closeEdgePop(); }

/* the jump control for one trigger row: its causing packet ("pkt N"), else the
   derived transition event itself ("◆ event"), else a static "timer" label */
function edgeTrigLink(t) {
  if (typeof t.n === 'number' && t.n > 0 && smJumpToPacket)
    return h('button', {
      class: 'linklike mono smpop-pkt', type: 'button',
      /* focus the main window: the jump may be clicked from a popup */
      onclick: () => { const n = t.n; closeEdgePop(); smJumpToPacket(n); window.focus(); },
    }, 'pkt ' + t.n);
  const ei = smTransEventIdx ? smTransEventIdx(t) : -1;
  if (ei >= 0 && smJumpToEvent)
    return h('button', {
      class: 'linklike mono smpop-pkt', type: 'button',
      title: 'go to this derived state event (# ' + ei + ' in the table)',
      onclick: () => { closeEdgePop(); smJumpToEvent(ei); window.focus(); },
    }, '◆ #' + ei);
  return h('span', { class: 'dim mono smpop-nopkt',
    title: 'not tied to a single packet (timer / derived event)' }, 'timer');
}

/* popover listing every observed event that drove one transition (from→to),
   each with its time and a jump-to-packet / jump-to-event link */
function showEdgeTriggers(ev, edge, triggers, def) {
  closeEdgePop();
  const evName = Array.isArray(edge.label) ? edge.label.join(' ') : (edge.label || '');
  const rows = triggers.map((t) => h('div', { class: 'smpop-row' },
    h('span', { class: 'mono smpop-ts' }, smFmtTime(t.ts)),
    h('span', { class: 'smpop-why', title: t.why || '' }, t.why || evName || (def && def.title) || ''),
    edgeTrigLink(t)));
  const pop = h('div', { class: 'smpop', role: 'dialog' },
    h('div', { class: 'smpop-head' },
      h('span', { class: 'smpop-title' }, String(edge.from) + ' → ' + String(edge.to)),
      h('span', { class: 'smpop-count dim' },
        triggers.length + (triggers.length === 1 ? ' event' : ' events'))),
    evName ? h('div', { class: 'smpop-evt dim small' },
      'triggering event: ', h('span', { class: 'mono' }, evName)) : null,
    triggers.length ? h('div', { class: 'smpop-rows' }, rows)
      : h('div', { class: 'smpop-empty dim small' }, 'not observed in this capture'));
  /* anchor in whichever document the click happened in (inline panel OR a
     per-device popup window) */
  const doc = (ev && ev.target && ev.target.ownerDocument) || document;
  const win = doc.defaultView || window;
  doc.body.appendChild(pop);
  smEdgePop = pop;
  smEdgePopDoc = doc;
  const r = pop.getBoundingClientRect(), pad = 8;
  const cx = ev && ev.clientX ? ev.clientX : 60, cy = ev && ev.clientY ? ev.clientY : 60;
  let x = cx + 12, y = cy + 8;
  if (x + r.width + pad > win.innerWidth) x = win.innerWidth - r.width - pad;
  if (y + r.height + pad > win.innerHeight) y = cy - r.height - 8;
  pop.style.left = Math.max(pad, x) + 'px';
  pop.style.top = Math.max(pad, y) + 'px';
  setTimeout(() => {
    doc.addEventListener('mousedown', onEdgePopAway, true);
    doc.addEventListener('keydown', onEdgePopKey, true);
  }, 0);
}

/* ── collapsible cards + per-protocol grouping ─────────────────────────────
   Fold state persists (by key) across re-renders so scrubbing / reselecting
   doesn't re-expand what the user folded. */
const smCollapsed = new Set();       /* folded machine cards, by key */
const smGroupCollapsed = new Set();  /* folded protocol groups, by key */

function foldSquare(expanded) {
  return h('button', {
    class: 'sm-fold', type: 'button',
    'aria-expanded': expanded ? 'true' : 'false', title: 'collapse / expand',
  });
}

/* add a square fold toggle to a .machine-card (header stays; body hides) */
function foldableCard(card, key) {
  const head = card.querySelector(':scope > .machine-head');
  if (!head || card.classList.contains('is-foldable')) return card;
  card.classList.add('is-foldable');
  if (key && smCollapsed.has(key)) card.classList.add('is-collapsed');
  const btn = foldSquare(!card.classList.contains('is-collapsed'));
  const toggle = () => {
    const c = card.classList.toggle('is-collapsed');
    btn.setAttribute('aria-expanded', c ? 'false' : 'true');
    if (key) { if (c) smCollapsed.add(key); else smCollapsed.delete(key); }
  };
  btn.addEventListener('click', (e) => { e.stopPropagation(); toggle(); });
  head.insertBefore(btn, head.firstChild);
  head.classList.add('is-foldhead');
  head.addEventListener('click', (e) => {
    if (e.target.closest('button, a, input, select, textarea, .linklike')) return;
    toggle();
  });
  return card;
}

/* wrap machine cards of one protocol in a foldable, colour-coded group */
function protoGroup(label, protoKey, cards, groupKey) {
  const kids = (cards || []).filter(Boolean);
  if (!kids.length) return null;
  const collapsed = groupKey && smGroupCollapsed.has(groupKey);
  const btn = foldSquare(!collapsed);
  const head = h('div', { class: 'sm-group-head is-foldhead' },
    btn,
    h('span', { class: 'sm-group-dot' }),
    h('span', { class: 'sm-group-title' }, label),
    h('span', { class: 'sm-group-count dim small' },
      kids.length + (kids.length === 1 ? ' machine' : ' machines')));
  const group = h('div', {
    class: 'sm-group' + (collapsed ? ' is-collapsed' : ''),
    dataset: { proto: protoKey },
    style: '--pc:' + (PROTO_COLORS[protoKey] || 'var(--muted)'),
  }, head, h('div', { class: 'sm-group-body' }, kids));
  const toggle = () => {
    const c = group.classList.toggle('is-collapsed');
    btn.setAttribute('aria-expanded', c ? 'false' : 'true');
    if (groupKey) { if (c) smGroupCollapsed.add(groupKey); else smGroupCollapsed.delete(groupKey); }
  };
  btn.addEventListener('click', (e) => { e.stopPropagation(); toggle(); });
  head.addEventListener('click', (e) => {
    if (e.target.closest('button, a, .linklike')) return;
    toggle();
  });
  return group;
}

/* ── resizable table columns ──────────────────────────────────────────────
   Works on any header-row + sibling-rows grid table: header cells get a drag
   grip on their right edge; dragging writes a px track list into a CSS
   variable on `scope`, which the shared grid-template-columns rule reads
   (grid-template-columns: var(<varName>, <stylesheet default>)). The last
   column stays flexible so the table keeps filling its container. Widths
   persist per `key`; double-clicking a grip resets to the defaults.
   Grips are absolutely positioned so they never become grid items. */
function makeColsResizable(head, scope, varName, key) {
  if (!head || !scope || head.dataset.gripped) return;
  head.dataset.gripped = '1';
  head.classList.add('has-grips');
  const store = 'avb.cols.' + key;
  const cells = [...head.children];
  let widths = null;                    /* px per column; null = flexible */
  try { widths = JSON.parse(localStorage.getItem(store) || 'null'); } catch { widths = null; }
  if (!Array.isArray(widths) || widths.length !== cells.length) widths = null;
  const grips = [];
  const place = () => {
    for (const g of grips) g.style.left = (g._cell.offsetLeft + g._cell.offsetWidth - 4) + 'px';
  };
  const apply = () => {
    if (widths) {
      scope.style.setProperty(varName, widths.map((w, i) =>
        (w == null || i === widths.length - 1) ? 'minmax(60px, 1fr)' : Math.round(w) + 'px').join(' '));
    } else {
      scope.style.removeProperty(varName);
    }
    place();
  };
  cells.forEach((cell, i) => {
    if (i === cells.length - 1) return;     /* last column always flexes */
    const g = h('span', { class: 'col-grip', title: 'drag to resize · double-click to reset' });
    g._cell = cell;
    g.addEventListener('pointerdown', (ev) => {
      ev.preventDefault();
      ev.stopPropagation();
      if (!widths) widths = cells.map((c, j) =>
        j === cells.length - 1 ? null : c.getBoundingClientRect().width);
      const startX = ev.clientX;
      const startW = widths[i] == null ? cell.getBoundingClientRect().width : widths[i];
      const move = (e2) => { widths[i] = Math.max(28, startW + (e2.clientX - startX)); apply(); };
      const up = () => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
        document.body.classList.remove('col-resizing');
        try { localStorage.setItem(store, JSON.stringify(widths)); } catch { /* quota */ }
      };
      document.body.classList.add('col-resizing');
      window.addEventListener('pointermove', move);
      window.addEventListener('pointerup', up);
    });
    g.addEventListener('dblclick', () => {
      widths = null;
      localStorage.removeItem(store);
      apply();
    });
    grips.push(g);
    head.appendChild(g);
  });
  apply();
  if (window.ResizeObserver) new ResizeObserver(place).observe(head);
}

function drawMachine(container, def, live) {
  live = live || {};
  const current = live.current || null;
  const visited = live.visited || new Set();
  const hist = Array.isArray(live.history) ? live.history : [];
  const recent = hist.length ? hist[hist.length - 1] : null;
  const histEdges = new Set(hist.map((t) => String(t.from) + '>' + String(t.to)));
  /* every observed transition (not just up to the cursor), grouped per edge, so
     clicking a transition lists the event(s) that triggered it. */
  const fullHist = Array.isArray(live.fullHistory) ? live.fullHistory : hist;
  const edgeTriggers = new Map();
  for (const t of fullHist) {
    const k = String(t.from) + '>' + String(t.to);
    if (!edgeTriggers.has(k)) edgeTriggers.set(k, []);
    edgeTriggers.get(k).push(t);
  }
  const accent = def.accent || '#6ab0f3';
  const uid = 'sm' + (smUid++);
  const mkDim = uid + '-adim';
  const mkAcc = uid + '-aacc';

  const nodeById = new Map();
  for (const s of def.states) nodeById.set(s.id, s);

  let view = def.view;
  if (!view) {
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const s of def.states) {
      minX = Math.min(minX, s.x); minY = Math.min(minY, s.y);
      maxX = Math.max(maxX, s.x + SM_NW); maxY = Math.max(maxY, s.y + SM_NH);
    }
    view = { x: minX - 30, y: minY - 30, w: (maxX - minX) + 60, h: (maxY - minY) + 60 };
  }
  const minW = def.minW || Math.round(view.w * 0.62);

  const svgEl = svg('svg', {
    class: 'sm-svg' + (def.reference ? ' sm-ref' : ''),
    id: def.svgId || null,
    viewBox: view.x + ' ' + view.y + ' ' + view.w + ' ' + view.h,
    preserveAspectRatio: 'xMidYMid meet', role: 'img', 'aria-label': def.title,
    style: 'width:100%;height:auto;max-width:' + view.w + 'px;min-width:'
      + minW + 'px;--sm-accent:' + accent,
  });

  const marker = (id, fill) => svg('marker', {
    id, viewBox: '0 0 10 10', refX: 8.5, refY: 5,
    markerWidth: 9, markerHeight: 9, orient: 'auto', markerUnits: 'userSpaceOnUse',
  }, svg('path', { d: 'M0,0 L10,5 L0,10 z', fill }));
  svgEl.appendChild(svg('defs', null,
    marker(mkDim, '#59606b'), marker(mkAcc, accent)));

  const gEdges = svg('g', { class: 'sm-edges' });
  const gNodes = svg('g', { class: 'sm-nodes' });
  const gLabels = svg('g', { class: 'sm-labels' });
  svgEl.appendChild(gEdges);
  svgEl.appendChild(gNodes);
  svgEl.appendChild(gLabels);

  function sidePoint(nd, side, t) {
    t = (t == null) ? 0.5 : t;
    if (side === 'L') return { x: nd.x, y: nd.y + SM_NH * t };
    if (side === 'R') return { x: nd.x + SM_NW, y: nd.y + SM_NH * t };
    if (side === 'T') return { x: nd.x + SM_NW * t, y: nd.y };
    return { x: nd.x + SM_NW * t, y: nd.y + SM_NH };   /* 'B' */
  }
  function autoAnchor(nd, tx, ty) {
    const cx = nd.x + SM_NW / 2, cy = nd.y + SM_NH / 2;
    const dx = tx - cx, dy = ty - cy;
    if (dx === 0 && dy === 0) return { x: cx, y: cy };
    const sx = dx !== 0 ? (SM_NW / 2) / Math.abs(dx) : Infinity;
    const sy = dy !== 0 ? (SM_NH / 2) / Math.abs(dy) : Infinity;
    const s = Math.min(sx, sy);
    return { x: cx + dx * s, y: cy + dy * s };
  }
  function quadPt(a, c, b, t) {
    const mt = 1 - t;
    return {
      x: mt * mt * a.x + 2 * mt * t * c.x + t * t * b.x,
      y: mt * mt * a.y + 2 * mt * t * c.y + t * t * b.y,
    };
  }

  function pathFor(e) {
    const A = nodeById.get(e.from), B = nodeById.get(e.to);
    if (!A || !B) return null;
    if (e.from === e.to) {                       /* self-loop off the top edge */
      const x1 = A.x + SM_NW * 0.62, x2 = A.x + SM_NW * 0.38, y0 = A.y;
      return {
        d: 'M ' + x1 + ' ' + y0 + ' C ' + (x1 + 20) + ' ' + (y0 - 48) + ' '
          + (x2 - 20) + ' ' + (y0 - 48) + ' ' + x2 + ' ' + y0,
        lbl: e.labelAt || { x: A.x + SM_NW / 2, y: y0 - 52 },
      };
    }
    const Bc = { x: B.x + SM_NW / 2, y: B.y + SM_NH / 2 };
    const Ac = { x: A.x + SM_NW / 2, y: A.y + SM_NH / 2 };
    const a = e.fromSide ? sidePoint(A, e.fromSide, e.fromT) : autoAnchor(A, Bc.x, Bc.y);
    const b = e.toSide ? sidePoint(B, e.toSide, e.toT) : autoAnchor(B, Ac.x, Ac.y);
    if (e.via) {
      let d = 'M ' + a.x + ' ' + a.y;
      for (const p of e.via) d += ' L ' + p.x + ' ' + p.y;
      d += ' L ' + b.x + ' ' + b.y;
      return { d, lbl: e.labelAt || { x: (a.x + b.x) / 2, y: (a.y + b.y) / 2 } };
    }
    const curve = e.curve || 0;
    const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1;
    const c = { x: (a.x + b.x) / 2 - dy / len * curve, y: (a.y + b.y) / 2 + dx / len * curve };
    return {
      d: 'M ' + a.x + ' ' + a.y + ' Q ' + c.x + ' ' + c.y + ' ' + b.x + ' ' + b.y,
      lbl: e.labelAt || quadPt(a, c, b, e.labelT == null ? 0.5 : e.labelT),
    };
  }

  function edgeState(e) {
    if (recent && String(recent.from) === e.from && String(recent.to) === e.to) return 'is-recent';
    if (histEdges.has(e.from + '>' + e.to)) return 'is-visited';
    return 'is-dim';
  }

  /* edges under nodes … */
  /* every transition of a RECONSTRUCTED machine is clickable (occurred → its
     events, else → its triggering event + "not observed"); pure spec-reference
     diagrams (def.reference) stay static. */
  const clickable = !def.reference;
  const paths = [];
  for (const e of def.edges) {
    const pf = pathFor(e);
    if (!pf) continue;
    const st = edgeState(e);
    const triggers = edgeTriggers.get(String(e.from) + '>' + String(e.to)) || [];
    const el = svg('path', {
      class: 'sm-edge ' + st + (clickable ? ' is-clickable' : ''), d: pf.d,
      'marker-end': 'url(#' + (st === 'is-dim' ? mkDim : mkAcc) + ')',
    });
    gEdges.appendChild(el);
    paths.push({ e, pf, st, el, triggers });
  }

  /* nodes */
  for (const s of def.states) {
    const nSt = s.id === current ? 'is-active'
      : (visited.has(s.id) ? 'is-visited' : 'is-dim');
    const cx = s.x + SM_NW / 2, cy = s.y + SM_NH / 2;
    gNodes.appendChild(svg('rect', {
      class: 'sm-node ' + nSt, x: s.x, y: s.y, width: SM_NW, height: SM_NH, rx: 9,
    }));
    gNodes.appendChild(svg('text', {
      class: 'sm-nid ' + nSt, x: cx, y: s.sub ? cy - 5 : cy,
      'text-anchor': 'middle', 'dominant-baseline': 'middle',
    }, s.label || s.id));
    if (s.sub) {
      gNodes.appendChild(svg('text', {
        class: 'sm-nsub ' + nSt, x: cx, y: cy + 12,
        'text-anchor': 'middle', 'dominant-baseline': 'middle',
      }, s.sub));
    }
  }

  /* edge labels on top, each with a backing rect so the wire under it reads */
  const charW = 5.35, lineH = 11;
  for (const p of paths) {
    if (!p.e.label) continue;
    const lines = Array.isArray(p.e.label) ? p.e.label : [p.e.label];
    let maxLen = 0;
    for (const l of lines) maxLen = Math.max(maxLen, l.length);
    const w = maxLen * charW + 9, hgt = lines.length * lineH + 3;
    const lx = p.pf.lbl.x, ly = p.pf.lbl.y;
    const bg = svg('rect', {
      class: 'sm-elabel-bg' + (clickable ? ' is-clickable' : ''),
      x: lx - w / 2, y: ly - hgt / 2, width: w, height: hgt, rx: 3,
    });
    gLabels.appendChild(bg);
    const text = svg('text', {
      class: 'sm-elabel ' + p.st + (clickable ? ' is-clickable' : ''),
      x: lx, y: ly, 'text-anchor': 'middle',
    });
    const y0 = ly - (lines.length - 1) * lineH / 2;
    lines.forEach((l, i) => text.appendChild(
      svg('tspan', { x: lx, y: y0 + i * lineH, 'dominant-baseline': 'middle' }, l)));
    gLabels.appendChild(text);
    if (clickable) {
      const onLabel = (ev) => { ev.stopPropagation(); showEdgeTriggers(ev, p.e, p.triggers, def); };
      bg.addEventListener('click', onLabel);
      text.addEventListener('click', onLabel);
    }
  }

  /* transparent wide hit-strokes on top so a transition is easy to click; a
     click lists the event(s) that drove it (see showEdgeTriggers). */
  const gHit = svg('g', { class: 'sm-hit' });
  svgEl.appendChild(gHit);
  for (const p of paths) {
    if (!clickable) continue;
    const hit = svg('path', { class: 'sm-hit-path', d: p.pf.d });
    hit.addEventListener('click', (ev) => { ev.stopPropagation(); showEdgeTriggers(ev, p.e, p.triggers, def); });
    hit.addEventListener('mouseenter', () => p.el.classList.add('is-hover'));
    hit.addEventListener('mouseleave', () => p.el.classList.remove('is-hover'));
    gHit.appendChild(hit);
  }

  container.appendChild(svgEl);
  return svgEl;
}

/* ── Milan v1.2 machine definitions (states, edges, spec-suggested layout) ──
   Node ids match the /state JSON verbatim, so the live overlay is a string
   match. Coordinates: probing column down the middle, settled states right,
   unbound/passive on the left (per the spec sheet). */

const ACMP_MACHINE = {
  title: 'ACMP Listener Sink',
  subtitle: 'Milan v1.2 §5.5.3, Figure 5.8 — probing / binding state machine',
  svgId: 'machine-acmp', accent: PROTO_COLORS.ACMP,
  view: { x: 0, y: 0, w: 772, h: 548 }, minW: 660,
  states: [
    { id: 'UNBOUND', x: 40, y: 20, sub: 'PROBING_DISABLED' },
    { id: 'PRB_W_AVAIL', x: 40, y: 120, sub: 'PROBING_PASSIVE' },
    { id: 'PRB_W_DELAY', x: 300, y: 120, sub: 'PROBING_ACTIVE' },
    { id: 'PRB_W_RESP', x: 300, y: 220, sub: 'PROBING_ACTIVE' },
    { id: 'PRB_W_RESP2', x: 300, y: 320, sub: 'PROBING_ACTIVE' },
    { id: 'PRB_W_RETRY', x: 300, y: 420, sub: 'PROBING_ACTIVE' },
    { id: 'SETTLED_NO_RSV', x: 560, y: 220, sub: 'PROBING_COMPLETED' },
    { id: 'SETTLED_RSV_OK', x: 560, y: 320, sub: 'PROBING_COMPLETED' },
  ],
  edges: [
    { from: 'UNBOUND', to: 'PRB_W_AVAIL', fromSide: 'B', fromT: 0.5, toSide: 'T', toT: 0.5,
      label: ['RCV_BIND_RX_CMD', '(talker not discovered)'], labelAt: { x: 116, y: 92 } },
    { from: 'UNBOUND', to: 'PRB_W_DELAY', fromSide: 'R', fromT: 0.5, toSide: 'T', toT: 0.30,
      label: ['RCV_BIND_RX_CMD', '(talker discovered)'], labelAt: { x: 258, y: 74 } },
    { from: 'PRB_W_AVAIL', to: 'PRB_W_DELAY', fromSide: 'R', fromT: 0.30, toSide: 'L', toT: 0.30,
      label: 'EVT_TK_DISCOVERED', labelAt: { x: 246, y: 126 } },
    { from: 'PRB_W_DELAY', to: 'PRB_W_AVAIL', fromSide: 'L', fromT: 0.72, toSide: 'R', toT: 0.72,
      label: 'EVT_TK_DEPARTED', labelAt: { x: 246, y: 160 } },
    { from: 'PRB_W_DELAY', to: 'PRB_W_RESP', fromSide: 'B', fromT: 0.5, toSide: 'T', toT: 0.5,
      label: 'TMR_DELAY', labelAt: { x: 376, y: 192 } },
    { from: 'PRB_W_RESP', to: 'SETTLED_NO_RSV', fromSide: 'R', fromT: 0.5, toSide: 'L', toT: 0.5,
      label: 'RCV_PROBE_TX_RESP', labelAt: { x: 506, y: 234 } },
    { from: 'PRB_W_RESP', to: 'PRB_W_RESP2', fromSide: 'B', fromT: 0.5, toSide: 'T', toT: 0.5,
      label: 'TMR_NO_RESP', labelAt: { x: 376, y: 292 } },
    { from: 'PRB_W_RESP', to: 'PRB_W_AVAIL', fromSide: 'L', fromT: 0.82, toSide: 'B', toT: 0.82,
      curve: 16, label: 'EVT_TK_DEPARTED', labelAt: { x: 236, y: 206 } },
    { from: 'PRB_W_RESP2', to: 'SETTLED_NO_RSV', fromSide: 'R', fromT: 0.32, toSide: 'B', toT: 0.35,
      curve: -10, label: 'RCV_PROBE_TX_RESP', labelAt: { x: 523, y: 293 } },
    { from: 'PRB_W_RESP2', to: 'PRB_W_RETRY', fromSide: 'B', fromT: 0.5, toSide: 'T', toT: 0.5,
      label: 'TMR_NO_RESP', labelAt: { x: 376, y: 393 } },
    { from: 'PRB_W_RESP2', to: 'PRB_W_AVAIL', fromSide: 'L', fromT: 0.70, toSide: 'B', toT: 0.62,
      curve: 22, label: 'EVT_TK_DEPARTED', labelAt: { x: 214, y: 262 } },
    { from: 'PRB_W_RETRY', to: 'PRB_W_RESP', fromSide: 'R', fromT: 0.5, toSide: 'R', toT: 0.5,
      curve: 58, label: 'TMR_RETRY', labelAt: { x: 492, y: 343 } },
    { from: 'PRB_W_RETRY', to: 'PRB_W_AVAIL', fromSide: 'L', fromT: 0.5, toSide: 'B', toT: 0.42,
      curve: 30, label: 'EVT_TK_DEPARTED', labelAt: { x: 198, y: 318 } },
    { from: 'SETTLED_NO_RSV', to: 'SETTLED_RSV_OK', fromSide: 'B', fromT: 0.35, toSide: 'T', toT: 0.35,
      label: 'EVT_TK_REGISTERED', labelAt: { x: 636, y: 283 } },
    { from: 'SETTLED_NO_RSV', to: 'PRB_W_DELAY', fromSide: 'T', fromT: 0.30, toSide: 'R', toT: 0.72,
      label: 'TMR_NO_TK', labelAt: { x: 520, y: 184 } },
    { from: 'SETTLED_NO_RSV', to: 'PRB_W_AVAIL', fromSide: 'B', fromT: 0.55, toSide: 'L', toT: 0.55,
      via: [{ x: 620, y: 500 }, { x: 22, y: 500 }, { x: 22, y: 145 }],
      label: 'EVT_TK_DEPARTED', labelAt: { x: 330, y: 491 } },
    { from: 'SETTLED_RSV_OK', to: 'SETTLED_NO_RSV', fromSide: 'T', fromT: 0.70, toSide: 'B', toT: 0.70,
      label: 'EVT_TK_UNREGISTERED', labelAt: { x: 636, y: 305 } },
    { from: 'SETTLED_RSV_OK', to: 'PRB_W_AVAIL', fromSide: 'B', fromT: 0.62, toSide: 'L', toT: 0.78,
      via: [{ x: 648, y: 522 }, { x: 8, y: 522 }, { x: 8, y: 156 }],
      label: 'EVT_TK_DEPARTED', labelAt: { x: 300, y: 513 } },
  ],
  note: 'Global (rendered as this note to stay readable): any state → UNBOUND on '
    + 'RCV_UNBIND_RX_CMD. EVT_TK_DEPARTED returns the sink to PRB_W_AVAIL from '
    + 'every probing/settled state.',
};

/* IEEE 1722.1 ACMP connection — one talker↔listener stream binding,
   reconstructed from the CONNECT/DISCONNECT command↔response flow (plus
   timeouts). Node ids match connections[].state / history verbatim. */
const ACMP_CONNECTION_MACHINE = {
  title: 'ACMP Connection',
  subtitle: 'IEEE 1722.1 §8.2 — CONNECT / DISCONNECT flow per talker↔listener stream',
  svgId: 'machine-acmp-conn', accent: PROTO_COLORS.ACMP,
  view: { x: 0, y: -20, w: 772, h: 390 }, minW: 620,
  states: [
    { id: 'FAILED', x: 300, y: 10, sub: 'error / timeout' },
    { id: 'DISCONNECTED', x: 40, y: 150, sub: 'no stream' },
    { id: 'CONNECTING', x: 300, y: 150, sub: 'await response' },
    { id: 'CONNECTED', x: 560, y: 150, sub: 'stream bound' },
    { id: 'DISCONNECTING', x: 430, y: 285, sub: 'await response' },
  ],
  edges: [
    { from: 'DISCONNECTED', to: 'CONNECTING', fromSide: 'R', fromT: 0.4, toSide: 'L', toT: 0.4,
      label: ['CONNECT_TX/RX', 'COMMAND'], labelAt: { x: 246, y: 136 } },
    { from: 'CONNECTING', to: 'CONNECTED', fromSide: 'R', fromT: 0.4, toSide: 'L', toT: 0.4,
      label: ['CONNECT_RX_RESP', 'SUCCESS'], labelAt: { x: 506, y: 136 } },
    { from: 'CONNECTING', to: 'FAILED', fromSide: 'T', fromT: 0.35, toSide: 'B', toT: 0.35,
      label: ['error status', '/ timeout'], labelAt: { x: 296, y: 103 } },
    { from: 'FAILED', to: 'CONNECTING', fromSide: 'B', fromT: 0.65, toSide: 'T', toT: 0.65,
      label: ['new CONNECT', 'COMMAND'], labelAt: { x: 462, y: 103 } },
    { from: 'FAILED', to: 'DISCONNECTING', fromSide: 'R', fromT: 0.5,
      via: [{ x: 745, y: 33 }, { x: 745, y: 308 }], toSide: 'R', toT: 0.5,
      label: ['DISCONNECT', 'COMMAND'], labelAt: { x: 682, y: 62 } },
    { from: 'CONNECTED', to: 'DISCONNECTING', fromSide: 'B', fromT: 0.35, toSide: 'T', toT: 0.55,
      label: ['DISCONNECT_TX/RX', 'COMMAND'], labelAt: { x: 653, y: 247 } },
    { from: 'DISCONNECTING', to: 'CONNECTED', fromSide: 'T', fromT: 0.9, toSide: 'B', toT: 0.75, curve: -12,
      label: 'rejected', labelAt: { x: 620, y: 285 } },
    { from: 'DISCONNECTING', to: 'DISCONNECTED', fromSide: 'L', fromT: 0.5, toSide: 'B', toT: 0.5,
      via: [{ x: 116, y: 308 }],
      label: ['RESPONSE SUCCESS', '/ timeout'], labelAt: { x: 268, y: 320 } },
  ],
  note: 'Reconstructed from the tap: a command opens the transition, the matching '
    + 'response (or its 200 ms/4.5 s ACMP timeout) settles it. GET_TX/RX_STATE '
    + 'and GET_TX_CONNECTION are observational and do not move this machine.',
};

/* Milan talker — deliberately stateless (§5.5.4): it must answer every
   PROBE_TX / DISCONNECT_TX immediately, holding no per-listener state. The
   single node + self-loop makes that spec property visible; the loop's
   triggers list every observed response. */
const MILAN_TALKER_MACHINE = {
  title: 'ACMP Talker Source',
  subtitle: 'Milan v1.2 §5.5.4 — stateless: every PROBE_TX / DISCONNECT_TX gets an immediate response',
  svgId: 'machine-acmp-talker', accent: PROTO_COLORS.ACMP,
  view: { x: 60, y: -78, w: 620, h: 200 }, minW: 420,
  states: [
    { id: 'STATELESS', x: 294, y: 50, sub: 'always responds' },
  ],
  edges: [
    { from: 'STATELESS', to: 'STATELESS',
      label: ['PROBE_TX / DISCONNECT_TX rx', '→ RESPONSE (always SUCCESS)'], labelAt: { x: 370, y: -14 } },
  ],
  note: 'A Milan talker keeps no binding state — listeners own the bindings '
    + '(see the ACMP Listener Sink machine). The stream itself is allocated at '
    + 'PROBE_TX_RESPONSE time; SRP carries its reservation.',
};

const ADP_ENTITY_MACHINE = {
  title: 'ADP Entity Lifecycle',
  subtitle: 'Observer reconstruction — ADP ENTITY_AVAILABLE / ENTITY_DEPARTING / valid_time',
  svgId: 'machine-adp-entity', accent: PROTO_COLORS.ADP,
  view: { x: 0, y: 0, w: 772, h: 320 }, minW: 560,
  states: [
    { id: 'UNKNOWN', x: 40, y: 70, sub: 'not yet seen' },
    { id: 'AVAILABLE', x: 300, y: 70, sub: 'advertising' },
    { id: 'DEPARTING', x: 560, y: 70, sub: 'graceful leave' },
    { id: 'TIMED_OUT', x: 300, y: 210, sub: 'valid_time lapsed' },
  ],
  edges: [
    { from: 'UNKNOWN', to: 'AVAILABLE', fromSide: 'R', fromT: 0.5, toSide: 'L', toT: 0.5,
      label: 'ENTITY_AVAILABLE', labelAt: { x: 246, y: 86 } },
    { from: 'AVAILABLE', to: 'AVAILABLE', label: ['ENTITY_AVAILABLE', '(re-announce · avail_index)'] },
    { from: 'AVAILABLE', to: 'DEPARTING', fromSide: 'R', fromT: 0.32, toSide: 'L', toT: 0.32,
      label: 'ENTITY_DEPARTING', labelAt: { x: 506, y: 80 } },
    { from: 'DEPARTING', to: 'AVAILABLE', fromSide: 'L', fromT: 0.70, toSide: 'R', toT: 0.70,
      label: 'ENTITY_AVAILABLE', labelAt: { x: 506, y: 110 } },
    { from: 'AVAILABLE', to: 'TIMED_OUT', fromSide: 'B', fromT: 0.4, toSide: 'T', toT: 0.4,
      label: 'valid_time expired', labelAt: { x: 350, y: 160 } },
    { from: 'TIMED_OUT', to: 'AVAILABLE', fromSide: 'T', fromT: 0.7, toSide: 'B', toT: 0.7,
      label: 'ENTITY_AVAILABLE', labelAt: { x: 422, y: 176 } },
  ],
  note: 'Reconstructed from the passive capture — the observable projection of '
    + 'the PAAD advertise machine below.',
};

const ADP_ADVERTISE_MACHINE = {
  title: 'ADP Advertise (PAAD)',
  subtitle: 'Milan v1.2 §5.6.3, Figure 5.9 — internal advertise machine (reference)',
  svgId: 'machine-adp-advertise', accent: PROTO_COLORS.ADP, reference: true,
  view: { x: 0, y: 0, w: 772, h: 210 }, minW: 560,
  states: [
    { id: 'DOWN', x: 40, y: 70, sub: 'link down' },
    { id: 'WAITING', x: 300, y: 70, sub: 'advertising' },
    { id: 'DELAY', x: 560, y: 70, sub: 'random delay' },
  ],
  edges: [
    { from: 'DOWN', to: 'WAITING', fromSide: 'R', fromT: 0.35, toSide: 'L', toT: 0.35,
      label: 'LINK_UP', labelAt: { x: 246, y: 82 } },
    { from: 'WAITING', to: 'DOWN', fromSide: 'L', fromT: 0.70, toSide: 'R', toT: 0.70,
      label: ['LINK_DOWN', '/ SHUTDOWN'], labelAt: { x: 246, y: 120 } },
    { from: 'WAITING', to: 'DELAY', fromSide: 'R', fromT: 0.35, toSide: 'L', toT: 0.35,
      label: ['RCV_ADP_DISCOVER |', 'TMR_ADVERTISE | GM_CHANGE'], labelAt: { x: 506, y: 44 } },
    { from: 'DELAY', to: 'WAITING', fromSide: 'L', fromT: 0.70, toSide: 'R', toT: 0.70,
      label: ['TMR_DELAY', '(ENTITY_AVAILABLE sent)'], labelAt: { x: 506, y: 140 } },
    { from: 'DELAY', to: 'DOWN', fromSide: 'B', fromT: 0.5, toSide: 'B', toT: 0.6,
      via: [{ x: 636, y: 174 }, { x: 120, y: 174 }], label: 'LINK_DOWN', labelAt: { x: 380, y: 166 } },
  ],
  note: 'Internal PAAD machine — not observable from a capture; the tool '
    + 'reconstructs the observed projection (the ADP Entity Lifecycle above). '
    + 'WAITING is tinted while the selected entity is AVAILABLE.',
};

const ADP_DISCOVERY_MACHINE = {
  title: 'ADP Listener Discovery',
  subtitle: 'Milan v1.2 §5.6.4, Figure 5.10 — talker discovery for the bound sink',
  svgId: 'machine-adp-discovery', accent: PROTO_COLORS.ADP,
  view: { x: 0, y: 0, w: 660, h: 232 }, minW: 520,
  states: [
    { id: 'TK_NOT_DISCOVERED', x: 60, y: 90, sub: 'talker absent' },
    { id: 'TK_DISCOVERED', x: 430, y: 90, sub: 'talker present' },
  ],
  edges: [
    { from: 'TK_NOT_DISCOVERED', to: 'TK_DISCOVERED', fromSide: 'R', fromT: 0.32, toSide: 'L', toT: 0.32,
      label: 'RCV_ADP_AVAILABLE', labelAt: { x: 328, y: 100 } },
    { from: 'TK_DISCOVERED', to: 'TK_NOT_DISCOVERED', fromSide: 'L', fromT: 0.70, toSide: 'R', toT: 0.70,
      label: ['RCV_ADP_DEPARTING', '/ TMR_NO_ADP'], labelAt: { x: 328, y: 152 } },
    { from: 'TK_DISCOVERED', to: 'TK_DISCOVERED', label: ['RCV_ADP_AVAILABLE', '(refresh)'] },
  ],
};

/* gPTP media-dependent Pdelay-request machine (802.1AS-2020 Clause 11) — the
   initiator side of the peer-delay mechanism, reconstructed per port from the
   observed Pdelay_Req / Pdelay_Resp / Pdelay_Resp_Follow_Up exchange. Node ids
   match md.pdelay_req_state verbatim so the live overlay is a plain string
   match; short labels keep the long enum boxes legible. Used by the Topology
   tab's per-port view (the responder/sync states ride alongside as badges). */
const GPTP_MD_PDELAY_REQ_MACHINE = {
  title: 'gPTP MD Pdelay Request',
  subtitle: '802.1AS-2020 Clause 11 — MDPdelayReq (peer-delay initiator)',
  svgId: 'topo-machine-gptp-md', accent: PROTO_COLORS.GPTP,
  view: { x: 0, y: -20, w: 740, h: 350 }, minW: 560,
  states: [
    { id: 'NOT_ENABLED', x: 40, y: 150, sub: 'port down' },
    { id: 'WAITING_FOR_PDELAY_INTERVAL_TIMER', label: 'WAIT_INTERVAL', x: 290, y: 150, sub: 'idle · interval' },
    { id: 'WAITING_FOR_PDELAY_RESP', label: 'WAIT_RESP', x: 540, y: 150, sub: 'req sent' },
    { id: 'WAITING_FOR_PDELAY_RESP_FOLLOW_UP', label: 'WAIT_FOLLOW_UP', x: 540, y: 258, sub: 'resp seen' },
    { id: 'RESET', x: 290, y: 30, sub: 'response lost' },
  ],
  edges: [
    { from: 'NOT_ENABLED', to: 'WAITING_FOR_PDELAY_INTERVAL_TIMER',
      fromSide: 'R', fromT: 0.5, toSide: 'L', toT: 0.5, label: 'portEnabled', labelAt: { x: 242, y: 166 } },
    { from: 'WAITING_FOR_PDELAY_INTERVAL_TIMER', to: 'WAITING_FOR_PDELAY_RESP',
      fromSide: 'R', fromT: 0.38, toSide: 'L', toT: 0.38, label: ['send', 'Pdelay_Req'], labelAt: { x: 492, y: 138 } },
    { from: 'WAITING_FOR_PDELAY_RESP', to: 'WAITING_FOR_PDELAY_RESP_FOLLOW_UP',
      fromSide: 'B', fromT: 0.5, toSide: 'T', toT: 0.5, label: 'RESP rx', labelAt: { x: 616, y: 227 } },
    { from: 'WAITING_FOR_PDELAY_RESP_FOLLOW_UP', to: 'WAITING_FOR_PDELAY_INTERVAL_TIMER',
      fromSide: 'L', fromT: 0.55, toSide: 'B', toT: 0.62, via: [{ x: 372, y: 305 }],
      label: ['FOLLOW_UP rx', '/ compute delay'], labelAt: { x: 470, y: 312 } },
    { from: 'WAITING_FOR_PDELAY_RESP', to: 'RESET',
      fromSide: 'T', fromT: 0.5, toSide: 'R', toT: 0.5, curve: 30, label: 'timeout', labelAt: { x: 512, y: 74 } },
    { from: 'RESET', to: 'WAITING_FOR_PDELAY_INTERVAL_TIMER',
      fromSide: 'B', fromT: 0.5, toSide: 'T', toT: 0.5, label: 'restart', labelAt: { x: 384, y: 112 } },
  ],
  note: 'Reconstructed per port from observed peer-delay timing — a lost or late '
    + 'Pdelay_Resp / Follow_Up drives MDPdelayReq to RESET (802.1AS 11.2.15). '
    + 'The MDSyncSend state is shown as a badge above.',
};

/* gPTP media-dependent Pdelay-response machine (802.1AS-2020 Figure 11-10) —
   the responder side: answer a peer's Pdelay_Req, then send the follow-up
   carrying the response egress timestamp. Node ids match md.pdelay_resp_state. */
const GPTP_MD_PDELAY_RESP_MACHINE = {
  title: 'gPTP MD Pdelay Response',
  subtitle: '802.1AS-2020 Clause 11 — MDPdelayResp (peer-delay responder)',
  svgId: 'topo-machine-gptp-md-resp', accent: PROTO_COLORS.GPTP,
  view: { x: 0, y: -30, w: 740, h: 260 }, minW: 560,
  states: [
    { id: 'NOT_ENABLED', x: 40, y: 90, sub: 'port down' },
    { id: 'WAITING_FOR_PDELAY_REQ', label: 'WAIT_REQ', x: 290, y: 90, sub: 'idle' },
    { id: 'SENT_PDELAY_RESP_WAITING_FOR_TIMESTAMP', label: 'SENT_RESP', x: 540, y: 90,
      sub: 'awaiting egress ts' },
  ],
  edges: [
    { from: 'NOT_ENABLED', to: 'WAITING_FOR_PDELAY_REQ',
      fromSide: 'R', fromT: 0.5, toSide: 'L', toT: 0.5, label: 'portEnabled', labelAt: { x: 242, y: 106 } },
    { from: 'WAITING_FOR_PDELAY_REQ', to: 'SENT_PDELAY_RESP_WAITING_FOR_TIMESTAMP',
      fromSide: 'R', fromT: 0.38, toSide: 'L', toT: 0.38,
      label: ['REQ rx /', 'send Pdelay_Resp'], labelAt: { x: 492, y: 66 } },
    { from: 'SENT_PDELAY_RESP_WAITING_FOR_TIMESTAMP', to: 'WAITING_FOR_PDELAY_REQ',
      fromSide: 'B', fromT: 0.5, toSide: 'B', toT: 0.62, via: [{ x: 590, y: 190 }, { x: 372, y: 190 }],
      label: ['send', 'Resp_Follow_Up'], labelAt: { x: 480, y: 205 } },
  ],
  note: 'Reconstructed per port from the Pdelay_Resp / Resp_Follow_Up frames this '
    + 'port sends. A port that never answers a peer’s Pdelay_Req stays dim here '
    + '(no responder activity observed in the capture).',
};

/* ── network-wide state machines (not tied to one device) ──────────────────
   Always shown in the Topology view. Node ids match the /state values so the
   live overlay is a plain string match. */

/* gPTP domain grandmaster lifecycle (per domain) — which clock is GM, per the
   BMCA. current = gptp.domains[].state; sync health rides alongside as a badge. */
const GPTP_DOMAIN_MACHINE = {
  title: 'gPTP Domain — Grandmaster',
  subtitle: '802.1AS — BMCA grandmaster lifecycle (network-wide, per domain)',
  svgId: 'topo-net-gptp-domain', accent: PROTO_COLORS.GPTP,
  view: { x: 0, y: 0, w: 700, h: 200 }, minW: 520,
  states: [
    { id: 'NO_GM', x: 40, y: 78, sub: 'no announce' },
    { id: 'GM_PRESENT', x: 290, y: 78, sub: 'GM elected' },
    { id: 'GM_TIMED_OUT', x: 540, y: 78, sub: 'announce lapsed' },
  ],
  edges: [
    { from: 'NO_GM', to: 'GM_PRESENT', fromSide: 'R', fromT: 0.5, toSide: 'L', toT: 0.5,
      label: ['Announce', '(BMCA)'], labelAt: { x: 242, y: 62 } },
    { from: 'GM_PRESENT', to: 'GM_PRESENT', label: ['Announce', '(BMCA reselect · GM change)'] },
    { from: 'GM_PRESENT', to: 'GM_TIMED_OUT', fromSide: 'R', fromT: 0.5, toSide: 'L', toT: 0.5,
      label: 'announce timeout', labelAt: { x: 492, y: 62 } },
    { from: 'GM_TIMED_OUT', to: 'GM_PRESENT', fromSide: 'B', fromT: 0.5, toSide: 'B', toT: 0.62,
      via: [{ x: 616, y: 162 }, { x: 366, y: 162 }], label: 'Announce', labelAt: { x: 470, y: 168 } },
  ],
  note: 'Network-wide per gPTP domain — not a single device. current = the '
    + 'domain grandmaster lifecycle; several GM changes in a burst are faithful '
    + 'BMCA reselection on the wire. Sync health (HEALTHY/LOST) is the badge above.',
};

/* MAAP multicast address-range acquisition (per claimant) — IEEE 1722 Annex B.
   current = maap[].state. */
const MAAP_MACHINE = {
  title: 'MAAP Address Claim',
  subtitle: 'IEEE 1722 Annex B — multicast address-range acquisition per claimant',
  svgId: 'topo-net-maap', accent: PROTO_COLORS.MAAP,
  view: { x: 0, y: 0, w: 720, h: 300 }, minW: 560,
  states: [
    { id: 'UNKNOWN', x: 40, y: 132, sub: 'not seen' },
    { id: 'PROBING', x: 270, y: 132, sub: 'claiming' },
    { id: 'ACQUIRED', x: 500, y: 132, sub: 'owns range' },
    { id: 'DEFENDING', x: 500, y: 30, sub: 'contested' },
    { id: 'LOST', x: 270, y: 236, sub: 'abandoned' },
  ],
  edges: [
    { from: 'UNKNOWN', to: 'PROBING', fromSide: 'R', fromT: 0.5, toSide: 'L', toT: 0.5,
      label: 'MAAP_PROBE', labelAt: { x: 212, y: 148 } },
    { from: 'PROBING', to: 'ACQUIRED', fromSide: 'R', fromT: 0.5, toSide: 'L', toT: 0.5,
      label: 'MAAP_ANNOUNCE', labelAt: { x: 442, y: 148 } },
    { from: 'ACQUIRED', to: 'DEFENDING', fromSide: 'T', fromT: 0.42, toSide: 'B', toT: 0.42,
      label: 'MAAP_DEFEND', labelAt: { x: 604, y: 100 } },
    { from: 'DEFENDING', to: 'ACQUIRED', fromSide: 'B', fromT: 0.72, toSide: 'T', toT: 0.72,
      label: 're-announce', labelAt: { x: 512, y: 100 } },
    { from: 'ACQUIRED', to: 'LOST', fromSide: 'B', fromT: 0.4, toSide: 'R', toT: 0.5,
      curve: 24, label: ['range', 'abandoned'], labelAt: { x: 430, y: 214 } },
    { from: 'LOST', to: 'PROBING', fromSide: 'T', fromT: 0.5, toSide: 'B', toT: 0.5,
      label: 're-probe', labelAt: { x: 300, y: 192 } },
  ],
  note: 'Reconstructed per claimant (a talker MAC) from observed MAAP_PROBE / '
    + 'ANNOUNCE / DEFEND — how stream destination multicast addresses are claimed '
    + 'and defended across the network.',
};

/* ── MRP machines (IEEE 802.1Q) — the registration layer beneath MSRP/MVRP ──
   The Registrar (Table 10-4) is fully tap-observable, so it carries a live
   overlay; the Applicant (Table 10-3) is sender-internal, drawn as a reference
   grid with a legend of driving events (its 12×15 matrix is not observable). */

/* wire AttributeEvent -> spec registrar event (for the step-through captions) */
const MRP_EV_MAP = {
  New: 'rNew', JoinIn: 'rJoinIn', JoinMt: 'rJoinMt',
  Lv: 'rLv', LeaveAll: 'rLA', In: 'rIn', Mt: 'rMt',
};

const MRP_REGISTRAR_MACHINE = {
  title: 'MRP Registrar',
  subtitle: 'IEEE 802.1Q §10.7.8, Table 10-4 — registration state machine (LeaveTime ≈ 1.0 s)',
  svgId: 'machine-mrp-registrar', accent: PROTO_COLORS.MSRP,
  view: { x: 0, y: -30, w: 600, h: 355 }, minW: 470,
  states: [
    { id: 'MT', x: 50, y: 60, sub: 'empty · start' },
    { id: 'IN', x: 360, y: 60, sub: 'registered' },
    { id: 'LV', x: 360, y: 210, sub: 'leaving · timer' },
  ],
  edges: [
    { from: 'MT', to: 'IN', fromSide: 'R', fromT: 0.5, toSide: 'L', toT: 0.5,
      label: ['rNew · rJoinIn', '· rJoinMt'], labelAt: { x: 281, y: 64 } },
    { from: 'IN', to: 'IN', label: ['rNew', '(New!)'], labelAt: { x: 436, y: 0 } },
    { from: 'IN', to: 'LV', fromSide: 'B', fromT: 0.66, toSide: 'T', toT: 0.66,
      label: ['rLv · rLA · txLA', '· Re-declare'], labelAt: { x: 512, y: 150 } },
    { from: 'LV', to: 'IN', fromSide: 'T', fromT: 0.34, toSide: 'B', toT: 0.34,
      label: ['rNew · rJoinIn', '· rJoinMt'], labelAt: { x: 330, y: 165 } },
    { from: 'LV', to: 'MT', fromSide: 'B', fromT: 0.5, toSide: 'B', toT: 0.5,
      via: [{ x: 436, y: 292 }, { x: 126, y: 292 }],
      label: ['leavetimer!', '/ Flush!'], labelAt: { x: 281, y: 280 } },
  ],
  note: 'Fully tap-observable — the registration layer shared by MSRP and MVRP. '
    + 'Wire AttributeEvents map New→rNew, JoinIn→rJoinIn, JoinMt→rJoinMt, '
    + 'Lv→rLv, LeaveAll→rLA. In / Mt are logged but do not move the registrar. '
    + 'Scrub the timeline to walk it event by event; click a transition to list '
    + 'the events that drove it.',
};

const MRP_APPLICANT_MACHINE = {
  title: 'MRP Applicant',
  subtitle: 'IEEE 802.1Q §10.7.7, Table 10-3 — sender-internal declaration machine (reference)',
  svgId: 'machine-mrp-applicant', accent: PROTO_COLORS.MVRP, reference: true,
  view: { x: 0, y: 0, w: 786, h: 392 }, minW: 620,
  states: [
    { id: 'VO', x: 30, y: 30, sub: 'v.anxious observer' },
    { id: 'VP', x: 222, y: 30, sub: 'v.anxious passive' },
    { id: 'VN', x: 414, y: 30, sub: 'v.anxious new' },
    { id: 'AO', x: 30, y: 126, sub: 'anxious observer' },
    { id: 'AP', x: 222, y: 126, sub: 'anxious passive' },
    { id: 'AN', x: 414, y: 126, sub: 'anxious new' },
    { id: 'AA', x: 606, y: 126, sub: 'anxious active' },
    { id: 'QO', x: 30, y: 222, sub: 'quiet observer' },
    { id: 'QP', x: 222, y: 222, sub: 'quiet passive' },
    { id: 'QA', x: 606, y: 222, sub: 'quiet active' },
    { id: 'LO', x: 30, y: 318, sub: 'leaving observer' },
    { id: 'LA', x: 606, y: 318, sub: 'leaving active' },
  ],
  edges: [
    /* tx! — the anxiety countdown: transmitting a declaration moves
       Very anxious -> Anxious -> Quiet (802.1Q Table 10-3). */
    { from: 'VN', to: 'AN', label: 'tx!' },
    { from: 'AN', to: 'QA', label: 'tx!' },
    { from: 'VP', to: 'AA', label: 'tx!' },
    { from: 'AA', to: 'QA', label: 'tx!' },
    { from: 'LA', to: 'VO', label: 'tx!' },
    /* Join! — declare (observer -> passive/active). */
    { from: 'VO', to: 'VP', label: 'Join!' },
    { from: 'AO', to: 'AP', label: 'Join!' },
    { from: 'QO', to: 'QP', label: 'Join!' },
    { from: 'LA', to: 'AA', label: 'Join!' },
    /* Lv! — withdraw (declaring states -> Leaving). */
    { from: 'VN', to: 'LA', label: 'Lv!' },
    { from: 'AA', to: 'LA', label: 'Lv!' },
    { from: 'QA', to: 'LA', label: 'Lv!' },
    { from: 'AP', to: 'AO', label: 'Lv!' },
    /* rJoinIn! — someone else registered, so declare less anxiously. */
    { from: 'VP', to: 'AP', label: 'rJoinIn!' },
    { from: 'AA', to: 'QA', label: 'rJoinIn!' },
    { from: 'AO', to: 'QO', label: 'rJoinIn!' },
    /* rJoinMt! / rMt! — registration went empty -> become active again. */
    { from: 'QA', to: 'AA', label: 'rJoinMt! / rMt!' },
    { from: 'QO', to: 'AO', label: 'rJoinMt! / rMt!' },
    /* rLv! / rLA! / Re-declare! — someone is leaving -> re-declare anxiously. */
    { from: 'QA', to: 'VP', label: 'rLv! / rLA!' },
    { from: 'AN', to: 'VN', label: 'rLv! / rLA!' },
    /* periodic! — periodic re-assertion of a quiet declaration. */
    { from: 'QP', to: 'AP', label: 'periodic!' },
  ],
  note: 'Sender-internal — not observable from a passive capture; reconstructed '
    + 'only as the observed event stream (see the Registrar above and the event '
    + 'log). Rows = declaration urgency (very anxious → anxious → quiet → leaving); '
    + 'columns = activity (observer · passive · new · active). Principal '
    + 'transitions shown (tx! countdown, Join!, Lv!, rJoinIn!, rJoinMt!/rMt!, '
    + 'rLv!/rLA!, periodic!); the full Table 10-3 also defines the Begin!→VO reset, '
    + 'New!→VN from every state, and the txLA!/txLAF! LeaveAll variants.',
};

function mrpAttrLabel(m) {
  return '[' + (m.proto || '?') + '] ' + (m.attribute || m.kind || '?')
    + ' — ' + (m.source || '?');
}

/* IN / LV / MT -> the shared state-chip colors (good / warn / neutral) */
function mrpStateBadge(s, small) {
  const cls = s === 'IN' ? 'st-good' : s === 'LV' ? 'st-warn' : 'st-neutral';
  return h('span', { class: 'sbadge ' + cls + (small ? ' sm' : '') }, String(s || '?'));
}

/* live overlay for the registrar at log step `idx`: current = the state after
   that event, visited = every state seen up to it, history = the transitions
   walked so far (last one is emphasized as the recent edge) */
function mrpLiveAt(entry, idx) {
  const log = (entry && entry.log) || [];
  const visited = new Set(['MT']);   /* the registrar always starts empty (MT) */
  const history = [];
  let prev = 'MT';
  const end = Math.min(idx, log.length - 1);
  for (let j = 0; j <= end; j++) {
    const stt = log[j].state;
    if (!stt) continue;
    visited.add(stt);
    if (prev !== stt) history.push({ from: prev, to: stt });
    else if (stt === 'IN' && MRP_EV_MAP[log[j].event] === 'rNew') history.push({ from: 'IN', to: 'IN' });
    prev = stt;
  }
  const current = (end >= 0 && log[end]) ? log[end].state
    : (log.length ? 'MT'                       /* cursor precedes the first event */
                  : ((entry && entry.registrar) || null));
  if (current) visited.add(current);
  /* every observed transition across the whole log (with its triggering event
     and packet), for the click-a-transition popover — independent of `idx`. */
  const fullHistory = [];
  let fp = 'MT';
  for (let j = 0; j < log.length; j++) {
    const stt = log[j].state;
    if (!stt) continue;
    if (fp !== stt || (stt === 'IN' && MRP_EV_MAP[log[j].event] === 'rNew'))
      fullHistory.push({ from: fp, to: stt, why: log[j].event, ts: log[j].ts, n: log[j].n });
    fp = stt;
  }
  return { current, history, visited, fullHistory };
}

/* the applicant reference's driving-event legend (rendered under its grid) */
function mrpApplicantEvents() {
  const item = (ev, eff) => h('div', { class: 'mae-row' },
    h('span', { class: 'mae-ev mono' }, ev),
    h('span', { class: 'mae-eff' }, eff));
  return h('div', { class: 'mrp-appl-events' },
    h('div', { class: 'mae-head' }, 'Driving events (Table 10-3)'),
    item('Begin!', 'reset → VO'),
    item('New!', 'declare a new value → VN'),
    item('Join!', 'declare · move toward Active (→ VP / AA)'),
    item('Lv!', 'withdraw · move to Leaving (LA / LO)'),
    item('tx! / txLA!', 'transmit; anxiety decreases (VN→AN→QA, VP→AA→QA)'),
    item('rJoinIn! / rJoinMt!', 'someone else declared; may go Quiet'),
    item('rLv! / rLA!', 'someone is leaving'));
}

/* ────────────────────────── admin view ────────────────────────── */

function adminView(app) {
  if (role !== 'admin') {
    /* the API 403s anyway — mirror it with an explicit empty state */
    app.appendChild(h('div', { class: 'home admin' },
      h('div', { class: 'empty' }, 'admin role required')));
    return { destroy() {} };
  }

  let alive = true;
  let timer = 0;

  const metricsBox = h('div', { class: 'metrics-strip' });
  const usersBox = h('div', { class: 'admin-users' },
    h('div', { class: 'empty' }, 'Loading…'));
  const presBox = h('div', { class: 'admin-presence' },
    h('div', { class: 'empty' }, 'Loading…'));

  /* create-user form */
  const newUser = h('input', {
    id: 'admin-new-user', class: 'input input-sm mono', placeholder: 'username',
    spellcheck: 'false', autocomplete: 'off',
  });
  const newPass = h('input', {
    id: 'admin-new-pass', class: 'input input-sm', type: 'password',
    placeholder: 'password (≥ 8 chars)', autocomplete: 'new-password',
  });
  const newRole = h('select', { id: 'admin-new-role', class: 'input input-sm' },
    h('option', { value: 'user' }, 'user'),
    h('option', { value: 'admin' }, 'admin'));
  const createBtn = h('button', {
    id: 'admin-create', class: 'btn btn-primary btn-sm', type: 'submit',
  }, 'Create user');
  const createForm = h('form', { class: 'admin-create-form', onsubmit: createUser },
    newUser, newPass, newRole, createBtn);

  const auHead = h('div', { class: 'au-head' },
    h('span', null, 'Username'), h('span', null, 'Role'),
    h('span', null, 'Online'), h('span', null, ''));
  const auPanel = h('section', { class: 'panel' },
    h('div', { class: 'panel-head' }, h('h2', null, 'Users')),
    auHead,
    usersBox,
    createForm,
  );
  const apHead = h('div', { class: 'ap-head' },
    h('span', null, 'Username'), h('span', null, 'View'),
    h('span', { class: 'num' }, 'Idle'));
  const apPanel = h('section', { class: 'panel' },
    h('div', { class: 'panel-head' }, h('h2', null, 'Presence'),
      h('span', { class: 'dim small' }, 'one entry per login session · 60 s expiry')),
    apHead,
    presBox,
  );

  /* ── storage: where the pcap library lives on the backend host ── */
  const rootIn = h('input', {
    class: 'input mono', spellcheck: 'false',
    placeholder: '/var/lib/avb-introspection/pcaps',
  });
  const rootApply = h('button', {
    class: 'btn btn-primary btn-sm', type: 'button', onclick: applyPcapRoot,
  }, 'Apply');
  const storageInfo = h('p', { class: 'dim small mono', id: 'storage-info' }, 'loading…');
  const storagePanel = h('section', { class: 'panel' },
    h('div', { class: 'panel-head' }, h('h2', null, 'Storage')),
    h('p', { class: 'dim small' },
      'Root folder where the uploaded pcap library is stored on the backend host. '
      + 'Changing it migrates the existing files (copy, then delete). The path must be '
      + 'writable by the service — for the systemd deployment add it to ReadWritePaths. '
      + 'Leave empty to reset to the default.'),
    h('div', { class: 'path-row' }, rootIn, rootApply),
    storageInfo,
  );

  async function loadStorage() {
    try {
      const s = await api('/api/admin/storage');
      rootIn.value = s.pcap_root === s.default_root ? '' : (s.pcap_root || '');
      storageInfo.textContent = 'current: ' + s.pcap_root
        + (s.pcap_root === s.default_root ? ' (default)' : '')
        + ' · ' + s.pcap_count + ' stored capture' + (s.pcap_count === 1 ? '' : 's');
    } catch (err) {
      storageInfo.textContent = 'storage info unavailable: ' + err.message;
    }
  }

  async function applyPcapRoot() {
    rootApply.disabled = true;
    try {
      const r = await api('/api/admin/storage',
        { method: 'PUT', json: { pcap_root: rootIn.value.trim() } });
      toast('pcap library now stored in ' + r.pcap_root);
      loadStorage();
    } catch (err) {
      toast('storage: ' + err.message, 'error');
    } finally {
      rootApply.disabled = false;
    }
  }

  app.appendChild(
    h('div', { class: 'home admin' },
      metricsBox,
      auPanel,
      apPanel,
      storagePanel,
    ),
  );
  makeColsResizable(auHead, auPanel, '--aucols', 'admin-users');
  makeColsResizable(apHead, apPanel, '--apcols', 'admin-presence');
  loadStorage();

  async function createUser(ev) {
    ev.preventDefault();
    const u = newUser.value.trim();
    const p = newPass.value;
    if (!u || !p) { toast('username and password are required', 'error'); return; }
    createBtn.disabled = true;
    try {
      await api('/api/admin/users', {
        method: 'POST', json: { username: u, password: p, role: newRole.value },
      });
      toast('user ' + u + ' created (' + newRole.value + ')');
      newUser.value = '';
      newPass.value = '';
      refresh();
    } catch (err) {
      toast('create user: ' + err.message, 'error');
    } finally {
      createBtn.disabled = false;
    }
  }

  async function deleteUser(name) {
    if (!window.confirm('Delete user "' + name + '"? Their tokens are revoked immediately.')) return;
    try {
      await api('/api/admin/users/' + encodeURIComponent(name), { method: 'DELETE' });
      toast('user ' + name + ' deleted');
      refresh();
    } catch (err) {
      toast('delete user: ' + err.message, 'error');
    }
  }

  function renderUsers(users) {
    if (!users.length) {
      usersBox.replaceChildren(h('div', { class: 'empty' }, 'No users.'));
      return;
    }
    const adminCount = users.filter((u) => u.role === 'admin').length;
    usersBox.replaceChildren(...users.map((u) => {
      const self = u.username === username;
      const lastAdmin = u.role === 'admin' && adminCount <= 1;
      const locked = self || lastAdmin;
      const del = h('button', {
        class: 'btn btn-danger btn-sm admin-del', type: 'button',
        dataset: { user: u.username || '' },
        disabled: locked,
        title: self ? 'you cannot delete your own account'
          : lastAdmin ? 'cannot delete the last administrator'
          : 'delete ' + u.username,
      }, 'Delete');
      if (!locked) del.addEventListener('click', () => deleteUser(u.username));
      return h('div', { class: 'aurow', dataset: { user: u.username || '' } },
        h('span', { class: 'au-name mono' }, u.username || ''),
        h('span', null, h('span', {
          class: 'sbadge ' + (u.role === 'admin' ? 'st-warn' : 'st-neutral'),
        }, u.role || 'user')),
        h('span', { class: 'au-online' },
          h('span', { class: 'online-dot' + (u.online ? ' on' : '') }),
          u.online
            ? h('span', { class: 'au-view' }, humanizeView(u.view))
            : h('span', { class: 'dim' }, 'offline')),
        h('span', { class: 'au-actions' }, del),
      );
    }));
  }

  function renderPresenceTable(entries) {
    if (!entries.length) {
      presBox.replaceChildren(h('div', { class: 'empty' }, 'Nobody online.'));
      return;
    }
    presBox.replaceChildren(...entries.map((u) => h('div', {
      class: 'aprow' + (u.username === username ? ' me' : ''),
      dataset: { user: u.username || '', view: u.view || '' },
    },
      h('span', { class: 'mono' }, u.username || ''),
      h('span', null, humanizeView(u.view)),
      h('span', { class: 'num mono' },
        typeof u.idle_s === 'number' ? u.idle_s.toFixed(1) + ' s' : '—'),
    )));
  }

  async function refresh() {
    if (!alive) return;
    const results = await Promise.allSettled([
      api('/api/admin/users'),
      api('/api/presence'),
      api('/api/metrics'),
    ]);
    if (!alive) return;
    if (results[0].status === 'fulfilled') renderUsers(results[0].value.users || []);
    else usersBox.replaceChildren(h('div', { class: 'empty errtext' }, results[0].reason.message));
    if (results[1].status === 'fulfilled') renderPresenceTable(results[1].value.users || []);
    else presBox.replaceChildren(h('div', { class: 'empty errtext' }, results[1].reason.message));
    if (results[2].status === 'fulfilled') metricsBox.replaceChildren(...metricTiles(results[2].value));
  }

  refresh();
  timer = setInterval(refresh, 10000);

  return {
    destroy() {
      alive = false;
      clearInterval(timer);
    },
  };
}

/* ────────────────────────── session view ────────────────────────── */

function sessionView(app, id) {
  /* let drawMachine's edge-trigger popover format times and jump to packets
     (both live in this closure; the hooks are module-level) */
  smFmtTime = fmtTime;
  smJumpToPacket = jumpToPacket;
  smJumpToEvent = jumpToEvent;
  smTransEventIdx = transEventIdx;
  /* ── mutable view state ── */
  const S = {
    meta: null,
    events: [],              /* dense array indexed by event index i */
    nToI: new Map(),         /* packet number n -> event index i (packet events) */
    transIdx: new Map(),     /* transition key (from|to|why|ts) -> event index i */
    filtered: [],            /* event indices passing the filters, ascending */
    protoOn: new Set(PROTOCOLS),
    kindOn: new Set(KINDS),
    query: '',
    selected: -1,            /* selected event index i, or -1 */
    forced: -1,              /* event index shown despite the filter (selected) */
    lonePacket: 0,           /* packet number shown without a selected event */
    tab: 'inspect',          /* 'inspect' | 'state' | 'notes' | 'markers' | 'info' | 'machines' | 'topology' */
    stateData: null,
    stateLoading: false,
    infoData: null,          /* GET /info payload (capture, file, devices) */
    infoLoading: false,
    deviceNames: new Map(),  /* mac -> user name || auto entity name */
    timeMode: localStorage.getItem(TIME_MODE_KEY) === 'tod' ? 'tod' : 'rel',
    entityNames: new Map(),
    entityDeviceNames: new Map(),  /* entity id -> owning device's label */
    srcMap: null,            /* Uint16Array: per-packet source index (combined) */
    origPos: null,           /* Uint32Array: per-packet position in its source pcap */
    packetCache: new Map(),
    progress: null,          /* last WS progress message */
    done: false,             /* analysis finished AND final data refreshed */
    closed: false,
  };

  /* ── timeline store (parallel arrays, capture order) ── */
  const TL = {
    i: [], n: [], ts: [], lane: [], kind: [], type: [],
    count: 0, maxTs: 0, hasOther: false,
    t0: 0, t1: 1, follow: true,
    w: 10, hgt: 10, dpr: 1,
    gutter: 62, axisH: 22, laneH: 23,
    drag: null, hoverIdx: -1, raf: 0,
  };
  {
    /* restore the user's lane height (shift+right-drag on the timeline) */
    const storedLaneH = parseFloat(localStorage.getItem(LANEH_KEY) || '');
    if (storedLaneH >= 14 && storedLaneH <= 44) TL.laneH = storedLaneH;
  }
  const LANE_OTHER = PROTOCOLS.length;

  function laneCount() { return TL.hasOther ? PROTOCOLS.length + 1 : PROTOCOLS.length; }
  function laneName(li) { return li < PROTOCOLS.length ? PROTOCOLS[li] : 'OTHER'; }
  function laneColor(li) { return li < PROTOCOLS.length ? PROTO_COLORS[PROTOCOLS[li]] : OTHER_COLOR; }

  /* ── toolbar elements ── */
  const titleEl = h('span', { class: 'sess-title' }, id);
  const statusSlot = h('span');
  const countsEl = h('span', { class: 'sess-counts dim small' });
  const progressEl = h('span', { class: 'progress-note', hidden: true },
    h('span', { class: 'spin' }), h('span', { class: 'progress-text' }));
  const errBanner = h('div', { class: 'sess-error-banner', hidden: true });
  const shownEl = h('span', { class: 'shown-counts mono small' });

  const protoChips = new Map();
  for (const p of PROTOCOLS) {
    const cnt = h('span', { class: 'chip-n mono' });
    const chip = h('button', { class: 'chip ' + protoClass(p), type: 'button', title: 'toggle ' + p },
      h('span', { class: 'chip-dot' }), p, cnt);
    chip.addEventListener('click', () => {
      if (S.protoOn.has(p)) S.protoOn.delete(p); else S.protoOn.add(p);
      chip.classList.toggle('off', !S.protoOn.has(p));
      applyFilters();
    });
    protoChips.set(p, { chip, cnt });
  }
  const kindChips = new Map();
  const KIND_GLYPH = { packet: '│', transition: '◆', error: '✕' };
  for (const k of KINDS) {
    const chip = h('button', {
      class: 'chip k-chip' + (k === 'error' ? ' k-err' : ''), type: 'button', title: 'toggle ' + k + ' events',
    }, h('span', { class: 'chip-glyph' }, KIND_GLYPH[k]), k);
    chip.addEventListener('click', () => {
      if (S.kindOn.has(k)) S.kindOn.delete(k); else S.kindOn.add(k);
      chip.classList.toggle('off', !S.kindOn.has(k));
      applyFilters();
    });
    kindChips.set(k, chip);
  }

  let searchTimer = 0;
  const searchIn = h('input', {
    class: 'input input-sm search-in', type: 'search',
    placeholder: 'search summaries…', spellcheck: 'false',
  });
  searchIn.addEventListener('input', () => {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(() => {
      S.query = searchIn.value.trim().toLowerCase();
      applyFilters();
    }, 150);
  });

  /* time display mode: two-button segmented control (rel = seconds since
     capture start, tod = local time of day). Enabled once meta arrives with a
     usable start_ts_ns; updateTimeModeCtl() keeps it in sync. */
  const timeModeBtns = new Map();
  const timeModeCtl = h('span', { id: 'time-mode', class: 'seg', role: 'group', 'aria-label': 'time display mode' });
  for (const m of ['rel', 'tod']) {
    const b = h('button', {
      class: 'seg-btn', type: 'button', dataset: { mode: m },
      'aria-pressed': 'false', disabled: true,
      title: m === 'rel' ? 'relative — seconds since capture start' : 'local time of day with nanoseconds',
      onclick: () => setTimeMode(m),
    }, m);
    timeModeBtns.set(m, b);
    timeModeCtl.appendChild(b);
  }

  /* ── timeline DOM ── */
  const tlCanvas = h('canvas');
  const tlTooltip = h('div', { class: 'tl-tooltip', hidden: true });
  const tlFitBtn = h('button', {
    class: 'btn btn-ghost btn-sm', type: 'button', title: 'fit the whole capture',
    onclick: () => tlFit(true),
  }, 'Fit');
  const tlWrap = h('div', { class: 'tl-wrap' },
    tlCanvas,
    tlTooltip,
    h('div', { class: 'tl-controls' },
      h('span', { class: 'tl-hint dim' }, 'wheel zoom · shift+wheel scroll · drag pan · dblclick fit'),
      tlFitBtn,
    ),
  );
  TL.canvas = tlCanvas;
  TL.wrap = tlWrap;
  TL.tooltip = tlTooltip;

  /* ── events table DOM (virtualized) ── */
  const tableHead = h('div', { class: 'etable-head' },
    h('span', { class: 'c-idx', title: 'event index in this session' }, '#'),
    h('span', { class: 'c-orig', title: 'packet number in its original pcap' }, 'Pkt'),
    h('span', { class: 'c-ts' }, 'Time'),
    h('span', { class: 'c-proto' }, 'Proto'),
    h('span', { class: 'c-type' }, 'Type'),
    h('span', { class: 'c-src' }, 'Src'),
    h('span', { class: 'c-dst' }, 'Dst'),
    h('span', { class: 'c-sum' }, 'Summary'),
  );
  const tableSpacer = h('div', { class: 'etable-spacer' });
  const tableRows = h('div', { class: 'etable-rows' });
  const tableBody = h('div', { class: 'etable-body' }, tableSpacer, tableRows);
  const tableEmpty = h('div', { class: 'etable-empty', hidden: true });
  let tableRaf = 0;
  tableBody.addEventListener('scroll', scheduleTable);
  tableRows.addEventListener('click', (ev) => {
    const row = ev.target.closest('.erow');
    if (row && row.dataset.i !== undefined) selectEvent(parseInt(row.dataset.i, 10), {});
  });

  /* ── inspector DOM ── */
  const tabInspBtn = h('button', { class: 'tab active', type: 'button', onclick: () => setTab('inspect') }, 'Packet inspector');
  const tabStateBtn = h('button', { class: 'tab', type: 'button', onclick: () => setTab('state') }, 'State');
  const tabNotesBtn = h('button', { id: 'tab-notes', class: 'tab', type: 'button', onclick: () => setTab('notes') }, 'Notes');
  const tabMarkersBtn = h('button', { id: 'tab-markers', class: 'tab', type: 'button', onclick: () => setTab('markers') }, 'Markers');
  const tabInfoBtn = h('button', { id: 'tab-info', class: 'tab', type: 'button', onclick: () => setTab('info') }, 'Info');
  /* "Network Status" = the device graph + every reconstructed state machine
     (network-wide and per-device), grouped by protocol. The old separate
     "Machines" tab is folded into here. */
  const tabTopologyBtn = h('button', { id: 'tab-topology', class: 'tab', type: 'button', onclick: () => setTab('topology') }, 'Network Status');
  const inspBody = h('div', { class: 'insp-body' });
  const sourceLegend = h('div', { class: 'source-legend', hidden: true });
  const eventsPanel = h('div', { class: 'events-panel' }, sourceLegend, tableHead, tableBody, tableEmpty);
  const inspectorPanel = h('div', { class: 'inspector-panel' },
    h('div', { class: 'tabs' }, tabInspBtn, tabStateBtn, tabNotesBtn, tabMarkersBtn, tabInfoBtn, tabTopologyBtn),
    inspBody,
  );
  const splitGutter = h('div', {
    class: 'gutter', role: 'separator', 'aria-orientation': 'vertical',
    title: 'drag to resize · double-click to reset · drag to an edge to collapse',
  });
  const mainSplit = h('div', { class: 'session-main' }, eventsPanel, splitGutter, inspectorPanel);

  /* ── assemble ── */
  const viewRoot =
    h('div', { class: 'session-view' },
      h('div', { class: 'toolbar' },
        h('div', { class: 'toolbar-row' },
          h('a', { class: 'btn btn-ghost btn-sm', href: '#/home', title: 'back to sessions' }, '←'),
          titleEl, statusSlot, progressEl,
          h('span', { class: 'toolbar-spacer' }),
          countsEl,
        ),
        h('div', { class: 'toolbar-row' },
          h('span', { class: 'chip-group' }, [...protoChips.values()].map((c) => c.chip)),
          h('span', { class: 'tb-sep' }),
          h('span', { class: 'chip-group' }, [...kindChips.values()]),
          h('span', { class: 'tb-sep' }),
          searchIn,
          h('span', { class: 'tb-sep' }),
          timeModeCtl,
          h('span', { class: 'toolbar-spacer' }),
          shownEl,
        ),
        errBanner,
      ),
      tlWrap,
      mainSplit,
    );
  app.appendChild(viewRoot);
  makeColsResizable(tableHead, eventsPanel, '--ecols', 'events');

  /* ────────── filtering ────────── */

  function passes(e) {
    if (!S.kindOn.has(e.kind)) return false;
    if (PROTO_COLORS[e.proto] !== undefined && !S.protoOn.has(e.proto)) return false;
    if (S.query) {
      const s = (e.summary || '').toLowerCase();
      if (!s.includes(S.query)) {
        const t = (e.type || '').toLowerCase();
        if (!t.includes(S.query)) return false;
      }
    }
    return true;
  }

  function applyFilters() {
    const out = [];
    for (let i = 0; i < S.events.length; i++) {
      const e = S.events[i];
      if (e && passes(e)) out.push(i);
    }
    /* Keep the selected event visible even when the active filter would hide
       it — otherwise following a "pkt N" / "go to causing packet" link selects
       an event whose row is filtered out, and the reference appears to vanish
       from the table. Force-include it at its correct (ascending) position. */
    S.forced = -1;
    if (S.selected >= 0 && S.events[S.selected] && !passes(S.events[S.selected])) {
      let lo = 0, hi = out.length;
      while (lo < hi) { const mid = (lo + hi) >> 1; if (out[mid] < S.selected) lo = mid + 1; else hi = mid; }
      out.splice(lo, 0, S.selected);
      S.forced = S.selected;
    }
    S.filtered = out;
    updateCounts();
    scheduleTable();
    tlSchedule();
  }

  function updateCounts() {
    const loaded = S.events.length;
    const total = S.meta && typeof S.meta.events === 'number' ? S.meta.events : loaded;
    let txt = fmtInt(S.filtered.length) + ' / ' + fmtInt(Math.max(total, loaded)) + ' events';
    if (loaded < total) txt += ' (' + fmtInt(loaded) + ' loaded)';
    shownEl.textContent = txt;
    if (S.filtered.length === 0) {
      tableEmpty.hidden = false;
      if (S.events.length === 0) {
        tableEmpty.textContent = (S.meta && S.meta.status === 'running')
          ? 'Waiting for events…' : 'No events in this session.';
      } else {
        tableEmpty.textContent = 'No events match the current filters.';
      }
    } else {
      tableEmpty.hidden = true;
    }
  }

  /* ────────── event ingestion ────────── */

  function appendEvents(list) {
    if (!Array.isArray(list) || !list.length) return;
    let added = false;
    for (const e of list) {
      if (!e || typeof e.i !== 'number' || e.i < 0) continue;
      if (S.events[e.i]) continue;                 /* dedup (WS reattach, overlap) */
      S.events[e.i] = e;
      if (e.kind === 'packet' && e.n > 0 && !S.nToI.has(e.n)) S.nToI.set(e.n, e.i);
      if (e.kind === 'transition') {
        /* index derived (timer/event-driven) transitions so a machine-history
           entry can link straight to its transition event in the table */
        const f = e.fields || {};
        const key = (f.from || '') + '\x1f' + (f.to || '') + '\x1f' + (f.why || '') + '\x1f' + e.ts;
        if (!S.transIdx.has(key)) S.transIdx.set(key, e.i);
      }
      if (e.i === TL.count) tlPush(e.i, e.n, e.ts, e.proto, e.kind, e.type);
      if (passes(e)) S.filtered.push(e.i);
      added = true;
    }
    if (added) {
      updateCounts();
      scheduleTable();
      tlSchedule();
      if (S.selected >= 0 && S.events[S.selected] && inspNeedsEvent === S.selected) {
        inspNeedsEvent = -1;
        renderInspector();
      }
    }
  }

  /* ────────── virtualized events table ────────── */

  function scheduleTable() {
    if (!tableRaf) tableRaf = requestAnimationFrame(renderTable);
  }

  function renderTable() {
    tableRaf = 0;
    if (S.closed) return;
    const total = S.filtered.length;
    tableSpacer.style.height = (total * ROW_H) + 'px';
    const vh = tableBody.clientHeight || 400;
    let st = tableBody.scrollTop;
    const maxSt = Math.max(0, total * ROW_H - vh);
    if (st > maxSt) st = maxSt;   /* spacer may have just shrunk (filter change) */
    const first = Math.max(0, Math.floor(st / ROW_H) - 8);
    const last = Math.min(total, Math.ceil((st + vh) / ROW_H) + 8);
    const frag = document.createDocumentFragment();
    for (let r = first; r < last; r++) {
      const i = S.filtered[r];
      const e = S.events[i];
      if (!e) continue;
      let cls = 'erow';
      if (i === S.selected) cls += ' sel';
      if (e.kind === 'error') cls += ' iserr';
      if (i === S.forced) cls += ' off-filter';   /* shown despite the filter */
      let title = e.summary || '';
      if (i === S.forced) title = '(hidden by the active filter — shown because it is selected)  ' + title;
      const si = srcOf(e.n);
      if (si >= 0) {
        cls += ' has-src src-c' + (si % 6);
        const al = srcAlias(si);
        if (al) title = '⎘ ' + al + '  ·  ' + title;
      }
      const glyph = e.kind === 'transition'
        ? h('span', { class: 'kg kg-tr' }, '◆ ')
        : (e.kind === 'error' ? h('span', { class: 'kg kg-err' }, '✕ ') : null);
      const op = origPosOf(e.n);
      const al2 = si >= 0 ? srcAlias(si) : null;
      frag.appendChild(h('div', { class: cls, dataset: { i: String(i) }, title: title },
        h('span', { class: 'c-idx mono' }, i),
        h('span', {
          class: 'c-orig mono',
          title: op ? ('packet #' + op + (al2 ? ' in ' + al2 : ' in the source pcap')) : null,
        }, op ? String(op) : ''),
        h('span', { class: 'c-ts mono' }, fmtTime(e.ts)),
        h('span', { class: 'c-proto' }, h('span', { class: 'badge ' + protoClass(e.proto) }, e.proto)),
        h('span', { class: 'c-type' }, glyph, e.type || ''),
        macCell('c-src', e.src),
        macCell('c-dst', e.dst),
        h('span', { class: 'c-sum' }, e.summary || ''),
      ));
    }
    tableRows.style.transform = 'translateY(' + (first * ROW_H) + 'px)';
    tableRows.replaceChildren(frag);
  }

  function filteredPos(i) {
    /* binary search in ascending S.filtered */
    const a = S.filtered;
    let lo = 0, hi = a.length - 1;
    while (lo <= hi) {
      const mid = (lo + hi) >> 1;
      if (a[mid] === i) return mid;
      if (a[mid] < i) lo = mid + 1; else hi = mid - 1;
    }
    return -1;
  }

  function scrollToSelected() {
    const r = filteredPos(S.selected);
    if (r < 0) return;
    const y = r * ROW_H;
    if (y < tableBody.scrollTop) tableBody.scrollTop = y;
    else if (y + ROW_H > tableBody.scrollTop + tableBody.clientHeight) {
      tableBody.scrollTop = y - tableBody.clientHeight + ROW_H;
    }
  }

  /* ────────── time display mode (rel | tod) ────────── */

  let startNsMemoKey = null;   /* memoized BigInt parse of meta.start_ts_ns */
  let startNsMemo = null;

  /* epoch ns of the first packet as BigInt, or null when unavailable ("0",
     missing, malformed) — null forces relative mode. */
  function startNs() {
    const v = (S.meta && typeof S.meta.start_ts_ns === 'string') ? S.meta.start_ts_ns : '';
    if (v !== startNsMemoKey) {
      startNsMemoKey = v;
      startNsMemo = null;
      if (/^[1-9][0-9]*$/.test(v)) {
        try { startNsMemo = BigInt(v); } catch (err) { startNsMemo = null; }
      }
    }
    return startNsMemo;
  }

  function pad2(x) { return String(x).padStart(2, '0'); }

  /* absolute epoch ns (BigInt) -> "HH:mm:ss.nnnnnnnnn" in LOCAL time:
     H/M/S from Date at ms precision, plus the full ns-of-second remainder */
  function fmtTod(absNs) {
    const d = new Date(Number(absNs / 1000000n));
    const ns = absNs % 1000000000n;
    return pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds())
      + '.' + String(ns).padStart(9, '0');
  }

  /* mode-aware event timestamp: relative seconds or local time of day */
  function fmtTime(ts) {
    if (typeof ts !== 'number' || !isFinite(ts)) return '—';
    const t0 = S.timeMode === 'tod' ? startNs() : null;
    if (t0 === null) return fmtTs(ts);
    return fmtTod(t0 + BigInt(Math.round(ts * 1e9)));
  }

  /* local date + full-precision time-of-day for the Info tab's ns strings */
  function fmtNsDate(nsStr) {
    if (typeof nsStr !== 'string' || !/^[1-9][0-9]*$/.test(nsStr)) return '—';
    let abs;
    try { abs = BigInt(nsStr); } catch (err) { return '—'; }
    const d = new Date(Number(abs / 1000000n));
    return d.toLocaleDateString() + ' ' + fmtTod(abs);
  }

  /* timeline axis tick label: HH:mm:ss in tod mode (fractional seconds only
     when the tick step goes sub-second), relative s/ms otherwise */
  function fmtAxisLabel(t, step) {
    const t0 = S.timeMode === 'tod' ? startNs() : null;
    if (t0 === null) return fmtAxis(t, step);
    const abs = t0 + BigInt(Math.round(t * 1e9));
    const d = new Date(Number(abs / 1000000n));
    let out = pad2(d.getHours()) + ':' + pad2(d.getMinutes()) + ':' + pad2(d.getSeconds());
    if (step < 1) {
      const frac = Number(abs % 1000000000n) / 1e9;
      const dec = Math.max(1, Math.min(6, -Math.floor(Math.log10(step))));
      out += frac.toFixed(dec).slice(1);
    }
    return out;
  }

  let shownTimeMode = 'rel';   /* last mode actually rendered */

  function updateTimeModeCtl() {
    const ok = startNs() !== null;
    const mode = ok ? S.timeMode : 'rel';   /* no absolute start -> force rel */
    timeModeCtl.title = ok
      ? 'time display: relative seconds / local time of day'
      : 'time-of-day unavailable — this capture has no absolute start timestamp';
    for (const [m, b] of timeModeBtns) {
      b.disabled = !ok;
      b.setAttribute('aria-pressed', mode === m ? 'true' : 'false');
      b.classList.toggle('active', mode === m);
    }
    eventsPanel.classList.toggle('tod', mode === 'tod');   /* widens the Time column */
    if (mode !== shownTimeMode) {
      shownTimeMode = mode;
      scheduleTable();
      tlSchedule();
      renderInspector();
    }
  }

  function setTimeMode(m) {
    if (m !== 'rel' && m !== 'tod') return;
    if (m === 'tod' && startNs() === null) return;
    S.timeMode = m;
    try { localStorage.setItem(TIME_MODE_KEY, m); } catch (err) { /* private mode */ }
    updateTimeModeCtl();
  }

  /* ────────── device names (GET /info, PUT /devices) ────────── */

  function rebuildDeviceNames() {
    S.deviceNames.clear();
    S.entityDeviceNames.clear();
    const devs = (S.infoData && S.infoData.devices) || [];
    for (const d of devs) {
      const label = d.name || d.entity_name || '';
      if (!label) continue;
      if (d.mac) S.deviceNames.set(String(d.mac).toLowerCase(), label);
      /* every entity id proven to belong to this MAC inherits the device's
         name, so controller/listener ids resolve to e.g. the renamed device */
      for (const eid of [d.entity_id].concat(d.assoc_entity_ids || [])) {
        if (eid) S.entityDeviceNames.set(String(eid).toLowerCase(), label);
      }
    }
  }

  /* name for an entity id: AEM entity name, else its device's label */
  function entityName(idStr) {
    if (!idStr) return null;
    return S.entityNames.get(idStr)
      || S.entityDeviceNames.get(String(idStr).toLowerCase()) || null;
  }

  /* user/auto name for a MAC, or null when unknown */
  function deviceName(mac) {
    if (!mac) return null;
    return S.deviceNames.get(String(mac).toLowerCase()) || null;
  }

  /* display label for a MAC: user name || auto entity name || the MAC itself */
  function deviceLabel(mac) {
    return deviceName(mac) || mac || '';
  }

  /* table cell for src/dst: label text, full MAC (+ name) in the title */
  function macCell(cls, mac) {
    if (!mac) return h('span', { class: cls + ' mono' });
    const nm = deviceName(mac);
    return h('span', { class: cls + ' mono', title: nm ? mac + ' — ' + nm : mac }, deviceLabel(mac));
  }

  /* inspector src/dst span: same labeling, em-dash when absent */
  function macSpan(mac) {
    if (!mac) return h('span', { class: 'dim' }, '—');
    const nm = deviceName(mac);
    return h('span', { class: 'mono', title: nm ? mac + ' — ' + nm : mac }, deviceLabel(mac));
  }

  /* inspector field value: when the value is exactly a known MAC, append the
     device name — "aa:bb:cc:dd:ee:ff (FOH Rack)" — keeping the MAC visible */
  function fieldVal(v) {
    const s = String(v);
    const nm = MAC_RE.test(s) ? deviceName(s) : null;
    return h('span', { class: 'f-val mono', title: nm ? s : null },
      s, nm ? h('span', { class: 'dev-nm' }, ' (' + nm + ')') : null);
  }

  async function loadInfo() {
    if (S.infoLoading || S.closed) return;
    S.infoLoading = true;
    try {
      const info = await api('/api/sessions/' + encodeURIComponent(id) + '/info');
      if (S.closed) return;
      S.infoData = info;
      rebuildDeviceNames();
      /* combined session: load the per-packet source map so the event table,
         inspector and history can attribute each packet to its source. */
      if ((info.sources || []).length > 1 && !S.srcMap) loadSrcMap();
      renderSourceLegend();
      if (S.tab === 'info') renderInfoTab();
      else if (S.tab === 'topology') renderTopologyTab();
      else if (S.tab === 'inspect') renderInspector();
      renderMachineWins();           /* device names may have changed */
      scheduleTable();               /* src/dst labels may have changed */
    } catch (err) {
      if (!S.closed) toast('session info: ' + err.message, 'error');
    } finally {
      S.infoLoading = false;
    }
  }

  async function loadSrcMap() {
    try {
      const res = await fetch(BASE + '/api/sessions/' + encodeURIComponent(id) + '/srcmap',
        { headers: token ? { Authorization: 'Bearer ' + token } : {} });
      if (!res.ok) return;
      S.srcMap = new Uint16Array(await res.arrayBuffer());
      /* per-source running counter -> position of each packet in its source */
      const pos = new Uint32Array(S.srcMap.length);
      const counters = [];
      for (let k = 0; k < S.srcMap.length; k++) {
        const s = S.srcMap[k];
        counters[s] = (counters[s] || 0) + 1;
        pos[k] = counters[s];
      }
      S.origPos = pos;
      renderSourceLegend();
      scheduleTable();
    } catch (err) { /* non-fatal: rows just won't be source-coloured */ }
  }

  /* source index for packet number n (1-based), or -1 */
  function srcOf(n) {
    return (S.srcMap && typeof n === 'number' && n >= 1 && n <= S.srcMap.length)
      ? S.srcMap[n - 1] : -1;
  }
  /* position of packet n in its ORIGINAL pcap: for combined sessions the
     per-source running index (derived from the source map), else n itself */
  function origPosOf(n) {
    if (typeof n !== 'number' || n < 1) return 0;
    if (S.origPos && n <= S.origPos.length) return S.origPos[n - 1];
    return S.srcMap ? 0 : n;   /* combined but map not loaded yet: unknown */
  }
  /* display alias for a source index */
  function srcAlias(idx) {
    const srcs = (S.infoData && S.infoData.sources) || [];
    return srcs[idx] ? (srcs[idx].alias || srcs[idx].name || ('source ' + idx)) : null;
  }

  /* colour + alias legend above the event table (combined sessions only) */
  function renderSourceLegend() {
    const srcs = (S.infoData && S.infoData.sources) || [];
    if (srcs.length < 2) { sourceLegend.hidden = true; sourceLegend.replaceChildren(); return; }
    sourceLegend.hidden = false;
    sourceLegend.replaceChildren(
      h('span', { class: 'sl-label dim small' }, 'sources:'),
      ...srcs.map((sc) => h('span', {
        class: 'sl-item', title: sc.name || sc.pcap_id + ' — rename in Info tab',
      },
        h('span', { class: 'sl-dot src-c' + ((sc.index != null ? sc.index : 0) % 6) }),
        h('span', { class: 'sl-name' }, sc.alias || sc.name || sc.pcap_id))));
  }

  /* ────────── selection ────────── */

  let inspNeedsEvent = -1;   /* selected-but-not-yet-loaded event index */
  let topoSelMac = null;     /* Topology tab: selected device MAC (lowercased) */
  let topoSelPort = null;    /* Topology tab: focused gPTP port id, or null */
  let topoModel = null;      /* last-built model, reused for selection-only updates */
  let topoNodeEls = null;    /* Map(mac -> node element) from the last full render */
  let topoPanelHost = null;  /* the panel container swapped on selection */
  let topoGraphEl = null;    /* the graph container, reused to redraw edges on scrub */
  let topoAsofSlot = null;   /* header "as of …" chip, refreshed on scrub */
  let topoNetHost = null;    /* always-on network-machines section, re-timed on scrub */
  let topoResetBtn = null;   /* "Reset layout" — enabled once a node was dragged */

  function selectEvent(i, opts) {
    opts = opts || {};
    S.selected = i;
    S.lonePacket = 0;
    const e = S.events[i];
    /* recompute the filtered set when the target is hidden by the active
       filter (so it's force-included) or when a previously force-included row
       must now drop out; otherwise a cheap row re-render is enough */
    if ((e && !passes(e)) || S.forced >= 0) applyFilters();
    else scheduleTable();
    if (e) tlCenterOn(e.ts); /* keep the selection visible in the timeline */
    tlSchedule();
    if (opts.scroll) scrollToSelected();
    /* Selecting a packet keeps whatever tab is open on the right. The Packet
       inspector re-renders for the new packet; the Machines and Topology views
       re-overlay their diagrams to the cursor's moment (their "current" state
       tracks the timeline bar). Notes/Info are left untouched. */
    if (opts.inspect && S.tab !== 'inspect') setTab('inspect');
    else if (S.tab === 'inspect') renderInspector();
    else if (S.tab === 'topology') syncTopologyToCursor();
    renderMachineWins();   /* floating machine windows track the cursor too */
  }

  function clearSelection() {
    if (S.selected < 0 && !S.lonePacket) return;
    const wasForced = S.forced >= 0;
    S.selected = -1;
    S.lonePacket = 0;
    if (wasForced) applyFilters();   /* drop the force-included row */
    else scheduleTable();
    tlSchedule();
    /* back to the final observed state on the time-tracking views */
    if (S.tab === 'inspect') renderInspector();
    else if (S.tab === 'topology') syncTopologyToCursor();
    renderMachineWins();
  }

  function jumpToPacket(n) {
    const i = S.nToI.get(n);
    if (i !== undefined) {
      /* explicit "go to packet" link -> show the packet inspector */
      selectEvent(i, { scroll: true, inspect: true });
    } else {
      S.selected = -1;
      S.lonePacket = n;
      scheduleTable();
      tlSchedule();
      if (S.tab !== 'inspect') setTab('inspect');
      else renderInspector();
    }
  }

  /* Select an event by its index — the same select+scroll+inspect behaviour as
     a packet link (including force-including it when the filter would hide it).
     Used for derived transitions (timer/event-driven, no causing packet). */
  function jumpToEvent(i) {
    if (typeof i === 'number' && i >= 0) selectEvent(i, { scroll: true, inspect: true });
  }
  /* event index of the transition event matching a machine-history entry
     (from|to|why|ts), or -1 if not found / not loaded yet */
  function transEventIdx(t) {
    if (!t) return -1;
    const key = (t.from || '') + '\x1f' + (t.to || '') + '\x1f' + (t.why || '') + '\x1f' + t.ts;
    const i = S.transIdx.get(key);
    return i === undefined ? -1 : i;
  }

  function onKey(ev) {
    if (S.tab === 'notes' && (ev.ctrlKey || ev.metaKey) && !ev.altKey
        && (ev.key === 's' || ev.key === 'S')) {
      ev.preventDefault();
      saveNotes();
      return;
    }
    const t = ev.target;
    if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT')) {
      if (ev.key === 'Escape') t.blur();
      return;
    }
    if (ev.key === 'Escape') { clearSelection(); return; }
    if ((ev.key === 'm' || ev.key === 'M') && !ev.ctrlKey && !ev.metaKey && !ev.altKey) {
      /* quick marker at the current selection */
      if (S.selected >= 0 && S.events[S.selected]) {
        ev.preventDefault();
        addMarkerHere();
      }
      return;
    }
    if (ev.key !== 'ArrowDown' && ev.key !== 'ArrowUp') return;
    const n = S.filtered.length;
    if (!n) return;
    ev.preventDefault();
    let r = S.selected >= 0 ? filteredPos(S.selected) : -1;
    let nr;
    if (r < 0) nr = Math.min(n - 1, Math.max(0, Math.floor(tableBody.scrollTop / ROW_H)));
    else nr = ev.key === 'ArrowDown' ? Math.min(n - 1, r + 1) : Math.max(0, r - 1);
    selectEvent(S.filtered[nr], { scroll: true });
  }
  document.addEventListener('keydown', onKey);

  /* ────────── inspector: packet + transition detail ────────── */

  function setTab(t) {
    /* auto-save on leave — but never while a conflict awaits a decision */
    if (S.tab === 'notes' && t !== 'notes' && N.dirty && !N.conflict) saveNotes();
    S.tab = t;
    tabInspBtn.classList.toggle('active', t === 'inspect');
    tabStateBtn.classList.toggle('active', t === 'state');
    tabNotesBtn.classList.toggle('active', t === 'notes');
    tabMarkersBtn.classList.toggle('active', t === 'markers');
    tabInfoBtn.classList.toggle('active', t === 'info');
    tabTopologyBtn.classList.toggle('active', t === 'topology');
    setPresenceView(t === 'notes' ? 'session/' + id + ':notes' : 'session/' + id);
    renderInspector();
  }

  function placeholder(msg) {
    return h('div', { class: 'insp-placeholder dim' }, msg);
  }

  function metaRow(label, ...value) {
    return [h('span', { class: 'f-name' }, label), h('span', { class: 'f-val' }, ...value)];
  }

  function entityLabel(idStr) {
    if (!idStr) return null;
    const name = entityName(idStr);
    return h('span', { class: 'ent' },
      name ? h('b', null, name + ' ') : null,
      h('span', { class: 'mono' }, idStr));
  }

  /* Re-render a time-tracking view without yanking the scroll position: the
     inspector rebuilds its .insp-scroll on every render, and the Machines tab
     also scrolls the selected MRP step into view — both would jump the panel
     when you merely change the selected packet. Preserve the scroll offset. */
  function reRenderKeepingScroll(renderFn) {
    closeEdgePop();
    const cur = inspBody.querySelector('.insp-scroll');
    const top = cur ? cur.scrollTop : 0;
    renderFn();
    const next = inspBody.querySelector('.insp-scroll');
    if (next && top) next.scrollTop = top;
  }

  function renderInspector() {
    if (S.tab === 'state') { renderStateTab(); return; }
    if (S.tab === 'notes') { renderNotesTab(); return; }
    if (S.tab === 'markers') { renderMarkersTab(); return; }
    if (S.tab === 'info') { renderInfoTab(); return; }
    if (S.tab === 'topology') { renderTopologyTab(); return; }
    if (S.lonePacket > 0) {
      const holder = h('div', { class: 'insp-scroll' });
      inspBody.replaceChildren(holder);
      renderPacketInto(holder, S.lonePacket);
      return;
    }
    if (S.selected < 0) {
      inspBody.replaceChildren(placeholder('Select an event in the table or timeline to inspect it. ↑/↓ navigate · Esc clears.'));
      return;
    }
    const e = S.events[S.selected];
    if (!e) {
      inspNeedsEvent = S.selected;
      inspBody.replaceChildren(placeholder('Event #' + S.selected + ' is still loading…'));
      return;
    }
    const parts = [];
    const metaRows = [];
    metaRows.push(metaRow('event', h('span', { class: 'mono' }, '#' + e.i)));
    metaRows.push(metaRow('packet', e.n > 0
      ? h('span', { class: 'mono' }, '#' + e.n)
      : h('span', { class: 'dim' }, 'derived — no packet')));
    metaRows.push(metaRow('time', h('span', { class: 'mono' }, fmtTime(e.ts))));
    metaRows.push(metaRow('proto / kind',
      h('span', { class: 'badge ' + protoClass(e.proto) }, e.proto), ' ',
      h('span', { class: 'dim' }, e.kind)));
    metaRows.push(metaRow('type', h('span', { class: 'mono' }, e.type || '')));
    if (e.src || e.dst) {
      metaRows.push(metaRow('src → dst',
        macSpan(e.src),
        h('span', { class: 'dim' }, ' → '),
        macSpan(e.dst)));
    }
    if (e.entity) metaRows.push(metaRow('entity', entityLabel(e.entity)));
    if (e.stream) metaRows.push(metaRow('stream', h('span', { class: 'mono' }, e.stream)));
    parts.push(h('div', { class: 'insp-meta' }, metaRows));
    if (e.summary) parts.push(h('div', { class: 'insp-summary' }, e.summary));

    if (e.kind === 'transition') {
      const f = e.fields || {};
      parts.push(h('div', { class: 'trans-card' },
        h('div', { class: 'trans-title' }, 'State transition'),
        h('div', { class: 'insp-meta' },
          metaRow('object', h('span', { class: 'mono' }, String(f.object !== undefined ? f.object : ''))),
          metaRow('transition',
            stateBadge(String(f.from !== undefined ? f.from : '?')),
            h('span', { class: 'dim' }, ' → '),
            stateBadge(String(f.to !== undefined ? f.to : '?'))),
          metaRow('why', String(f.why !== undefined ? f.why : '')),
        ),
        e.n > 0
          ? h('div', { class: 'trans-link' },
              h('button', { class: 'linklike', type: 'button', onclick: () => jumpToPacket(e.n) },
                'go to causing packet #' + e.n))
          : null,
      ));
    } else if (e.fields && Object.keys(e.fields).length) {
      parts.push(h('details', { class: 'layer', open: true },
        h('summary', { class: 'layer-head' }, 'event fields'),
        h('div', { class: 'layer-fields' },
          Object.entries(e.fields).map(([k, v]) => [
            h('span', { class: 'f-name' }, k),
            fieldVal(typeof v === 'object' ? JSON.stringify(v) : String(v)),
          ]),
        ),
      ));
    }

    if (e.kind === 'error') {
      parts.push(h('div', { class: 'err-card' },
        h('b', null, 'Decode error'), ' — ', e.summary || 'malformed frame'));
    }

    const holder = h('div', { class: 'pkt-holder' });
    parts.push(holder);
    inspBody.replaceChildren(h('div', { class: 'insp-scroll' }, parts));
    if (e.n > 0) renderPacketInto(holder, e.n);
  }

  let pktReq = 0;
  function renderPacketInto(container, n) {
    const req = ++pktReq;
    container.replaceChildren(h('div', { class: 'dim small pad8' }, 'loading packet #' + n + '…'));
    fetchPacket(n).then((pkt) => {
      if (S.closed || req !== pktReq) return;
      container.replaceChildren(packetDom(pkt));
    }).catch((err) => {
      if (S.closed || req !== pktReq) return;
      container.replaceChildren(h('div', { class: 'err-card' }, 'packet #' + n + ': ' + err.message));
    });
  }

  async function fetchPacket(n) {
    if (S.packetCache.has(n)) return S.packetCache.get(n);
    const pkt = await api('/api/sessions/' + encodeURIComponent(id) + '/packets/' + n);
    S.packetCache.set(n, pkt);
    if (S.packetCache.size > 300) {
      S.packetCache.delete(S.packetCache.keys().next().value);
    }
    return pkt;
  }

  function packetDom(pkt) {
    const layers = (pkt.layers || []).map((ly) =>
      h('details', { class: 'layer', open: true },
        h('summary', { class: 'layer-head mono' }, ly.service || 'layer'),
        h('div', { class: 'layer-fields' },
          (ly.fields || []).map((f) => [
            h('span', { class: 'f-name' }, f.name),
            fieldVal(f.value),
          ]),
        ),
      ));
    return h('div', { class: 'packet-view' },
      h('div', { class: 'pkt-head' },
        h('b', null, 'packet #' + pkt.n),
        h('span', { class: 'dim mono small' },
          '  ' + fmtTime(pkt.ts) + ' · ' + pkt.len + ' B'
          + (pkt.caplen !== undefined && pkt.caplen !== pkt.len ? ' (captured ' + pkt.caplen + ')' : '')),
        pkt.source_alias ? h('span', {
          class: 'pkt-src src-c' + ((pkt.source_index || 0) % 6),
          title: 'source capture: ' + (pkt.source_name || pkt.source_alias)
            + ' — rename in the Info tab',
        }, '⎘ ' + pkt.source_alias) : null,
      ),
      layers.length ? layers : h('div', { class: 'dim small pad8' }, 'no decoded layers'),
      hexDump(pkt.hex || ''),
    );
  }

  function hexDump(hex) {
    const nBytes = hex.length >> 1;
    if (!nBytes) return h('div', { class: 'dim small pad8' }, 'no raw bytes');
    const lines = [];
    for (let off = 0; off < nBytes; off += 16) {
      const end = Math.min(off + 16, nBytes);
      let hx = '';
      let ascii = '';
      for (let b = off; b < end; b++) {
        const bh = hex.slice(b * 2, b * 2 + 2);
        hx += bh + (b === off + 7 ? '  ' : ' ');
        const v = parseInt(bh, 16);
        ascii += (v >= 0x20 && v < 0x7f) ? String.fromCharCode(v) : '.';
      }
      lines.push(off.toString(16).padStart(4, '0') + '  ' + hx.padEnd(49, ' ') + ' ' + ascii);
    }
    return h('pre', { class: 'hexdump' }, lines.join('\n'));
  }

  /* ────────── inspector: state tab ────────── */
  /* (stateClass/stateBadge/kvList are module-level, shared with the admin view) */

  /* the jump link for one history transition: its causing packet ("pkt N") if
     there is one, else — for a timer/event-driven transition — the transition
     event itself ("◆ #<i>", its place in the table's # column). */
  function histLink(t) {
    if (typeof t.n === 'number' && t.n > 0)
      return h('button', { class: 'linklike mono', type: 'button', onclick: () => jumpToPacket(t.n) }, 'pkt ' + t.n);
    const ei = transEventIdx(t);
    if (ei >= 0)
      return h('button', {
        class: 'linklike mono', type: 'button',
        title: 'go to this derived state event (# ' + ei + ' in the table)',
        onclick: () => jumpToEvent(ei),
      }, '◆ #' + ei);
    return null;
  }

  function historyBlock(hist) {
    if (!Array.isArray(hist) || !hist.length) return null;
    return h('details', { class: 'history' },
      h('summary', null, 'history (' + hist.length + ')'),
      h('div', { class: 'hist-rows' },
        hist.map((t) => h('div', { class: 'hist-row' },
          h('span', { class: 'mono hist-ts' }, fmtTime(t.ts)),
          stateBadge(t.from, true),
          h('span', { class: 'dim' }, '→'),
          stateBadge(t.to, true),
          h('span', { class: 'hist-why', title: t.why || '' }, t.why || ''),
          histLink(t),
        )),
      ),
    );
  }

  function sobj(title, badge, kv, extra, history) {
    return h('div', { class: 'sobj' },
      h('div', { class: 'sobj-head' }, h('span', { class: 'sobj-title' }, title), badge || null),
      kv || null,
      extra || null,
      historyBlock(history),
    );
  }

  function stateSection(titleTxt, arr, renderItem) {
    const items = (arr || []).map(renderItem);
    return h('section', { class: 'ssec' },
      h('h3', null, titleTxt, ' ', h('span', { class: 'count mono' }, String((arr || []).length))),
      items.length ? items : h('div', { class: 'empty small' }, 'None observed.'),
    );
  }

  async function loadState() {
    if (S.stateLoading || S.closed) return;
    S.stateLoading = true;
    try {
      const st = await api('/api/sessions/' + encodeURIComponent(id) + '/state');
      if (S.closed) return;
      S.stateData = st;
      S.entityNames.clear();
      for (const en of st.entities || []) {
        if (en.entity_id && en.name) S.entityNames.set(en.entity_id, en.name);
      }
      if (S.tab === 'state') renderStateTab();
      else if (S.tab === 'topology') renderTopologyTab();
      renderMachineWins();
    } catch (err) {
      if (!S.closed) toast('state: ' + err.message, 'error');
    } finally {
      S.stateLoading = false;
    }
  }

  function renderStateTab() {
    if (!S.stateData) {
      inspBody.replaceChildren(placeholder(S.stateLoading ? 'Loading state…'
        : 'State not loaded yet.'));
      if (!S.stateLoading) loadState();
      return;
    }
    const st = S.stateData;
    const refreshBtn = h('button', { class: 'btn btn-sm', type: 'button' }, 'Refresh');
    refreshBtn.addEventListener('click', () => { S.stateData = null; renderStateTab(); });

    const entitySec = stateSection('Entities (ADP)', st.entities, (en) => sobj(
      h('span', null,
        en.name ? h('b', null, en.name + ' ') : null,
        h('span', { class: 'mono' }, en.entity_id || '')),
      stateBadge(en.state),
      kvList([
        ['last seen', fmtTime(en.last_seen)],
        ['avail idx', en.available_index],
        ['talker srcs', en.talker_sources],
        ['listener sinks', en.listener_sinks],
        ['model', en.model_id],
        ['gPTP GM', en.gptp_gm ? h('span', null,
          h('span', { class: 'kv-v mono' }, en.gptp_gm), ' ',
          en.gm_in_sync && en.gm_in_sync !== 'UNKNOWN'
            ? stateBadge(en.gm_in_sync, true) : null) : undefined],
      ]),
      null, en.history));

    const resvSec = stateSection('Stream reservations (MSRP)', st.reservations, (r) => {
      const listeners = (r.listeners || []).map((l) =>
        h('span', { class: 'listener' },
          h('span', { class: 'mono' }, l.mac), ' ', stateBadge(l.state, true)));
      const failed = r.declaration === 'FAILED';
      return sobj(
        h('span', { class: 'mono' }, r.stream_id || ''),
        stateBadge(r.state),
        kvList([
          ['talker', r.talker_mac],
          ['dest', r.dest_mac],
          ['VLAN', r.vlan],
          ['frame size', r.max_frame_size],
          ['frames/int', r.max_interval_frames],
          ['prio', r.priority],
          ['rank', r.rank],
          ['acc. latency', (typeof r.accumulated_latency === 'number' ? fmtInt(r.accumulated_latency) + ' ns' : undefined)],
          ['declaration', h('span', null, stateBadge(r.declaration, true),
            failed ? h('span', { class: 'errtext small' },
              ' bridge ' + (r.failure_bridge || '?') + ' code ' + (r.failure_code !== undefined ? r.failure_code : '?')) : null)],
          ['gPTP sync', r.gptp_sync && r.gptp_sync !== 'UNKNOWN'
            ? stateBadge(r.gptp_sync, true) : undefined],
        ]),
        listeners.length
          ? h('div', { class: 'listeners' }, h('span', { class: 'kv-k' }, 'listeners '), listeners)
          : null,
        r.history);
    });

    const vlanSec = stateSection('VLANs (MVRP)', st.vlans, (v) => sobj(
      h('span', null, 'VLAN ', h('b', { class: 'mono' }, String(v.vid))),
      stateBadge(v.state),
      kvList([
        ['members', (v.members || []).length ? (v.members || []).join(', ') : undefined],
      ]),
      null, v.history));

    const domSec = stateSection('SRP domains (MSRP)', st.domains, (d) => sobj(
      h('span', null, 'class ', h('b', { class: 'mono' }, String(d.class_id))),
      null,
      kvList([
        ['priority', d.priority],
        ['VID', d.vid],
        ['declarer', d.declarer],
      ]),
      null, null));

    const maapSec = stateSection('MAAP address ranges', st.maap, (m) => {
      const end = (typeof m.count === 'number' && m.count > 0) ? macAdd(m.range_start, m.count - 1) : null;
      return sobj(
        h('span', null,
          h('span', { class: 'mono' }, m.range_start || ''),
          end && end !== m.range_start ? h('span', { class: 'dim' }, ' … ') : null,
          end && end !== m.range_start ? h('span', { class: 'mono' }, end) : null),
        stateBadge(m.state),
        kvList([
          ['claimant', m.claimant],
          ['count', m.count],
          ['conflicts', m.conflicts],
        ]),
        null, m.history);
    });

    const connSec = stateSection('Connections (ACMP)', st.connections, (c) => sobj(
      h('span', { class: 'conn-title' },
        entityLabel(c.talker_entity),
        h('span', { class: 'mono dim' }, ':' + (c.talker_unique_id !== undefined ? c.talker_unique_id : '?')),
        h('span', { class: 'dim' }, ' → '),
        entityLabel(c.listener_entity),
        h('span', { class: 'mono dim' }, ':' + (c.listener_unique_id !== undefined ? c.listener_unique_id : '?'))),
      stateBadge(c.state),
      kvList([
        ['controller', entityLabel(c.controller_entity)],
        ['stream', c.stream_id],
        ['dest', c.dest_mac],
        ['VLAN', c.vlan],
        ['conn count', c.connection_count],
      ]),
      null, c.history));

    const aecpSec = stateSection('AECP transactions', st.aecp, (a) => {
      const lastRows = (a.last || []).map((cmd) => h('div', { class: 'aecp-row' },
        h('span', { class: 'mono dim' }, 'seq ' + cmd.sequence_id),
        h('span', { class: 'mono' }, cmd.command),
        stateBadge(cmd.status, true),
        h('span', { class: 'mono dim' }, (typeof cmd.rtt_ms === 'number' ? cmd.rtt_ms.toFixed(1) + ' ms' : '')),
      ));
      return sobj(
        h('span', { class: 'conn-title' },
          entityLabel(a.controller), h('span', { class: 'dim' }, ' → '), entityLabel(a.target)),
        (a.timeouts > 0) ? h('span', { class: 'sbadge st-warn' }, a.timeouts + ' timeouts') : null,
        kvList([
          ['commands', a.commands],
          ['responses', a.responses],
          ['timeouts', a.timeouts],
          ['unsolicited', a.unsolicited],
        ]),
        lastRows.length ? h('div', { class: 'aecp-last' }, lastRows) : null,
        null);
    });

    const gptp = st.gptp || {};
    const gptpDomSec = stateSection('gPTP domains (802.1AS)', gptp.domains, (d) => {
      const gm = d.grandmaster || {};
      return sobj(
        h('span', null, 'domain ', h('b', { class: 'mono' }, String(d.domain)),
          h('span', { class: 'dim' }, ' GM '),
          gm.name ? h('b', null, gm.name + ' ') : null,
          h('span', { class: 'mono' }, gm.clock_identity || '—')),
        h('span', null, stateBadge(d.state), ' ',
          stateBadge(d.sync || 'UNKNOWN', true)),
        kvList([
          ['prio1/2', gm.priority1 + '/' + gm.priority2],
          ['clock class', gm.clock_class],
          ['steps', gm.steps_removed],
          ['time source', gm.time_source],
          ['sync interval', d.sync_interval_ms + ' ms'],
          ['sync/fu', d.sync_count + '/' + d.follow_up_count],
          ['announces', d.announce_count],
          ['rate offset', (typeof d.cumulative_rate_offset_ppm === 'number'
            ? d.cumulative_rate_offset_ppm.toFixed(2) + ' ppm' : undefined)],
          ['path', d.path_trace],
          ['BMCA', d.bmca && d.bmca !== 'UNKNOWN'
            ? stateBadge(d.bmca, true) : undefined],
          ['expected GM', (d.bmca === 'PRIORITY_INVERSION' || d.bmca === 'TIEBREAK')
            ? h('span', null,
                d.expected_gm_name ? h('b', null, d.expected_gm_name + ' ') : null,
                h('span', { class: 'kv-v mono' }, d.expected_gm || ''))
            : undefined],
        ]),
        null, d.history);
    });

    const gptpPortSec = stateSection('gPTP ports', gptp.ports, (p) => {
      const pd = p.pdelay || {};
      const md = p.md || {};
      return sobj(
        h('span', null,
          p.name ? h('b', null, p.name + ' ') : null,
          h('span', { class: 'mono' }, p.port || ''),
          h('span', { class: 'dim small' }, ' ' + (p.src_mac || ''))),
        h('span', null, stateBadge(p.role), ' ', stateBadge(p.as_capable, true)),
        kvList([
          ['domain', p.domain],
          ['sync sent', p.sync_sent],
          ['announce sent', p.announce_sent],
          ['pdelay ok/init', pd.complete + '/' + pd.initiated],
          ['pdelay lost', pd.lost],
          ['turnaround', (typeof pd.last_turnaround_us === 'number' && pd.last_turnaround_us >= 0
            ? pd.last_turnaround_us.toFixed(1) + ' µs (wire)' : undefined)],
          ['req↔resp gap', (typeof pd.last_observed_gap_ms === 'number' && pd.last_observed_gap_ms >= 0
            ? '≈' + pd.last_observed_gap_ms.toFixed(2) + ' ms (capture)' : undefined)],
          ['MDPdelayReq', md.pdelay_req_state !== 'NOT_ENABLED' ? md.pdelay_req_state : undefined],
          ['MDPdelayResp', md.pdelay_resp_state !== 'NOT_ENABLED' ? md.pdelay_resp_state : undefined],
          ['MDSyncSend', md.sync_send_state && md.sync_send_state !== 'NOT_ENABLED'
            ? md.sync_send_state : undefined],
          ['MD resets', md.resets || undefined],
          ['announce', p.announce_state && p.announce_state !== 'NONE'
            ? stateBadge(p.announce_state, true) : undefined],
          ['gPTP capable', p.gptp_capable && p.gptp_capable !== 'UNKNOWN'
            ? stateBadge(p.gptp_capable, true) : undefined],
          ['req. intervals', p.requested_intervals
            ? 'sync ' + p.requested_intervals.time_sync
              + ' · announce ' + p.requested_intervals.announce
              + ' · pdelay ' + p.requested_intervals.link_delay
            : undefined],
        ]),
        h('div', { class: 'dim small' },
          '802.1AS Clause ' + (md.clause || '11') + ' media-dependent machines'),
        p.history);
    });

    // Milan v1.2 §5.5.3: listener sink state machine + stateless talkers.
    const milanSinkSec = stateSection('Milan listener sinks (§5.5.3)',
      st.milan_sinks, (s) => sobj(
        h('span', { class: 'conn-title' },
          entityLabel(s.listener_entity),
          h('span', { class: 'mono dim' }, ':' + s.listener_unique_id)),
        h('span', null, stateBadge(s.state), ' ',
          stateBadge(s.probing_status, true)),
        kvList([
          ['bound talker', s.bound_talker
            ? h('span', null, entityLabel(s.bound_talker),
                h('span', { class: 'mono dim' }, ':' + s.bound_talker_unique_id))
            : undefined],
          ['controller', s.controller ? entityLabel(s.controller) : undefined],
          ['stream', s.stream_id || undefined],
          ['dest', s.dest_mac || undefined],
          ['VLAN', s.vlan || undefined],
          ['probes sent', s.probes_sent],
        ]),
        null, s.history));

    const milanTalkerSec = stateSection('Milan talker sources (stateless, §5.5.2.7)',
      st.milan_talkers, (t) => sobj(
        h('span', { class: 'conn-title' },
          entityLabel(t.talker_entity),
          h('span', { class: 'mono dim' }, ':' + t.talker_unique_id)),
        stateBadge(t.srp_declaration === 'ADVERTISE' ? 'ADVERTISE'
          : t.srp_declaration === 'FAILED' ? 'FAILED' : 'NO_SRP', true),
        kvList([
          ['probes answered', t.probe_responses + '/' + t.probes_received],
          ['last status', t.last_status],
          ['stream', t.stream_id || undefined],
          ['SRP declaration', t.srp_declaration],
          ['disconnect_tx seen', t.disconnect_tx_seen || undefined],
          ['get_tx_connection seen', t.get_tx_connection_seen || undefined],
        ]),
        null, t.history));

    inspBody.replaceChildren(h('div', { class: 'insp-scroll' },
      h('div', { class: 'state-actions' },
        h('span', { class: 'dim small' }, 'Reconstructed protocol state'),
        h('span', { class: 'toolbar-spacer' }),
        refreshBtn),
      entitySec, resvSec, vlanSec, domSec, maapSec, connSec,
      milanSinkSec, milanTalkerSec, aecpSec,
      gptpDomSec, gptpPortSec,
    ));
  }

  /* ────────── inspector: machines tab ──────────
     Draws the Milan v1.2 protocol state machines as spec diagrams with the
     selected instance's reconstructed state overlaid (see drawMachine). */

  /* option/short label for an entity id: user/AEM name if known, else the id */
  function entText(idStr) {
    return (idStr && entityName(idStr)) || idStr || '?';
  }

  /* ── time-indexed overlays ────────────────────────────────────────────
     "current" must mean current AS OF where the timeline cursor sits — the
     selected event's timestamp — not merely the end of capture. curTs() is
     that cursor time (Infinity = nothing selected = final observed state);
     liveAtN walks an object's transition history up to it. Faithful to the
     observed transitions only — never fabricates a state. */
  function curTs() {
    if (S.selected >= 0 && S.events[S.selected]
        && typeof S.events[S.selected].ts === 'number') return S.events[S.selected].ts;
    return Infinity;
  }
  /* a chip telling the user which moment every diagram below reflects */
  function asOfBadge() {
    if (S.selected >= 0 && S.events[S.selected]) {
      const e = S.events[S.selected];
      return h('span', { class: 'asof',
        title: 'the diagrams show each machine’s state at this point on the timeline — move the cursor to scrub' },
        'as of ', h('span', { class: 'mono' },
          (e.n > 0 ? 'pkt ' + e.n + ' · ' : '') + fmtTime(e.ts)));
    }
    return h('span', { class: 'asof dim',
      title: 'no event selected — showing the final observed state; click a packet or the timeline to scrub through time' },
      'final observed state');
  }

  /* state in effect at cursor time T: current = last transition with ts≤T
     (or the pre-first-transition state), visited = states seen up to T,
     history = the transitions walked so far. */
  function liveAtN(history, finalState, T) {
    const hist = Array.isArray(history) ? history : [];
    if (T == null) T = Infinity;
    const visited = new Set();
    const walked = [];
    let current = null, initial = null;
    for (const t of hist) {
      if (initial == null) initial = t.from;
      if (typeof t.ts === 'number' && t.ts > T) break;   /* history is time-ordered */
      visited.add(t.from); visited.add(t.to);
      walked.push({ from: t.from, to: t.to, why: t.why, ts: t.ts, n: t.n });
      current = t.to;
    }
    if (current == null) current = hist.length ? (initial != null ? initial : finalState) : finalState;
    if (current) visited.add(current);
    return { current, history: walked, visited };
  }
  function sinkLive(sink, T) {
    if (!sink) return { current: null, history: [], visited: new Set() };
    const r = liveAtN(sink.history, sink.state || null, T == null ? curTs() : T);
    r.fullHistory = sink.history || [];   /* all triggers, for edge-click */
    return r;
  }
  function entityLive(en, T) {
    if (!en) return { current: null, history: [], visited: new Set() };
    const r = liveAtN(en.history, en.state || null, T == null ? curTs() : T);
    r.fullHistory = en.history || [];
    return r;
  }
  function connLive(c, T) {
    if (!c) return { current: null, history: [], visited: new Set() };
    const r = liveAtN(c.history, c.state || 'DISCONNECTED', T == null ? curTs() : T);
    r.fullHistory = c.history || [];
    return r;
  }
  /* Milan talkers are stateless — the overlay only animates the self-loop
     (its clickable triggers list every observed response) */
  function talkerLive(t, T) {
    const r = liveAtN(t.history, 'STATELESS', T == null ? curTs() : T);
    r.current = 'STATELESS';
    r.visited.add('STATELESS');
    r.fullHistory = t.history || [];
    return r;
  }
  function advertiseLive(en, T) {
    const cur = entityLive(en, T).current === 'AVAILABLE' ? 'WAITING' : null;
    return { current: cur, history: [], visited: new Set(cur ? [cur] : []) };
  }
  /* talker_discovered is a live-only field (no transition history), so it is
     not time-indexed — shown as the final observed value. */
  function discoveryLive(sink) {
    const cur = (sink && sink.talker_discovered && sink.talker_discovered !== 'N/A')
      ? sink.talker_discovered : null;
    const v = new Set();
    if (cur) { v.add(cur); if (cur === 'TK_DISCOVERED') v.add('TK_NOT_DISCOVERED'); }
    return { current: cur, history: [], visited: v };
  }
  /* gPTP port role / asCapable at T. The port history interleaves both fields.
     Classify each transition by its DESTINATION (role-only vs asCapable-only
     values); UNKNOWN is shared by both, so for a to=UNKNOWN transition fall back
     to the source to decide which machine it belongs to. Then walk to T. */
  const GPTP_ROLE_ONLY = new Set(['MASTER', 'SLAVE', 'PASSIVE', 'DISABLED']);
  const GPTP_ASCAP_ONLY = new Set(['AS_CAPABLE', 'NOT_AS_CAPABLE']);
  function portFieldAt(p, onlySet, finalVal, T) {
    const rel = (Array.isArray(p.history) ? p.history : [])
      .filter((t) => onlySet.has(t.to) || (t.to === 'UNKNOWN' && onlySet.has(t.from)));
    return liveAtN(rel, finalVal, T == null ? curTs() : T).current || finalVal;
  }
  /* log step at/before cursor time T (-1 = cursor precedes the first event) */
  function mrpStepForTs(log, T) {
    let idx = -1;
    for (let j = 0; j < (log ? log.length : 0); j++) {
      if (typeof log[j].ts === 'number' && log[j].ts > T) break;
      idx = j;
    }
    return idx;
  }

  function machineCard(def, live, liveNote) {
    const scroll = h('div', { class: 'sm-scroll' });
    drawMachine(scroll, def, live);
    const card = h('div', { class: 'machine-card' },
      h('div', { class: 'machine-head' },
        h('span', { class: 'machine-title' }, def.title),
        h('span', { class: 'machine-sub dim small' }, def.subtitle)),
      scroll,
      liveNote ? h('div', { class: 'machine-note mn-live' }, liveNote) : null,
      def.note ? h('div', { class: 'machine-note' }, def.note) : null,
    );
    return foldableCard(card, def.svgId || def.title);
  }

  function machineLegend() {
    const leg = (cls, txt) => h('span', { class: 'mleg' },
      h('span', { class: 'mleg-sw ' + cls }), txt);
    return h('div', { class: 'machine-legend' },
      leg('a-active', 'active (current state)'),
      leg('a-visited', 'reached (history)'),
      leg('a-dim', 'not reached'),
      h('span', { class: 'mleg' }, h('span', { class: 'mleg-sw a-ref' }),
        'reference — not tap-observable'));
  }

  /* ────────── inspector: topology tab ──────────
     Device-centric navigation: a graph of the observed devices (endstations +
     inferred bridges) with their gPTP-sync and stream relationships, and — for
     the selected device or port — every reconstructed state machine, reusing
     the Machines-tab renderer (drawMachine + machineCard + the machine defs).
     The graph itself is a small bespoke renderer (HTML cards + an SVG edge
     layer), NOT drawMachine. Built entirely from S.infoData + S.stateData. */

  const TOPO_PAD = 18;
  const TOPO_CARD_W = 200;
  const TOPO_DX = TOPO_CARD_W + 56;   /* column pitch */
  const TOPO_DY = 172;                /* row pitch (layered by gPTP hierarchy) */
  const TOPO_ROLE_CLS = {
    GM: 'rb-gm', MASTER: 'rb-master', SLAVE: 'rb-slave', Talker: 'rb-talker',
    Listener: 'rb-listener', Controller: 'rb-controller', Bridge: 'rb-bridge',
  };
  const TOPO_ROLE_ORDER = ['GM', 'MASTER', 'SLAVE', 'Talker', 'Listener', 'Controller', 'Bridge'];

  const tnorm = (s) => String(s == null ? '' : s).toLowerCase();
  function isZeroId(x) { const s = tnorm(x); return !s || /^0x0+$/.test(s); }
  function extractHex(s) { return String(s || '').match(/0x[0-9a-fA-F]+/g) || []; }
  function shortStream(sid) {
    if (isZeroId(sid)) return '';           /* never surface an all-zero stream id */
    const s = String(sid || '');
    if (!s) return '';
    const c = s.lastIndexOf(':');
    return c >= 0 ? '…' + s.slice(c) : s;
  }

  /* Correlate /info devices with the /state arrays into one node per MAC.
     Returns { devices: Map(mac->node), entityToMac, entityToMacs, bridgesByDomain }. */
  function buildTopologyModel() {
    const info = S.infoData || {};
    const st = S.stateData || {};
    const devices = new Map();
    function ensure(mac) {
      const key = tnorm(mac);
      if (!key) return null;
      let n = devices.get(key);
      if (!n) {
        n = {
          mac: key, entity_id: '', entity_name: '', name: '', label: key,
          assocIds: [], protocols: [], packets: 0, ports: [], entity: null,
          milanSinks: [], talkerSinks: [], milanTalkers: [], connections: [],
          mrp: [], roles: new Set(),
          clockIds: new Set(), synthetic: false,
        };
        devices.set(key, n);
      }
      return n;
    }
    for (const d of info.devices || []) {
      const n = ensure(d.mac);
      if (!n) continue;
      n.entity_id = d.entity_id || '';
      n.entity_name = d.entity_name || '';
      n.name = d.name || '';
      n.assocIds = (d.assoc_entity_ids || []).slice();
      n.protocols = (d.protocols || []).slice();
      n.packets = d.packets || 0;
      n.label = d.name || d.entity_name || d.mac;
    }
    /* one entity_id can map to several MACs (seamless redundancy); keep all so
       a redundant device's roles/machines are not silently dropped. */
    const entityToMacs = new Map();
    const mapEntity = (id, mac) => {
      const k = tnorm(id);
      if (!k || isZeroId(k)) return;
      const arr = entityToMacs.get(k) || [];
      if (!arr.includes(mac)) arr.push(mac);
      entityToMacs.set(k, arr);
    };
    for (const n of devices.values()) {
      if (n.entity_id) mapEntity(n.entity_id, n.mac);
    }
    /* secondary ids (AECP/ACMP controllers, emulated talkers/listeners) map
       after the ADP-advertised ones so those keep the primary slot; this is
       what ties a pure controller (e.g. a certification test machine) to the
       ACMP/AECP state it produced. */
    for (const n of devices.values()) {
      for (const aid of n.assocIds || []) mapEntity(aid, n.mac);
    }
    const macsFor = (id) => entityToMacs.get(tnorm(id)) || [];
    const entityToMac = new Map();   /* first MAC per entity — single-endpoint edges */
    for (const [k, arr] of entityToMacs) entityToMac.set(k, arr[0]);

    const gptp = st.gptp || {};
    const gmClocks = new Set();
    for (const dom of gptp.domains || []) {
      const gm = dom.grandmaster || {};
      if (gm.clock_identity) gmClocks.add(tnorm(gm.clock_identity));
      if (dom.sync_gm) gmClocks.add(tnorm(dom.sync_gm));
    }
    /* gPTP ports attach by src_mac (creating a node if the port's source was
       never seen as a device); MASTER/SLAVE roles come straight off the port. */
    const localClocks = new Set();
    for (const p of gptp.ports || []) {
      const n = ensure(p.src_mac);
      if (!n) continue;
      n.ports.push(p);
      if (!n.protocols.includes('GPTP')) n.protocols.push('GPTP');
      const clk = tnorm(p.clock_identity || String(p.port || '').split(':')[0]);
      if (clk) { n.clockIds.add(clk); localClocks.add(clk); }
      if (p.role === 'MASTER') n.roles.add('MASTER');
      else if (p.role === 'SLAVE') n.roles.add('SLAVE');
    }
    for (const n of devices.values()) {
      for (const clk of n.clockIds) { if (gmClocks.has(clk)) { n.roles.add('GM'); break; } }
    }
    for (const en of st.entities || []) {
      for (const mac of macsFor(en.entity_id)) {
        const n = devices.get(mac); if (!n) continue;
        n.entity = en;
        if (en.talker_sources > 0) n.roles.add('Talker');
        if (en.listener_sinks > 0) n.roles.add('Listener');
      }
    }
    for (const s of st.milan_sinks || []) {
      for (const mac of macsFor(s.listener_entity)) {
        const n = devices.get(mac); if (n) { n.milanSinks.push(s); n.roles.add('Listener'); }
      }
      for (const cm of macsFor(s.controller)) { const n = devices.get(cm); if (n) n.roles.add('Controller'); }
      /* Milan talkers are stateless — the binding state machine lives in the
         listener sink. Still surface it on the bound talker's device, so a
         DUT-centric view shows the machines of streams it talks into. */
      if (s.bound_talker && !isZeroId(s.bound_talker)) {
        for (const tm of macsFor(s.bound_talker)) {
          const n = devices.get(tm);
          if (n && !n.milanSinks.includes(s)) { n.talkerSinks.push(s); n.roles.add('Talker'); }
        }
      }
    }
    for (const t of st.milan_talkers || []) {
      for (const mac of macsFor(t.talker_entity)) {
        const n = devices.get(mac);
        if (n) { n.milanTalkers.push(t); n.roles.add('Talker'); }
      }
    }
    for (const c of st.connections || []) {
      if (!isZeroId(c.talker_entity)) for (const m of macsFor(c.talker_entity)) devices.get(m).roles.add('Talker');
      if (!isZeroId(c.listener_entity)) for (const m of macsFor(c.listener_entity)) devices.get(m).roles.add('Listener');
      if (!isZeroId(c.controller_entity)) for (const m of macsFor(c.controller_entity)) devices.get(m).roles.add('Controller');
      /* the connection machine renders on both stream endpoints — skip
         never-transitioned placeholder rows (e.g. from a lone GET_TX_STATE) */
      if ((!c.history || !c.history.length)
          && (c.state || 'DISCONNECTED') === 'DISCONNECTED') continue;
      const attached = new Set();
      for (const m of macsFor(c.talker_entity).concat(macsFor(c.listener_entity))) {
        if (attached.has(m)) continue;
        attached.add(m);
        const n = devices.get(m);
        if (n) n.connections.push(c);
      }
    }
    for (const r of st.reservations || []) {
      const tn = ensure(r.talker_mac);
      if (tn) tn.roles.add('Talker');
      for (const l of r.listeners || []) { const ln = ensure(l.mac); if (ln) ln.roles.add('Listener'); }
      /* failure_bridge is a clock/bridge identity (8 bytes), NOT a device MAC —
         route it through the synthetic-bridge path, never a device node. */
      if (r.failure_bridge && !isZeroId(r.failure_bridge)) {
        const t = tnorm(r.failure_bridge), bkey = 'clk:' + t;
        let bn = devices.get(bkey);
        if (!bn) { bn = ensure(bkey); bn.label = 'bridge ' + t; bn.synthetic = true; bn.protocols = ['MSRP']; }
        bn.roles.add('Bridge'); bn.clockIds.add(t);
      }
    }
    for (const m of st.mrp || []) {
      const n = ensure(m.source);
      if (n) n.mrp.push(m);
    }
    /* path-trace bridges: clock identities in the path that are neither the GM
       nor a local endstation become synthetic (inferred) bridge nodes. */
    const bridgesByDomain = new Map();
    for (const dom of gptp.domains || []) {
      const brs = [];
      for (const tk of extractHex(dom.path_trace)) {
        const t = tnorm(tk);
        if (gmClocks.has(t) || localClocks.has(t)) continue;
        const key = 'clk:' + t;
        let bn = devices.get(key);
        if (!bn) { bn = ensure(key); bn.label = 'bridge ' + t; bn.synthetic = true; bn.protocols = ['GPTP']; }
        bn.roles.add('Bridge'); bn.clockIds.add(t);
        brs.push(key);
      }
      if (brs.length) bridgesByDomain.set(dom.domain, brs);
    }
    return { devices, entityToMac, entityToMacs, bridgesByDomain };
  }

  /* Edges as of cursor time T (default = the selected event): gPTP sync
     (master→slave per domain, chained through path-trace bridges) + streams
     (ACMP connections and MSRP reservations, talker→listener). Deduped by
     kind|from|to|label; endpoints must be known nodes. */
  function buildTopoEdges(model, T) {
    if (T == null) T = curTs();
    const st = S.stateData || {};
    const gptp = st.gptp || {};
    const edges = [];
    const seen = new Set();
    const add = (kind, from, to, label) => {
      from = tnorm(from); to = tnorm(to);
      if (!from || !to || from === to) return;
      if (!model.devices.has(from) || !model.devices.has(to)) return;
      /* label carries the domain (sync) / stream id (stream), so keeping it in
         the key preserves dual-domain sync links and distinct streams. */
      const key = kind + '|' + from + '|' + to + '|' + (label || '');
      if (seen.has(key)) return;
      seen.add(key);
      edges.push({ kind, from, to, label });
    };
    /* Sync flows from ONE source per domain — the grandmaster — down to each
       slave (chained through any path-trace bridges). A masters×slaves product
       would invent links between unrelated master/slave pairs, so we resolve a
       single source instead: the device holding the GM clock, else the sole
       master; if neither is identifiable we draw nothing rather than guess. */
    const domInfo = new Map();
    for (const dom of gptp.domains || []) domInfo.set(dom.domain, dom);
    const portDomains = new Set((gptp.ports || []).map((p) => p.domain));
    for (const domNum of portDomains) {
      const dom = domInfo.get(domNum) || {};
      const gmIds = new Set();
      if (dom.grandmaster && dom.grandmaster.clock_identity) gmIds.add(tnorm(dom.grandmaster.clock_identity));
      if (dom.sync_gm) gmIds.add(tnorm(dom.sync_gm));
      /* roles as of the cursor: the sync source is whichever port is master
         at T, so the arrow follows BMCA handovers as you scrub. */
      const slaves = [], masters = [];
      for (const p of gptp.ports || []) {
        if (p.domain !== domNum) continue;
        const roleT = portFieldAt(p, GPTP_ROLE_ONLY, p.role || 'UNKNOWN', T);
        if (roleT === 'SLAVE') slaves.push(tnorm(p.src_mac));
        else if (roleT === 'MASTER') masters.push(tnorm(p.src_mac));
      }
      let source = null;
      if (masters.length === 1) source = masters[0];
      else if (gmIds.size) {
        for (const n of model.devices.values()) {
          for (const clk of n.clockIds) { if (gmIds.has(clk)) { source = tnorm(n.mac); break; } }
          if (source) break;
        }
      }
      if (!source) continue;
      const label = 'gPTP domain ' + domNum;
      let head = source;
      for (const br of model.bridgesByDomain.get(domNum) || []) { add('sync', head, br, label); head = tnorm(br); }
      for (const s of slaves) if (s !== head) add('sync', head, s, label);
    }
    /* streams: only where a stream is actually flowing AS OF the cursor — a
       reservation ESTABLISHED at T (to a ready listener), or an ACMP pair
       CONNECTED at T. Torn-down/failed/pending links never draw. */
    for (const c of st.connections || []) {
      if (liveAtN(c.history, c.state, T).current !== 'CONNECTED') continue;
      if (isZeroId(c.talker_entity) || isZeroId(c.listener_entity)) continue;
      add('stream', model.entityToMac.get(tnorm(c.talker_entity)),
        model.entityToMac.get(tnorm(c.listener_entity)), shortStream(c.stream_id));
    }
    for (const r of st.reservations || []) {
      if (liveAtN(r.history, r.state, T).current !== 'ESTABLISHED') continue;
      for (const l of r.listeners || []) {
        if (l.state !== 'READY' && l.state !== 'READY_FAILED') continue;
        add('stream', r.talker_mac, l.mac, shortStream(r.stream_id));
      }
    }
    /* Milan bindings that are not (yet) streaming: a sink bound to a talker
       (probing or settled, as of T) draws dotted, so the relationship between
       the machines involved stays visible even when no stream flows */
    for (const s of st.milan_sinks || []) {
      if (isZeroId(s.bound_talker) || isZeroId(s.listener_entity)) continue;
      const cur = liveAtN(s.history, s.state, T).current || '';
      if (!cur || cur === 'UNBOUND') continue;
      const from = model.entityToMac.get(tnorm(s.bound_talker));
      const to = model.entityToMac.get(tnorm(s.listener_entity));
      /* skip if a live stream edge already joins the pair */
      if (seen.has('stream|' + from + '|' + to + '|' + shortStream(s.stream_id))) continue;
      add('binding', from, to, 'bound · ' + cur);
    }
    return edges;
  }

  function topoRoleBadges(n) {
    return h('div', { class: 'topo-badges' },
      TOPO_ROLE_ORDER.filter((r) => n.roles.has(r)).map((r) =>
        h('span', { class: 'sbadge ' + (TOPO_ROLE_CLS[r] || 'st-neutral') }, r)));
  }

  function selectTopoNode(mac) { topoSelMac = mac; topoSelPort = null; if (!updateTopoSelection()) renderTopologyTab(); }
  function selectTopoPort(mac, port) { topoSelMac = mac; topoSelPort = port; if (!updateTopoSelection()) renderTopologyTab(); }

  /* ── user-arranged node layout (persisted per session) ── */
  const TOPO_POS_KEY = 'avb.topoPos.' + id;
  function topoLoadPos() {
    try { return JSON.parse(localStorage.getItem(TOPO_POS_KEY) || '{}') || {}; }
    catch (err) { return {}; }
  }
  function topoSavePos(mac, x, y) {
    const all = topoLoadPos();
    all[mac] = { x: Math.round(x), y: Math.round(y) };
    try { localStorage.setItem(TOPO_POS_KEY, JSON.stringify(all)); } catch (err) { /* quota */ }
    if (topoResetBtn) topoResetBtn.disabled = false;
  }
  function topoHasSavedPos() { return Object.keys(topoLoadPos()).length > 0; }
  function topoResetPos() {
    localStorage.removeItem(TOPO_POS_KEY);
    renderTopologyTab();
  }

  /* drag a device card to rearrange the graph; edges follow live and the
     position sticks (localStorage, per session). A real drag suppresses the
     click so it doesn't also change the selection. */
  function topoMakeDraggable(el, n) {
    el.addEventListener('pointerdown', (ev) => {
      if (ev.button !== 0 || ev.target.closest('button')) return;
      const startX = ev.clientX, startY = ev.clientY;
      const origL = el.offsetLeft, origT = el.offsetTop;
      let moved = false, raf = 0;
      const edges = topoModel ? buildTopoEdges(topoModel) : [];
      const redraw = () => {
        raf = 0;
        if (topoGraphEl && topoNodeEls) drawTopoEdges(topoGraphEl, topoNodeEls, edges);
      };
      const move = (e2) => {
        const dx = e2.clientX - startX, dy = e2.clientY - startY;
        if (!moved && Math.hypot(dx, dy) < 5) return;   /* click tolerance */
        moved = true;
        el.classList.add('is-dragging');
        el.style.left = Math.max(0, origL + dx) + 'px';
        el.style.top = Math.max(0, origT + dy) + 'px';
        if (!raf) raf = requestAnimationFrame(redraw);
      };
      const up = () => {
        window.removeEventListener('pointermove', move);
        window.removeEventListener('pointerup', up);
        if (!moved) return;
        el.classList.remove('is-dragging');
        el._dragged = true;   /* consumed by the click handler */
        topoSavePos(n.mac, el.offsetLeft, el.offsetTop);
        if (raf) cancelAnimationFrame(raf);
        redraw();
      };
      window.addEventListener('pointermove', move);
      window.addEventListener('pointerup', up);
    });
  }

  /* Selection-only update: the graph layout never depends on selection, so a
     click just re-highlights the nodes/ports and swaps the machines panel —
     no full rebuild or edge re-measure (which flickered on every click).
     Returns false if the cached render is stale so the caller does a full one. */
  function updateTopoSelection() {
    if (!topoModel || !topoNodeEls || !topoPanelHost || !topoModel.devices.has(topoSelMac)) return false;
    const selNode = topoModel.devices.get(topoSelMac);
    if (topoSelPort && !(selNode.ports || []).some((p) => p.port === topoSelPort)) topoSelPort = null;
    for (const [mac, el] of topoNodeEls) {
      el.classList.toggle('is-selected', mac === topoSelMac);
      el.querySelectorAll('.topo-port').forEach((chip) =>
        chip.classList.toggle('is-selected', mac === topoSelMac && chip.dataset.port === topoSelPort));
    }
    topoPanelHost.replaceChildren(topoMachinesPanel(selNode));
    return true;
  }

  function topoNodeEl(n) {
    const selected = n.mac === topoSelMac;
    const portChips = (n.ports || []).map((p) => {
      const pn = p.port_number != null ? p.port_number : (String(p.port || '').split(':')[1] || '?');
      const chip = h('button', {
        class: 'topo-port' + (selected && topoSelPort === p.port ? ' is-selected' : ''),
        type: 'button', dataset: { port: p.port || '' },
        title: 'gPTP port ' + (p.port || '') + ' · ' + (p.role || 'UNKNOWN') + ' · ' + (p.as_capable || ''),
      }, 'port ' + pn + ' ', h('span', { class: 'tp-role' }, (p.role || '').slice(0, 3) || '—'));
      chip.addEventListener('click', (ev) => { ev.stopPropagation(); selectTopoPort(n.mac, p.port); });
      return chip;
    });
    const el = h('div', {
      class: 'topo-node' + (selected ? ' is-selected' : ''),
      dataset: { mac: n.mac }, role: 'button', tabindex: '0',
      title: n.label + ' — ' + (n.synthetic ? 'inferred bridge' : n.mac) + ' · drag to reposition',
    },
      h('div', { class: 'topo-node-name' }, n.label),
      h('div', { class: 'topo-node-mac mono' }, n.synthetic ? 'inferred' : n.mac),
      topoRoleBadges(n),
      (n.protocols || []).length
        ? h('div', { class: 'topo-protos' }, n.protocols.map((p) => h('span', { class: 'badge ' + protoClass(p) }, p)))
        : null,
      portChips.length ? h('div', { class: 'topo-ports' }, portChips) : null,
    );
    el.addEventListener('click', () => {
      if (el._dragged) { el._dragged = false; return; }   /* drop, not a select */
      selectTopoNode(n.mac);
    });
    el.addEventListener('keydown', (ev) => {
      if (ev.key === 'Enter' || ev.key === ' ') { ev.preventDefault(); selectTopoNode(n.mac); }
    });
    topoMakeDraggable(el, n);
    return el;
  }

  /* one gPTP port's MD Pdelay machines (initiator + responder, reusing
     drawMachine) + sync state as a badge + the port's transition history */
  function topoPortCard(p, idx) {
    const md = p.md || {};
    const def = Object.assign({}, GPTP_MD_PDELAY_REQ_MACHINE, {
      svgId: idx === 0 ? 'topo-machine-gptp-md' : 'topo-machine-gptp-md-' + idx,
      title: 'gPTP port ' + (p.port || '') + ' — MD Pdelay',
      subtitle: '802.1AS-2020 Clause ' + (md.clause || '11') + ' — MDPdelayReq (initiator)',
    });
    /* p.history holds role/asCapable transitions — a different state space from
       MDPdelayReq — so it must NOT drive this machine's overlay. Only the live
       pdelay_req_state is authoritative; show it, and no phantom visited path.
       (The role/asCapable history is shown below, correctly labelled.) */
    const live = {
      current: md.pdelay_req_state || null,
      history: [],
      visited: new Set(md.pdelay_req_state ? [md.pdelay_req_state] : []),
    };
    const scroll = h('div', { class: 'sm-scroll' });
    drawMachine(scroll, def, live);
    /* the responder side (Figure 11-10): this port answering the peer's
       Pdelay_Req — dim when this port never responded on the wire */
    const respDef = Object.assign({}, GPTP_MD_PDELAY_RESP_MACHINE, {
      svgId: (idx === 0 ? 'topo-machine-gptp-md-resp' : 'topo-machine-gptp-md-resp-' + idx),
    });
    const respLive = {
      current: md.pdelay_resp_state || null,
      history: [],
      visited: new Set(md.pdelay_resp_state ? [md.pdelay_resp_state] : []),
    };
    const respScroll = h('div', { class: 'sm-scroll' });
    drawMachine(respScroll, respDef, respLive);
    const kv = (k, badge) => h('span', { class: 'kv' }, h('span', { class: 'kv-k' }, k + ' '), badge);
    /* role and asCapable are reconstructed transitions → shown as of the cursor */
    const roleT = portFieldAt(p, GPTP_ROLE_ONLY, p.role || 'UNKNOWN');
    const ascapT = portFieldAt(p, GPTP_ASCAP_ONLY, p.as_capable || 'UNKNOWN');
    const pd = p.pdelay || {};
    const card = h('div', { class: 'machine-card' + (topoSelPort === p.port ? ' is-focus' : '') },
      h('div', { class: 'machine-head' },
        h('span', { class: 'machine-title' }, def.title),
        h('span', { class: 'machine-sub dim small' }, def.subtitle)),
      h('div', { class: 'topo-badges' },
        stateBadge(roleT),
        stateBadge(ascapT, true),
        (md.sync_send_state && md.sync_send_state !== 'NOT_ENABLED') ? kv('MDSyncSend', stateBadge(md.sync_send_state, true)) : null,
        (typeof pd.initiated === 'number' && pd.initiated > 0)
          ? h('span', { class: 'sbadge sm ' + (pd.lost > 0 ? 'st-warn' : 'st-good') },
              'pdelay ' + pd.complete + '/' + pd.initiated + ' answered'
              + (pd.lost ? ' · ' + pd.lost + ' lost' : '')) : null),
      scroll,
      h('div', { class: 'machine-note mn-live' },
        'MDPdelayReq free-runs (~1/s) with no per-cycle history — shown at its final observed position; the port role / asCapable above track the cursor.'),
      h('div', { class: 'machine-subhead' },
        h('span', { class: 'machine-title' }, respDef.title),
        h('span', { class: 'machine-sub dim small' }, respDef.subtitle)),
      respScroll,
      h('div', { class: 'machine-note' }, respDef.note),
      (Array.isArray(p.history) && p.history.length)
        ? h('div', { class: 'dim small mt4' }, 'port role / asCapable transitions') : null,
      historyBlock(p.history),
      h('div', { class: 'machine-note' }, def.note),
    );
    return foldableCard(card, 'topo-port:' + (p.port || idx));
  }

  /* ── network-wide state machines (always shown, independent of selection) ──
     gPTP domain grandmaster, MSRP SR domain, MAAP address claims. Time-indexed
     to the cursor like everything else. */
  const GPTP_GM_STATES = new Set(['NO_GM', 'GM_PRESENT', 'GM_TIMED_OUT']);
  function domainGmLive(d, T) {
    /* domain history mixes GM-lifecycle and SYNC_* transitions; keep only GM */
    const hist = (d.history || []).filter((t) =>
      GPTP_GM_STATES.has(t.to) || GPTP_GM_STATES.has(t.from));
    const r = liveAtN(hist, d.state || 'NO_GM', T == null ? curTs() : T);
    r.fullHistory = hist;
    return r;
  }
  function domainSyncAt(d, T) {
    const rel = (d.history || []).filter((t) =>
      String(t.to).indexOf('SYNC_') === 0 || String(t.from).indexOf('SYNC_') === 0);
    const cur = liveAtN(rel, 'SYNC_' + (d.sync || 'UNKNOWN'), T == null ? curTs() : T).current
      || ('SYNC_' + (d.sync || 'UNKNOWN'));
    return String(cur).replace('SYNC_', '');
  }
  function maapLive(m, T) {
    const r = liveAtN(m.history, m.state || 'UNKNOWN', T == null ? curTs() : T);
    r.fullHistory = m.history || [];
    return r;
  }

  function msrpDomainCard() {
    const st = S.stateData || {};
    const srDomains = st.domains || [];
    const reservations = st.reservations || [];
    const domChips = srDomains.map((d) => h('span', { class: 'sbadge st-neutral sm' },
      'SR class ' + d.class_id + ' · prio ' + d.priority + ' · VID ' + d.vid));
    const resRows = reservations.map((r) => {
      const rstate = liveAtN(r.history, r.state, curTs()).current || r.state || 'PENDING';
      const sy = r.gptp_sync;
      return h('div', { class: 'topo-res-row' },
        stateBadge(rstate, true),
        h('span', { class: 'mono small' }, shortStream(r.stream_id) || String(r.stream_id || '')),
        h('span', { class: 'dim small' }, (r.listeners || []).length + ' listener'
          + ((r.listeners || []).length === 1 ? '' : 's')),
        sy ? h('span', {
          class: 'sbadge sm ' + (sy === 'HEALTHY' ? 'st-good' : sy === 'LOST' ? 'st-warn' : 'st-neutral'),
        }, 'gPTP ' + sy) : null);
    });
    const card = h('div', { class: 'machine-card' },
      h('div', { class: 'machine-head' },
        h('span', { class: 'machine-title' }, 'MSRP — SR domain & reservations'),
        h('span', { class: 'machine-sub dim small' }, 'IEEE 802.1Q SRP — stream reservation domain (network-wide)')),
      domChips.length ? h('div', { class: 'topo-badges' }, domChips)
        : h('div', { class: 'dim small' }, 'no SR class domain declared'),
      resRows.length ? h('div', { class: 'topo-res-list' }, resRows)
        : h('div', { class: 'dim small mt4' }, 'no reservations observed'),
      h('div', { class: 'machine-note' },
        'The talker→listener paths are the graph’s stream edges above; this is their SRP domain and per-stream status (as of the cursor).'));
    return foldableCard(card, 'net-msrp');
  }

  function topoNetworkPanel() {
    const st = S.stateData || {};
    const gptp = st.gptp || {};
    const gptpCards = [], msrpCards = [], maapCards = [];

    (gptp.domains || []).forEach((d, i) => {
      const def = Object.assign({}, GPTP_DOMAIN_MACHINE,
        { svgId: i === 0 ? 'topo-net-gptp-domain' : 'topo-net-gptp-domain-' + i });
      const card = machineCard(def, domainGmLive(d), null);
      const gm = d.grandmaster || {};
      const sy = domainSyncAt(d) || 'UNKNOWN';
      const info = h('div', { class: 'topo-badges' },
        h('span', {
          class: 'sbadge sm ' + (sy === 'HEALTHY' ? 'st-good' : sy === 'LOST' ? 'st-warn' : 'st-neutral'),
        }, 'sync ' + sy),
        h('span', { class: 'kv' }, h('span', { class: 'kv-k' }, 'domain '), h('span', { class: 'mono' }, String(d.domain))),
        h('span', { class: 'kv' }, h('span', { class: 'kv-k' }, 'GM '),
          h('span', { class: 'mono' }, gm.name || gm.clock_identity || '—')),
        (gm.priority1 != null && gm.clock_identity)
          ? h('span', { class: 'kv' }, h('span', { class: 'kv-k' }, 'prio1 '), h('span', { class: 'mono' }, String(gm.priority1))) : null,
        d.bmca ? h('span', { class: 'sbadge st-neutral sm' }, 'BMCA ' + d.bmca) : null);
      card.insertBefore(info, card.querySelector('.sm-scroll'));
      gptpCards.push(card);
    });

    if ((st.domains || []).length || (st.reservations || []).length) msrpCards.push(msrpDomainCard());

    (st.maap || []).forEach((m, i) => {
      const def = Object.assign({}, MAAP_MACHINE,
        { svgId: i === 0 ? 'topo-net-maap' : 'topo-net-maap-' + i });
      const card = machineCard(def, maapLive(m), null);
      const head = card.querySelector('.machine-head');
      const end = (typeof m.count === 'number' && m.count > 0) ? macAdd(m.range_start, m.count - 1) : null;
      if (head) head.appendChild(h('span', { class: 'machine-sub dim small' },
        m.claimant + ' · ', h('span', { class: 'mono' },
          m.range_start + (end && end !== m.range_start ? ' … ' + end : '') + ' (×' + m.count + ')')));
      maapCards.push(card);
    });

    const groups = [
      protoGroup('gPTP (802.1AS) — domain', 'GPTP', gptpCards, 'net-gptp'),
      protoGroup('MSRP (802.1Q SRP)', 'MSRP', msrpCards, 'net-msrp-grp'),
      protoGroup('MAAP (1722)', 'MAAP', maapCards, 'net-maap'),
    ].filter(Boolean);

    return h('div', { class: 'topo-net' },
      h('div', { class: 'topo-net-head' },
        h('span', { class: 'machine-title' }, 'Network state machines'),
        h('span', { class: 'dim small' }, 'fabric-wide — always shown, independent of the selected device '),
        h('span', { class: 'toolbar-spacer' }), asOfBadge()),
      machineLegend(),
      groups.length ? groups
        : h('div', { class: 'empty small' }, 'No network-wide protocol state observed yet (gPTP / MSRP / MAAP).'));
  }

  /* ACMP endpoint as ENTITY_ID(NAME):STREAM_UNIQUE_ID (name only when known) */
  function acmpEndpoint(entityId, uid) {
    if (!entityId || isZeroId(entityId)) return h('span', { class: 'acmp-ep dim' }, '— (unbound)');
    const name = entityName(entityId);
    return h('span', { class: 'acmp-ep' },
      h('span', { class: 'mono acmp-ep-id' }, entityId),
      name ? h('span', { class: 'acmp-ep-name' }, '(' + name + ')') : null,
      h('span', { class: 'mono acmp-ep-uid' }, ':' + (uid != null ? uid : '?')));
  }

  /* AECP has no tap-observable state machine — the transaction log IS its
     state: one card per controller↔target pair this device participates in */
  function aecpPairCard(a, role, i) {
    const rows = (a.last || []).map((cmd) => h('div', { class: 'aecp-row' },
      h('span', { class: 'mono dim' }, 'seq ' + cmd.sequence_id),
      h('span', { class: 'mono' }, cmd.command),
      stateBadge(cmd.status, true),
      h('span', { class: 'mono dim' },
        typeof cmd.rtt_ms === 'number' ? cmd.rtt_ms.toFixed(1) + ' ms' : '')));
    const card = h('div', { class: 'machine-card' },
      h('div', { class: 'machine-head' },
        h('span', { class: 'machine-title' }, 'AECP transactions — as ' + role),
        h('span', { class: 'machine-sub dim small' },
          entityLabel(a.controller), ' → ', entityLabel(a.target))),
      h('div', { class: 'topo-badges' },
        h('span', { class: 'kv' }, h('span', { class: 'kv-k' }, 'commands '),
          h('span', { class: 'mono' }, String(a.commands || 0))),
        h('span', { class: 'kv' }, h('span', { class: 'kv-k' }, 'responses '),
          h('span', { class: 'mono' }, String(a.responses || 0))),
        a.timeouts > 0 ? h('span', { class: 'sbadge st-warn sm' }, a.timeouts + ' timeouts') : null,
        a.unsolicited > 0 ? h('span', { class: 'sbadge st-neutral sm' }, a.unsolicited + ' unsolicited') : null),
      rows.length ? h('div', { class: 'aecp-last' }, rows) : null);
    return foldableCard(card, 'dev-aecp-' + i);
  }

  function kvBadge(k, badge) {
    return h('span', { class: 'kv' }, h('span', { class: 'kv-k' }, k + ' '), badge);
  }

  /* ENTITY_ID(NAME):STREAM_UNIQUE_ID for the talker source and listener sink,
     plus the StreamID — shown in the card header so it stays visible folded */
  function acmpEpsBlock(s) {
    return h('div', { class: 'acmp-eps' },
      h('span', { class: 'acmp-ep-row' }, h('span', { class: 'acmp-ep-k' }, 'Talker '),
        acmpEndpoint(s.bound_talker, s.bound_talker_unique_id)),
      h('span', { class: 'acmp-ep-row' }, h('span', { class: 'acmp-ep-k' }, 'Listener '),
        acmpEndpoint(s.listener_entity, s.listener_unique_id)),
      (s.stream_id && !isZeroId(s.stream_id))
        ? h('span', { class: 'acmp-ep-row' }, h('span', { class: 'acmp-ep-k' }, 'StreamID '),
            h('span', { class: 'mono acmp-ep-id' }, s.stream_id)) : null);
  }

  /* every reconstructed machine for one device, bound to its live data.
     opts.win: rendered inside a floating window — show all ports (ignore the
     inline port focus) and omit the "open in window" button. */
  function topoMachinesPanel(n, opts) {
    opts = opts || {};
    const adp = [], gptpC = [], acmp = [], mrp = [], aecpC = [];
    /* all entity ids this MAC is proven to own (advertised + associated) */
    const nodeIds = new Set([n.entity_id].concat(n.assocIds || [])
      .map(tnorm).filter((x) => x && !isZeroId(x)));
    ((S.stateData || {}).aecp || []).forEach((a, i) => {
      const asCtl = nodeIds.has(tnorm(a.controller));
      if (!asCtl && !nodeIds.has(tnorm(a.target))) return;
      aecpC.push(aecpPairCard(a, asCtl ? 'controller' : 'target', i));
    });
    if (n.entity) {
      const def = Object.assign({}, ADP_ENTITY_MACHINE, { svgId: 'topo-machine-entity' });
      adp.push(machineCard(def, entityLive(n.entity), null));
      /* the internal PAAD advertise machine (reference, tinted while available) */
      adp.push(machineCard(Object.assign({}, ADP_ADVERTISE_MACHINE, { svgId: 'topo-machine-adp-advertise' }),
        advertiseLive(n.entity), null));
    }
    let ports = n.ports || [];
    const selPort = opts.win ? null : topoSelPort;
    if (selPort) ports = ports.filter((p) => p.port === selPort);   /* focus one */
    ports.forEach((p, i) => gptpC.push(topoPortCard(p, selPort ? 0 : i)));
    (n.milanSinks || []).forEach((s, i) => {
      const def = Object.assign({}, ACMP_MACHINE, { svgId: i === 0 ? 'topo-machine-acmp' : 'topo-machine-acmp-' + i });
      const card = machineCard(def, sinkLive(s), null);
      const head = card.querySelector('.machine-head');
      if (head) head.appendChild(acmpEpsBlock(s));
      acmp.push(card);
      /* talker-discovery machine for this bound sink */
      adp.push(machineCard(Object.assign({}, ADP_DISCOVERY_MACHINE,
        { svgId: i === 0 ? 'topo-machine-adp-discovery' : 'topo-machine-adp-discovery-' + i }),
        discoveryLive(s), null));
    });
    /* this device's talker sources: the Milan stateless-talker card, with
       probe/response counters and the SRP declaration state */
    (n.milanTalkers || []).forEach((t, i) => {
      const def = Object.assign({}, MILAN_TALKER_MACHINE, { svgId: 'topo-machine-acmp-talker-' + i });
      const card = machineCard(def, talkerLive(t), null);
      const head = card.querySelector('.machine-head');
      if (head) {
        head.appendChild(h('div', { class: 'acmp-eps' },
          h('span', { class: 'acmp-ep-row' }, h('span', { class: 'acmp-ep-k' }, 'Talker '),
            acmpEndpoint(t.talker_entity, t.talker_unique_id)),
          (t.stream_id && !isZeroId(t.stream_id))
            ? h('span', { class: 'acmp-ep-row' }, h('span', { class: 'acmp-ep-k' }, 'StreamID '),
                h('span', { class: 'mono acmp-ep-id' }, t.stream_id)) : null));
        head.appendChild(h('div', { class: 'topo-badges' },
          h('span', { class: 'kv' }, h('span', { class: 'kv-k' }, 'probes '),
            h('span', { class: 'mono' }, String(t.probes_received || 0))),
          h('span', { class: 'kv' }, h('span', { class: 'kv-k' }, 'responses '),
            h('span', { class: 'mono' }, String(t.probe_responses || 0))),
          t.disconnect_tx_seen ? h('span', { class: 'kv' }, h('span', { class: 'kv-k' }, 'disconnects '),
            h('span', { class: 'mono' }, String(t.disconnect_tx_seen))) : null,
          t.last_status ? kvBadge('last status', stateBadge(t.last_status, true)) : null,
          t.srp_declaration && t.srp_declaration !== 'NONE'
            ? kvBadge('SRP', stateBadge(t.srp_declaration, true)) : null));
      }
      acmp.push(card);
    });
    /* the IEEE 1722.1 connection machine for each stream this device is an
       endpoint of (talker or listener side) */
    (n.connections || []).forEach((c, i) => {
      const def = Object.assign({}, ACMP_CONNECTION_MACHINE, { svgId: 'topo-machine-acmp-conn-' + i });
      const card = machineCard(def, connLive(c), null);
      const head = card.querySelector('.machine-head');
      if (head) head.appendChild(h('div', { class: 'acmp-eps' },
        h('span', { class: 'acmp-ep-row' }, h('span', { class: 'acmp-ep-k' }, 'Talker '),
          acmpEndpoint(c.talker_entity, c.talker_unique_id)),
        h('span', { class: 'acmp-ep-row' }, h('span', { class: 'acmp-ep-k' }, 'Listener '),
          acmpEndpoint(c.listener_entity, c.listener_unique_id)),
        (c.controller_entity && !isZeroId(c.controller_entity))
          ? h('span', { class: 'acmp-ep-row' }, h('span', { class: 'acmp-ep-k' }, 'Controller '),
              entityLabel(c.controller_entity)) : null,
        (c.stream_id && !isZeroId(c.stream_id))
          ? h('span', { class: 'acmp-ep-row' }, h('span', { class: 'acmp-ep-k' }, 'StreamID '),
              h('span', { class: 'mono acmp-ep-id' }, c.stream_id)) : null));
      acmp.push(card);
    });
    /* sink machines of streams this device TALKS into (the machine itself
       lives in the remote listener — Milan talkers are stateless) */
    (n.talkerSinks || []).forEach((s, i) => {
      const def = Object.assign({}, ACMP_MACHINE, { svgId: 'topo-machine-acmp-tlk-' + i });
      const card = machineCard(def, sinkLive(s), null);
      const head = card.querySelector('.machine-head');
      if (head) {
        head.appendChild(h('span', { class: 'machine-sub dim small' },
          'remote listener’s sink — this device is the talker'));
        head.appendChild(acmpEpsBlock(s));
      }
      acmp.push(card);
    });
    (n.mrp || []).forEach((m, i) => {
      const def = Object.assign({}, MRP_REGISTRAR_MACHINE, {
        svgId: i === 0 ? 'topo-machine-mrp-registrar' : 'topo-machine-mrp-registrar-' + i,
        accent: PROTO_COLORS[m.proto] || PROTO_COLORS.MSRP,
      });
      const log = m.log || [];
      const liveAt = mrpLiveAt(m, mrpStepForTs(log, curTs()));   /* as of the cursor */
      const card = machineCard(def, liveAt, null);
      const head = card.querySelector('.machine-head');
      if (head) head.appendChild(h('span', { class: 'machine-sub dim small' },
        mrpAttrLabel(m) + ' — registrar ', mrpStateBadge(liveAt.current || 'MT', true)));
      mrp.push(card);
    });
    /* the 802.1Q MRP Applicant reference (sender-internal, not tap-observable) */
    if ((n.mrp || []).length) {
      const applCard = machineCard(Object.assign({}, MRP_APPLICANT_MACHINE, { svgId: 'topo-machine-mrp-applicant' }), {}, null);
      const body = applCard.querySelector('.sm-scroll');
      if (body) body.after(mrpApplicantEvents());
      mrp.push(applCard);
    }
    const groups = [
      protoGroup('ATDECC — ADP', 'ADP', adp, 'dev-adp'),
      protoGroup('gPTP (802.1AS)', 'GPTP', gptpC, 'dev-gptp'),
      protoGroup('ATDECC — ACMP', 'ACMP', acmp, 'dev-acmp'),
      protoGroup('ATDECC — AECP', 'AECP', aecpC, 'dev-aecp'),
      protoGroup('MRP (802.1Q)', 'MSRP', mrp, 'dev-mrp'),
    ].filter(Boolean);
    const winBtn = opts.win ? null : h('button', {
      class: 'btn btn-ghost btn-sm', type: 'button',
      title: 'open this device’s state machines in a floating window (keeps tracking the timeline cursor)',
      onclick: () => openMachineWindow(n.mac),
    }, '⧉ window');
    const head = h('div', { class: 'topo-panel-head' },
      h('span', { class: 'machine-title' }, n.label),
      h('span', { class: 'mono dim small' }, n.synthetic ? 'inferred bridge' : n.mac),
      topoRoleBadges(n),
      selPort ? h('span', { class: 'sbadge st-neutral sm' }, 'port ' + selPort) : null,
      h('span', { class: 'toolbar-spacer' }), winBtn, asOfBadge());
    return h('div', { class: 'topo-panel' }, head, machineLegend(),
      groups.length ? groups : h('div', { class: 'empty small' },
        'No reconstructed state machines for this device'
        + (n.packets ? ' (' + fmtInt(n.packets) + ' packets observed).' : '.')));
  }

  /* ── per-device machine windows (real browser popups) ─────────────────
     Each device opens in its own browser window (window.open, same origin,
     sharing this page's stylesheet). The opener owns the rendering: every
     cursor move re-renders each popup's panel (renderMachineWins is called
     from selectEvent / clearSelection / loadState / loadInfo), so the
     machines keep tracking the timeline wherever the windows sit. */
  const machineWins = new Map();   /* mac -> { win, body } */

  function openMachineWindow(mac) {
    const existing = machineWins.get(mac);
    if (existing && existing.win && !existing.win.closed) { existing.win.focus(); return; }
    if (existing) machineWins.delete(mac);
    const idx = machineWins.size;
    const w = window.open('', 'avb-mwin-' + id + '-' + mac.replace(/[^a-z0-9]/gi, ''),
      'popup=yes,width=720,height=820,left=' + (90 + idx * 44) + ',top=' + (60 + idx * 44));
    if (!w) {
      toast('popup blocked — allow popups for this site to open machine windows', 'error');
      return;
    }
    const doc = w.document;
    doc.head.replaceChildren();
    const meta = doc.createElement('meta');
    meta.setAttribute('charset', 'utf-8');
    doc.head.appendChild(meta);
    /* same-origin stylesheet: the popup renders with the app's exact look */
    const link = doc.createElement('link');
    link.rel = 'stylesheet';
    link.href = new URL((BASE || '') + '/style.css', location.href).href;
    doc.head.appendChild(link);
    doc.body.className = 'mwin-doc';
    doc.body.replaceChildren();
    const body = doc.createElement('div');
    body.className = 'mwin-body';
    doc.body.appendChild(body);
    w.addEventListener('pagehide', () => {
      const e = machineWins.get(mac);
      if (e && e.win === w) machineWins.delete(mac);
    });
    machineWins.set(mac, { win: w, body });
    renderMachineWins();
  }

  function closeMachineWins() {
    for (const [, wm] of machineWins) { try { wm.win.close(); } catch (err) { /* gone */ } }
    machineWins.clear();
  }
  /* popups don't die with the tab on their own */
  window.addEventListener('pagehide', closeMachineWins);

  /* re-render every open popup to the cursor, preserving its scroll */
  function renderMachineWins() {
    if (!machineWins.size) return;
    for (const [mac, wm] of [...machineWins]) {
      if (!wm.win || wm.win.closed) machineWins.delete(mac);
    }
    if (!machineWins.size || !S.stateData || !S.infoData) return;
    const model = buildTopologyModel();
    for (const [mac, wm] of machineWins) {
      const n = model.devices.get(mac);
      try {
        wm.win.document.title = ((n && n.label) || mac) + ' — state machines';
        const y = wm.win.scrollY || 0;
        wm.body.replaceChildren(n ? topoMachinesPanel(n, { win: true })
          : h('div', { class: 'empty small' }, 'Device ' + mac + ' not observed.'));
        wm.win.scrollTo(0, y);
      } catch (err) { machineWins.delete(mac); }
    }
  }

  function topoMarker(idv, fill) {
    return svg('marker', {
      id: idv, viewBox: '0 0 10 10', refX: 8.5, refY: 5,
      markerWidth: 8, markerHeight: 8, orient: 'auto', markerUnits: 'userSpaceOnUse',
    }, svg('path', { d: 'M0,0 L10,5 L0,10 z', fill }));
  }

  /* border-intersection point of a box toward (tx,ty) — where the arrow meets */
  function topoBorderPt(box, tx, ty) {
    const dx = tx - box.cx, dy = ty - box.cy;
    if (dx === 0 && dy === 0) return { x: box.cx, y: box.cy };
    const sx = dx !== 0 ? (box.w / 2) / Math.abs(dx) : Infinity;
    const sy = dy !== 0 ? (box.h / 2) / Math.abs(dy) : Infinity;
    const s = Math.min(sx, sy);
    return { x: box.cx + dx * s, y: box.cy + dy * s };
  }

  /* measure the laid-out cards, size the graph, then draw the edge SVG behind
     them (pointer-events:none so the cards stay clickable) */
  function drawTopoEdges(graph, nodeEls, edges) {
    const prior = graph.querySelector('svg.topo-svg');   /* re-callable on scrub */
    if (prior) prior.remove();
    const boxes = new Map();
    let maxR = 0, maxB = 0;
    for (const [mac, el] of nodeEls) {
      const b = { x: el.offsetLeft, y: el.offsetTop, w: el.offsetWidth, h: el.offsetHeight };
      b.cx = b.x + b.w / 2; b.cy = b.y + b.h / 2;
      boxes.set(mac, b);
      maxR = Math.max(maxR, b.x + b.w); maxB = Math.max(maxB, b.y + b.h);
    }
    const W = Math.ceil(maxR + TOPO_PAD), H = Math.ceil(maxB + TOPO_PAD);
    graph.style.width = W + 'px';
    graph.style.height = H + 'px';
    const svgEl = svg('svg', { class: 'topo-svg', width: W, height: H, viewBox: '0 0 ' + W + ' ' + H });
    svgEl.appendChild(svg('defs', null,
      topoMarker('topo-arr-sync', PROTO_COLORS.GPTP),
      topoMarker('topo-arr-stream', PROTO_COLORS.ACMP)));
    for (const e of edges) {
      const A = boxes.get(e.from), B = boxes.get(e.to);
      if (!A || !B) continue;
      const a = topoBorderPt(A, B.cx, B.cy);
      const b = topoBorderPt(B, A.cx, A.cy);
      const mx = (a.x + b.x) / 2, my = (a.y + b.y) / 2;
      const dx = b.x - a.x, dy = b.y - a.y, len = Math.hypot(dx, dy) || 1;
      /* bow streams/bindings off any sync line (and off each other) */
      const off = e.kind === 'stream' ? 18 : e.kind === 'binding' ? 32 : 0;
      const cx = mx - dy / len * off, cy = my + dx / len * off;
      const cls = e.kind === 'sync' ? 'is-sync' : e.kind === 'binding' ? 'is-binding' : 'is-stream';
      svgEl.appendChild(svg('path', {
        class: 'topo-edge ' + cls,
        d: 'M ' + a.x + ' ' + a.y + ' Q ' + cx + ' ' + cy + ' ' + b.x + ' ' + b.y,
        'marker-end': 'url(#' + (e.kind === 'sync' ? 'topo-arr-sync' : 'topo-arr-stream') + ')',
      }));
      if (e.label) {
        const lx = off ? cx : mx, ly = off ? cy : my;
        const txt = String(e.label);
        const w = txt.length * 5.6 + 8;
        svgEl.appendChild(svg('rect', {
          class: 'topo-elabel-bg', x: lx - w / 2, y: ly - 7, width: w, height: 14, rx: 3,
        }));
        svgEl.appendChild(svg('text', {
          class: 'topo-elabel ' + cls,
          x: lx, y: ly, 'text-anchor': 'middle', 'dominant-baseline': 'middle',
        }, txt));
      }
    }
    graph.insertBefore(svgEl, graph.firstChild);
  }

  function topoLegend() {
    return h('div', { class: 'topo-legend' },
      h('span', { class: 'tl-item' }, h('span', { class: 'tl-line tl-sync' }), 'gPTP sync (master → slave)'),
      h('span', { class: 'tl-item' }, h('span', { class: 'tl-line tl-stream' }), 'stream (talker → listener)'),
      h('span', { class: 'tl-item' }, h('span', { class: 'tl-line tl-binding' }), 'ACMP binding (bound, no stream)'),
      h('span', { class: 'tl-item dim' }, 'drag a device card to rearrange'));
  }

  function renderTopologyTab() {
    if (!S.stateData || !S.infoData) {
      inspBody.replaceChildren(placeholder(
        (S.stateData || S.infoData || S.stateLoading || S.infoLoading)
          ? 'Loading topology…' : 'Topology not loaded yet.'));
      if (!S.stateData && !S.stateLoading) loadState();
      if (!S.infoData && !S.infoLoading) loadInfo();
      return;
    }
    const model = buildTopologyModel();
    topoModel = model;
    const nodes = [...model.devices.values()];

    if (!nodes.length) {
      inspBody.replaceChildren(h('div', { class: 'insp-scroll' },
        h('div', { class: 'state-actions' },
          h('span', { class: 'dim small' }, 'Observed network topology'),
          h('span', { class: 'toolbar-spacer' })),
        h('div', { class: 'empty' }, 'No devices observed yet.')));
      return;
    }

    if (!topoSelMac || !model.devices.has(topoSelMac)) {
      const gm = nodes.find((n) => n.roles.has('GM')) || nodes[0];
      topoSelMac = gm.mac; topoSelPort = null;
    }
    const selNode = model.devices.get(topoSelMac);
    if (topoSelPort && !(selNode.ports || []).some((p) => p.port === topoSelPort)) topoSelPort = null;

    /* layered layout: GM/master top, bridges, slaves, then non-gPTP others.
       Unused tiers collapse so rows stay adjacent. */
    const tierOf = (n) => (n.roles.has('GM') || n.roles.has('MASTER')) ? 0
      : n.roles.has('Bridge') ? 1 : n.roles.has('SLAVE') ? 2 : 3;
    const byTier = new Map();
    for (const n of nodes) {
      const t = tierOf(n);
      if (!byTier.has(t)) byTier.set(t, []);
      byTier.get(t).push(n);
    }
    const rows = [...byTier.keys()].sort((a, b) => a - b).map((t) => byTier.get(t));
    rows.forEach((row, r) => row.forEach((n, c) => {
      n._x = TOPO_PAD + c * TOPO_DX;
      n._y = TOPO_PAD + r * TOPO_DY;
    }));
    /* user-arranged positions win over the automatic tier layout */
    const savedPos = topoLoadPos();
    for (const n of nodes) {
      const p = savedPos[n.mac];
      if (p && typeof p.x === 'number' && typeof p.y === 'number') {
        n._x = Math.max(0, p.x);
        n._y = Math.max(0, p.y);
      }
    }

    const graph = h('div', { class: 'topo-graph' });
    const nodeEls = new Map();
    for (const n of nodes) {
      const el = topoNodeEl(n);
      el.style.left = n._x + 'px';
      el.style.top = n._y + 'px';
      el.style.width = TOPO_CARD_W + 'px';
      graph.appendChild(el);
      nodeEls.set(n.mac, el);
    }
    topoNodeEls = nodeEls;
    topoGraphEl = graph;
    const panelHost = h('div', { class: 'topo-panel-host' }, topoMachinesPanel(selNode));
    topoPanelHost = panelHost;
    const netHost = h('div', { class: 'topo-net-host' }, topoNetworkPanel());
    topoNetHost = netHost;

    const asofSlot = h('span', { class: 'topo-asof-slot' }, asOfBadge());
    topoAsofSlot = asofSlot;
    const resetBtn = h('button', {
      class: 'btn btn-ghost btn-sm', type: 'button',
      title: 'discard the manual node arrangement and go back to the automatic layout',
      onclick: topoResetPos,
    }, 'Reset layout');
    resetBtn.disabled = !topoHasSavedPos();
    topoResetBtn = resetBtn;   /* enabled by the first drag */
    inspBody.replaceChildren(h('div', { class: 'insp-scroll' },
      h('div', { class: 'state-actions' },
        h('span', { class: 'dim small' },
          'Observed network topology — click a device or port for its state machines; drag cards to rearrange; links show streams/sync flowing '),
        asofSlot,
        h('span', { class: 'toolbar-spacer' }),
        resetBtn),
      netHost,
      topoLegend(),
      h('div', { class: 'sm-scroll topo-scroll' }, graph),
      panelHost,
    ));

    /* cards are in the live DOM now — measure them, then draw the edges at the
       cursor's moment (positions are fixed; edges/overlays track the timeline) */
    drawTopoEdges(graph, nodeEls, buildTopoEdges(model));
  }

  /* selection unchanged, but the timeline cursor moved: keep the node layout,
     just redraw the time-varying edges and the selected device's machines. */
  function syncTopologyToCursor() {
    closeEdgePop();
    if (!topoModel || !topoNodeEls || !topoGraphEl || !topoPanelHost
        || !S.stateData || !topoModel.devices.has(topoSelMac)) { renderTopologyTab(); return; }
    if (topoAsofSlot) topoAsofSlot.replaceChildren(asOfBadge());
    if (topoNetHost) topoNetHost.replaceChildren(topoNetworkPanel());
    drawTopoEdges(topoGraphEl, topoNodeEls, buildTopoEdges(topoModel));
    topoPanelHost.replaceChildren(topoMachinesPanel(topoModel.devices.get(topoSelMac)));
  }

  /* ────────── inspector: notes tab ────────── */

  const N = {
    loaded: false, loading: false, dirty: false, saving: false, preview: false,
    rev: '',          /* revision the editor content is based on (GET/PUT) */
    conflict: null,   /* {rev, markdown} from a 409, while the banner is up */
  };

  const notesStatus = h('span', {
    id: 'notes-status', class: 'notes-status dim small', dataset: { state: 'loading' },
  }, 'loading…');
  const notesSaveBtn = h('button', {
    id: 'notes-save', class: 'btn btn-sm', type: 'button', disabled: true,
    title: 'save notes (Ctrl+S)', onclick: () => saveNotes(),
  }, 'Save');
  const notesPreviewBtn = h('button', {
    id: 'notes-preview-toggle', class: 'btn btn-ghost btn-sm', type: 'button',
    'aria-pressed': 'false', title: 'toggle markdown preview', onclick: togglePreview,
  }, 'Preview');
  const notesTa = h('textarea', {
    id: 'notes-editor', class: 'notes-editor', spellcheck: 'false', disabled: true,
    placeholder: 'Investigation notes (markdown)…',
  });
  const notesPreview = h('div', { id: 'notes-preview', class: 'notes-preview', hidden: true });
  const notesConflict = h('div', { id: 'notes-conflict', class: 'notes-conflict', hidden: true },
    h('span', { class: 'nc-msg' },
      'Someone else saved these notes while you were editing. Your text below is kept, but not saved yet.'),
    h('span', { class: 'nc-actions' },
      h('button', {
        id: 'notes-take-theirs', class: 'btn btn-sm', type: 'button',
        title: 'discard my text and load their version', onclick: takeTheirs,
      }, 'Take theirs'),
      h('button', {
        id: 'notes-overwrite', class: 'btn btn-danger btn-sm', type: 'button',
        title: 'force-save my text over their version', onclick: overwriteWithMine,
      }, 'Overwrite with mine')));
  const notesWrap = h('div', { class: 'notes-wrap' },
    h('div', { class: 'notes-toolbar' },
      notesSaveBtn, notesPreviewBtn,
      h('span', { class: 'toolbar-spacer' }),
      notesStatus),
    notesConflict, notesTa, notesPreview,
  );
  notesTa.addEventListener('input', () => {
    N.dirty = true;
    /* while the conflict banner is up the status stays "conflict" */
    if (!N.saving && !N.conflict) setNotesStatus('dirty');
  });

  function setNotesStatus(state, msg) {
    const text = {
      saved: 'saved', dirty: 'unsaved changes', saving: 'saving…',
      loading: 'loading…', conflict: 'edit conflict',
    };
    notesStatus.dataset.state = state;
    notesStatus.classList.toggle('errtext', state === 'error');
    notesStatus.textContent = state === 'error' ? (msg || 'save failed') : text[state];
  }

  function clearConflict() {
    N.conflict = null;
    notesConflict.hidden = true;
  }

  /* 409 resolution A: replace my text with the server's current revision */
  function takeTheirs() {
    if (!N.conflict) return;
    notesTa.value = N.conflict.markdown;
    N.rev = N.conflict.rev;
    clearConflict();
    N.dirty = false;
    setNotesStatus('saved');
    if (N.preview) notesPreview.innerHTML = mdToHtml(notesTa.value);
  }

  /* 409 resolution B: force-save my text (PUT without rev = last write wins) */
  async function overwriteWithMine() {
    if (!N.conflict || N.saving || S.closed) return;
    N.saving = true;
    notesSaveBtn.disabled = true;
    setNotesStatus('saving');
    const text = notesTa.value;
    try {
      const r = await api('/api/sessions/' + encodeURIComponent(id) + '/notes', {
        method: 'PUT', json: { markdown: text },
      });
      if (S.closed) return;
      if (r && typeof r.rev === 'string') N.rev = r.rev;
      clearConflict();
      N.dirty = notesTa.value !== text;     /* stay dirty if edited mid-flight */
      setNotesStatus(N.dirty ? 'dirty' : 'saved');
    } catch (err) {
      if (S.closed) return;
      setNotesStatus('error', 'save failed: ' + err.message);
    } finally {
      N.saving = false;
      notesSaveBtn.disabled = !N.loaded;
    }
  }

  function renderNotesTab() {
    if (notesWrap.parentNode !== inspBody) inspBody.replaceChildren(notesWrap);
    if (!N.loaded && !N.loading) loadNotes();
  }

  async function loadNotes() {
    if (N.loading || N.loaded || S.closed) return;
    N.loading = true;
    setNotesStatus('loading');
    try {
      const r = await api('/api/sessions/' + encodeURIComponent(id) + '/notes');
      if (S.closed) return;
      notesTa.value = (r && typeof r.markdown === 'string') ? r.markdown : '';
      N.rev = (r && typeof r.rev === 'string') ? r.rev : '';
      clearConflict();
      N.loaded = true;
      N.dirty = false;
      notesTa.disabled = false;
      notesSaveBtn.disabled = false;
      setNotesStatus('saved');
      if (N.preview) notesPreview.innerHTML = mdToHtml(notesTa.value);
    } catch (err) {
      if (!S.closed) setNotesStatus('error', 'load failed: ' + err.message);
    } finally {
      N.loading = false;
    }
  }

  async function saveNotes() {
    if (!N.loaded || N.saving || S.closed) return;
    N.saving = true;
    notesSaveBtn.disabled = true;
    setNotesStatus('saving');
    const text = notesTa.value;
    /* revision-based save: the backend 409s when someone saved in between */
    const payload = N.rev ? { markdown: text, rev: N.rev } : { markdown: text };
    try {
      const r = await api('/api/sessions/' + encodeURIComponent(id) + '/notes', {
        method: 'PUT', json: payload,
      });
      if (S.closed) return;
      if (r && typeof r.rev === 'string') N.rev = r.rev;
      clearConflict();
      N.dirty = notesTa.value !== text;     /* stay dirty if edited mid-flight */
      setNotesStatus(N.dirty ? 'dirty' : 'saved');
    } catch (err) {
      if (S.closed) return;
      if (err.status === 409 && err.body && typeof err.body.markdown === 'string') {
        /* stale rev: keep the user's text, surface the banner with theirs */
        N.conflict = { rev: err.body.rev || '', markdown: err.body.markdown };
        notesConflict.hidden = false;
        setNotesStatus('conflict');
        if (S.tab !== 'notes') toast('notes: edit conflict — someone else saved; open the Notes tab to resolve', 'error');
      } else {
        setNotesStatus('error', 'save failed: ' + err.message);
        if (S.tab !== 'notes') toast('notes save failed: ' + err.message, 'error');
      }
    } finally {
      N.saving = false;
      notesSaveBtn.disabled = !N.loaded;
    }
  }

  function togglePreview() {
    N.preview = !N.preview;
    notesPreviewBtn.setAttribute('aria-pressed', N.preview ? 'true' : 'false');
    notesPreviewBtn.classList.toggle('active', N.preview);
    if (N.preview) notesPreview.innerHTML = mdToHtml(notesTa.value);
    notesTa.hidden = N.preview;
    notesPreview.hidden = !N.preview;
    if (!N.preview && !notesTa.disabled) notesTa.focus();
  }

  /* ────────── inspector: markers tab (user annotations) ──────────
     Markers are personal bookmarks on the capture timeline. There is no
     backend endpoint for them, so they live in localStorage, keyed per
     session ("avb.markers.<id>"): [{id, ts, label, n}] with ts in seconds
     since capture start. Drawn as amber dashed verticals in the timeline. */

  const MK = { list: [] };

  function loadMarkers() {
    try {
      const raw = JSON.parse(localStorage.getItem(MARKERS_KEY_PREFIX + id) || '[]');
      MK.list = Array.isArray(raw)
        ? raw.filter((m) => m && typeof m.ts === 'number' && isFinite(m.ts) && typeof m.id === 'string')
        : [];
    } catch (err) {
      MK.list = [];
    }
    MK.list.sort((a, b) => a.ts - b.ts);
  }

  function saveMarkers() {
    try {
      localStorage.setItem(MARKERS_KEY_PREFIX + id, JSON.stringify(MK.list));
    } catch (err) { /* private mode / quota — markers stay in memory */ }
  }

  function addMarker(ts, label, n) {
    const m = {
      id: Date.now().toString(36) + Math.random().toString(36).slice(2, 7),
      ts,
      label: label || '',
      n: (typeof n === 'number' && n > 0) ? n : 0,
    };
    MK.list.push(m);
    MK.list.sort((a, b) => a.ts - b.ts);
    saveMarkers();
    tlSchedule();
    return m;
  }

  /* add at the selected event, else at the center of the visible window */
  function addMarkerHere() {
    const e = S.selected >= 0 ? S.events[S.selected] : null;
    let m;
    if (e) {
      m = addMarker(e.ts, ((e.proto || '') + ' ' + (e.type || '')).trim(), e.n);
    } else {
      const mid = Math.min(Math.max((TL.t0 + TL.t1) / 2, 0), fullSpan());
      m = addMarker(mid, '');
    }
    if (S.tab === 'markers') renderMarkersTab(m.id);
    else toast('marker added at ' + fmtTime(m.ts) + ' — see the Markers tab');
    return m;
  }

  function deleteMarker(mid) {
    MK.list = MK.list.filter((m) => m.id !== mid);
    saveMarkers();
    tlSchedule();
    if (S.tab === 'markers') renderMarkersTab();
  }

  /* pan the timeline to a time and scroll the events table to the nearest
     filtered row — without changing the selection or leaving the tab */
  function jumpToTs(ts) {
    tlCenterOn(ts);
    tlSchedule();
    const a = S.filtered;
    if (!a.length) return;
    let lo = 0, hi = a.length - 1;   /* first row with event ts >= target */
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      const e = S.events[a[mid]];
      if (e && e.ts < ts) lo = mid + 1; else hi = mid;
    }
    tableBody.scrollTop = Math.max(0, lo * ROW_H - tableBody.clientHeight / 2);
  }

  function renderMarkersTab(focusId) {
    const addBtn = h('button', {
      id: 'marker-add', class: 'btn btn-primary btn-sm', type: 'button',
      title: 'add a marker at the selected event, or at the visible timeline center (shortcut: m)',
      onclick: () => addMarkerHere(),
    }, 'Add marker');
    const rows = MK.list.map((m) => {
      const labelIn = h('input', {
        class: 'input input-sm marker-label', value: m.label || '',
        placeholder: 'label…', spellcheck: 'false', dataset: { id: m.id },
      });
      labelIn.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter') { ev.preventDefault(); labelIn.blur(); }
      });
      labelIn.addEventListener('blur', () => {
        const v = labelIn.value.trim();
        if (v !== (m.label || '')) {
          m.label = v;
          saveMarkers();
          tlSchedule();          /* the timeline shows the label */
        }
      });
      return h('div', { class: 'marker-row', dataset: { id: m.id } },
        h('button', {
          class: 'linklike mono marker-jump', type: 'button',
          title: 'pan the timeline to this marker', onclick: () => jumpToTs(m.ts),
        }, fmtTime(m.ts)),
        labelIn,
        m.n > 0
          ? h('button', { class: 'linklike mono', type: 'button', onclick: () => jumpToPacket(m.n) }, 'pkt ' + m.n)
          : h('span', { class: 'dim small' }, '—'),
        h('button', {
          class: 'btn btn-danger btn-sm marker-del', type: 'button',
          dataset: { id: m.id }, title: 'delete this marker',
          onclick: () => deleteMarker(m.id),
        }, 'Delete'),
      );
    });
    const markerHead = h('div', { class: 'marker-head' },
      h('span', null, 'Time'), h('span', null, 'Label'),
      h('span', null, 'Packet'), h('span', null, ''));
    const markerList = h('div', { id: 'markers-list' },
      markerHead,
      rows.length ? rows : h('div', { class: 'empty small' },
        'No markers yet — select an event and press "Add marker" (or the m key).'),
    );
    inspBody.replaceChildren(h('div', { class: 'insp-scroll' },
      h('div', { class: 'state-actions' },
        h('span', { class: 'dim small' },
          'User markers — stored in this browser, drawn on the timeline'),
        h('span', { class: 'toolbar-spacer' }),
        addBtn),
      markerList,
    ));
    makeColsResizable(markerHead, markerList, '--mkcols', 'markers');
    if (focusId) {
      const inp = inspBody.querySelector('.marker-label[data-id="' + focusId + '"]');
      if (inp) inp.focus();
    }
  }

  /* ────────── inspector: info tab ────────── */

  function flashInput(inp, cls) {
    inp.classList.remove('flash-ok', 'flash-err');
    inp.classList.add(cls);
    setTimeout(() => inp.classList.remove(cls), 1200);
  }

  async function saveDeviceName(d, inp) {
    const name = inp.value.trim();
    if (inp.value !== name) inp.value = name;
    if (!d.mac || name === (d.name || '')) return;   /* unchanged */
    try {
      await api('/api/devices', { method: 'PUT', json: { mac: d.mac, name } });
      if (S.closed) return;
      d.name = name;                 /* empty string clears the user name */
      rebuildDeviceNames();
      flashInput(inp, 'flash-ok');
      scheduleTable();               /* propagate to src/dst columns */
      if (S.tab === 'inspect') renderInspector();
    } catch (err) {
      if (S.closed) return;
      flashInput(inp, 'flash-err');
      toast('device name: ' + err.message, 'error');
    }
  }

  function renderInfoTab() {
    if (!S.infoData) {
      inspBody.replaceChildren(placeholder(S.infoLoading
        ? 'Loading session info…' : 'Session info not loaded yet.'));
      if (!S.infoLoading) loadInfo();
      return;
    }
    const info = S.infoData;
    const cap = info.capture || {};
    const f = info.file || {};
    const sess = info.session || {};
    const devices = info.devices || [];
    const refreshBtn = h('button', { class: 'btn btn-sm', type: 'button' }, 'Refresh');
    refreshBtn.addEventListener('click', () => { S.infoData = null; renderInfoTab(); });

    const path = String(f.path || '');
    const base = path ? (path.split('/').pop() || path) : '—';

    const capSec = h('section', { class: 'ssec' },
      h('h3', null, 'Capture'),
      h('div', { class: 'insp-meta' },
        metaRow('start', h('span', { class: 'mono' }, fmtNsDate(cap.start_ts_ns))),
        metaRow('end', h('span', { class: 'mono' }, fmtNsDate(cap.end_ts_ns))),
        metaRow('duration', h('span', { class: 'mono' }, fmtDur(cap.duration))),
        metaRow('packets', h('span', { class: 'mono' }, fmtInt(cap.packets))),
      ));

    const fileSec = h('section', { class: 'ssec' },
      h('h3', null, 'File'),
      h('div', { class: 'insp-meta' },
        metaRow('path', h('span', { class: 'mono', title: path }, base)),
        metaRow('size', h('span', { class: 'mono' }, fmtBytes(f.size))),
        metaRow('modified', fmtDate(f.modified)),
        metaRow('accessed', fmtDate(f.accessed)),
        metaRow('created', f.created ? fmtDate(f.created) : '—'),
      ),
      h('p', { class: 'info-note' },
        'This is the session’s own copy of the capture, not the original file.'),
    );

    const sessSec = h('section', { class: 'ssec' },
      h('h3', null, 'Session'),
      h('div', { class: 'insp-meta' },
        metaRow('id', h('span', { class: 'mono' }, sess.id || id)),
        metaRow('name', sess.name || '—'),
        metaRow('created', fmtDate(sess.created_at)),
      ));

    const devRows = devices.map((d) => {
      const inp = h('input', {
        class: 'input input-sm dev-name', spellcheck: 'false',
        dataset: { mac: d.mac || '' },
        value: d.name || '', placeholder: 'name…',
        title: 'display name for ' + (d.mac || '') + ' — Enter/blur saves, empty clears',
      });
      inp.addEventListener('keydown', (ev) => {
        if (ev.key === 'Enter') { ev.preventDefault(); inp.blur(); }
      });
      inp.addEventListener('blur', () => saveDeviceName(d, inp));
      return h('div', { class: 'dev-row' },
        inp,
        h('span', { class: 'mono' }, d.mac || ''),
        h('span', { class: 'dev-ent' },
          d.entity_name ? h('b', null, d.entity_name + ' ') : null,
          d.entity_id
            ? h('span', { class: 'mono dim small' }, d.entity_id)
            : (d.entity_name ? null : h('span', { class: 'dim' }, '—'))),
        h('span', { class: 'num mono' }, fmtInt(d.packets)),
        h('span', { class: 'dev-protos' },
          (d.protocols || []).map((p) => h('span', { class: 'badge ' + protoClass(p) }, p))),
      );
    });
    const devHead = h('div', { class: 'dev-head' },
      h('span', null, 'Name'), h('span', null, 'MAC'), h('span', null, 'Entity'),
      h('span', { class: 'num' }, 'Pkts'), h('span', null, 'Protocols'));
    const devScroll = h('div', { class: 'dev-scroll' },
      devHead,
      devRows.length ? devRows : h('div', { class: 'empty small' }, 'No devices observed.'),
    );
    const devSec = h('section', { class: 'ssec' },
      h('h3', null, 'Devices ', h('span', { class: 'count mono' }, String(devices.length))),
      devScroll);

    const sources = info.sources || [];
    const srcSec = sources.length > 1 ? h('section', { class: 'ssec' },
      h('h3', null, 'Combined sources ', h('span', { class: 'count mono' }, String(sources.length))),
      h('p', { class: 'info-note' },
        'This session merges these captures by time. Each packet in the inspector '
        + 'is tagged with its source; rename the alias here (Enter/blur saves).'),
      h('div', { class: 'src-list' },
        sources.map((sc) => {
          const inp = h('input', {
            class: 'input input-sm', spellcheck: 'false',
            value: sc.alias || sc.name || '', placeholder: 'alias…',
            title: 'display alias for ' + (sc.name || sc.pcap_id),
          });
          inp.addEventListener('keydown', (ev) => {
            if (ev.key === 'Enter') { ev.preventDefault(); inp.blur(); }
          });
          inp.addEventListener('blur', () => saveSourceAlias(sc.index, inp));
          return h('div', { class: 'src-row' },
            h('span', { class: 'src-swatch src-c' + (sc.index % 6) }),
            inp,
            h('span', { class: 'mono dim small', title: sc.pcap_id }, sc.name || sc.pcap_id));
        }))) : null;

    inspBody.replaceChildren(h('div', { class: 'insp-scroll' },
      h('div', { class: 'state-actions' },
        h('span', { class: 'dim small' }, 'Session & capture info'),
        h('span', { class: 'toolbar-spacer' }),
        refreshBtn),
      capSec, fileSec, sessSec, srcSec, devSec,
    ));
    makeColsResizable(devHead, devScroll, '--devcols', 'devices');
  }

  async function saveSourceAlias(index, inp) {
    const alias = inp.value.trim();
    try {
      await api('/api/sessions/' + encodeURIComponent(id) + '/sources/' + index,
        { method: 'PUT', json: { alias } });
      if (S.infoData && (S.infoData.sources || [])[index])
        S.infoData.sources[index].alias = alias;
      S.packetCache.clear();   /* badges re-fetch with the new alias */
      renderSourceLegend();
      scheduleTable();          /* row tooltips pick up the new alias */
      toast('source alias saved');
    } catch (err) {
      toast('alias save failed: ' + err.message, 'error');
    }
  }

  /* ────────── timeline: data ────────── */

  function tlPush(i, n, ts, proto, kindName, type) {
    let lane = PROTOCOLS.indexOf(proto);
    if (lane < 0) {
      lane = LANE_OTHER;
      if (!TL.hasOther) { TL.hasOther = true; tlLayout(); }
    }
    const kIdx = kindName === 'transition' ? 1 : (kindName === 'error' ? 2 : 0);
    TL.i.push(i); TL.n.push(n); TL.ts.push(ts);
    TL.lane.push(lane); TL.kind.push(kIdx); TL.type.push(type || '');
    TL.count++;
    if (typeof ts === 'number' && ts > TL.maxTs) TL.maxTs = ts;
    if (TL.follow) {
      TL.t0 = 0;
      TL.t1 = fullSpan() * 1.02;
    }
  }

  async function loadCompact() {
    try {
      const resp = await api('/api/sessions/' + encodeURIComponent(id) + '/events?compact=1');
      if (S.closed) return;
      const protos = resp.protos || PROTOCOLS;
      const kinds = resp.kinds || KINDS;
      TL.i = []; TL.n = []; TL.ts = []; TL.lane = []; TL.kind = []; TL.type = [];
      TL.count = 0; TL.maxTs = 0; TL.hasOther = false; TL.hoverIdx = -1;
      const laneOf = protos.map((p) => PROTOCOLS.indexOf(p));
      const kindOf = kinds.map((k) => k === 'transition' ? 1 : (k === 'error' ? 2 : 0));
      for (const row of resp.events || []) {
        const i = row[0], n = row[1], ts = row[2], pIdx = row[3], kIdx = row[4], type = row[5];
        let lane = laneOf[pIdx];
        if (lane === undefined || lane < 0) { lane = LANE_OTHER; TL.hasOther = true; }
        TL.i.push(i); TL.n.push(n); TL.ts.push(ts);
        TL.lane.push(lane);
        TL.kind.push(kindOf[kIdx] !== undefined ? kindOf[kIdx] : 0);
        TL.type.push(type || '');
        TL.count++;
        if (typeof ts === 'number' && ts > TL.maxTs) TL.maxTs = ts;
      }
      tlLayout();
      if (TL.follow) tlFit(false);
      tlSchedule();
    } catch (err) {
      if (!S.closed) toast('timeline: ' + err.message, 'error');
    }
  }

  /* ────────── timeline: geometry + interaction ────────── */

  function fullSpan() {
    const dur = (S.meta && typeof S.meta.duration === 'number') ? S.meta.duration : 0;
    return Math.max(dur, TL.maxTs, 0.001);
  }

  function tlFit(redraw) {
    TL.t0 = 0;
    TL.t1 = fullSpan() * 1.02;
    TL.follow = true;
    if (redraw !== false) tlSchedule();
  }

  function xOf(ts) {
    return TL.gutter + (ts - TL.t0) / (TL.t1 - TL.t0) * (TL.w - TL.gutter);
  }

  function tOf(x) {
    return TL.t0 + (x - TL.gutter) / (TL.w - TL.gutter) * (TL.t1 - TL.t0);
  }

  function clampDomain(t0, t1) {
    const span = t1 - t0;
    const full = fullSpan();
    const lo = -full * 0.05;
    const hi = full * 1.05;
    if (span >= hi - lo) return [lo, hi];
    if (t0 < lo) { t0 = lo; t1 = lo + span; }
    if (t1 > hi) { t1 = hi; t0 = hi - span; }
    return [t0, t1];
  }

  function zoomAround(t, factor) {
    const oldSpan = TL.t1 - TL.t0;
    const full = fullSpan() * 1.1;
    let span = oldSpan * factor;
    span = Math.min(Math.max(span, full / 200000), full);
    let t0 = t - (t - TL.t0) * (span / oldSpan);
    let t1 = t0 + span;
    const c = clampDomain(t0, t1);
    TL.t0 = c[0]; TL.t1 = c[1];
    TL.follow = false;
    tlSchedule();
  }

  function tlWheel(ev) {
    ev.preventDefault();
    const rect = TL.canvas.getBoundingClientRect();
    const x = ev.clientX - rect.left;
    if (x < TL.gutter) return;
    /* Firefox reports shift+wheel as deltaX (axis swap); Chromium keeps deltaY */
    const raw = (ev.shiftKey && ev.deltaY === 0) ? ev.deltaX : ev.deltaY;
    const d = ev.deltaMode === 1 ? raw * 20 : raw;
    if (ev.shiftKey) {
      /* shift+wheel: scroll left/right — wheel down/right pans to later times */
      const span = TL.t1 - TL.t0;
      const dt = d / Math.max(1, TL.w - TL.gutter) * span;
      const c = clampDomain(TL.t0 + dt, TL.t1 + dt);
      TL.t0 = c[0]; TL.t1 = c[1];
      TL.follow = false;
      tlSchedule();
      return;
    }
    zoomAround(tOf(x), Math.exp(d * 0.0016));
  }

  /* Pan (never zoom) so time T is visible: used when a selection is made from
     the table or keyboard while the timeline is zoomed elsewhere. No-op when
     T is already comfortably inside the window. */
  function tlCenterOn(t) {
    const span = TL.t1 - TL.t0;
    const margin = span * 0.05;
    if (t >= TL.t0 + margin && t <= TL.t1 - margin) return;
    const c = clampDomain(t - span / 2, t + span / 2);
    TL.t0 = c[0]; TL.t1 = c[1];
    TL.follow = false;
    tlSchedule();
  }

  function tlLowerBound(t) {
    /* first index k with TL.ts[k] >= t (ts ascending: capture order) */
    let lo = 0, hi = TL.count;
    while (lo < hi) {
      const mid = (lo + hi) >> 1;
      if (TL.ts[mid] < t) lo = mid + 1; else hi = mid;
    }
    return lo;
  }

  function tlVisibleMark(k) {
    if (!S.kindOn.has(KINDS[TL.kind[k]])) return false;
    const lane = TL.lane[k];
    if (lane < PROTOCOLS.length && !S.protoOn.has(PROTOCOLS[lane])) return false;
    if (S.query) {
      const e = S.events[TL.i[k]];
      if (e && !passes(e)) return false;
      if (!e) {
        const t = (TL.type[k] || '').toLowerCase();
        if (!t.includes(S.query)) return false;
      }
    }
    return true;
  }

  function tlHitTest(x, y) {
    if (x < TL.gutter - 4 || y > TL.hgt - TL.axisH) return -1;
    const lane = Math.floor(y / TL.laneH);
    if (lane < 0 || lane >= laneCount()) return -1;
    const pxTol = 5;
    const tTol = pxTol / (TL.w - TL.gutter) * (TL.t1 - TL.t0);
    const kStart = tlLowerBound(TL.t0 - tTol);
    let best = -1;
    let bestD = pxTol + 0.001;
    for (let k = kStart; k < TL.count; k++) {
      const ts = TL.ts[k];
      if (ts > TL.t1 + tTol) break;
      if (TL.lane[k] !== lane) continue;
      if (!tlVisibleMark(k)) continue;
      const d = Math.abs(xOf(ts) - x);
      if (d <= bestD) { bestD = d; best = k; }   /* <= prefers the later event on ties */
    }
    return best;
  }

  function tlPointerDown(ev) {
    if (ev.button !== 0) return;
    TL.canvas.setPointerCapture(ev.pointerId);
    TL.drag = { x: ev.clientX, t0: TL.t0, t1: TL.t1, moved: false };
  }

  function tlPointerMove(ev) {
    const rect = TL.canvas.getBoundingClientRect();
    const x = ev.clientX - rect.left;
    const y = ev.clientY - rect.top;
    if (TL.drag) {
      const dx = ev.clientX - TL.drag.x;
      if (Math.abs(dx) > 3) TL.drag.moved = true;
      if (TL.drag.moved) {
        const span = TL.drag.t1 - TL.drag.t0;
        const dt = dx / (TL.w - TL.gutter) * span;
        const c = clampDomain(TL.drag.t0 - dt, TL.drag.t1 - dt);
        TL.t0 = c[0]; TL.t1 = c[1];
        TL.follow = false;
        updateTooltip(-1, 0, 0);
        tlSchedule();
      }
      return;
    }
    const hit = tlHitTest(x, y);
    if (hit !== TL.hoverIdx) {
      TL.hoverIdx = hit;
      tlSchedule();
    }
    updateTooltip(hit, x, y);
    TL.canvas.style.cursor = hit >= 0 ? 'pointer' : 'crosshair';
  }

  function tlPointerUp(ev) {
    const wasDrag = TL.drag && TL.drag.moved;
    TL.drag = null;
    if (wasDrag) return;
    const rect = TL.canvas.getBoundingClientRect();
    const hit = tlHitTest(ev.clientX - rect.left, ev.clientY - rect.top);
    if (hit >= 0) selectEvent(TL.i[hit], { scroll: true });
  }

  function tlLeave() {
    TL.hoverIdx = -1;
    updateTooltip(-1, 0, 0);
    tlSchedule();
  }

  function updateTooltip(k, x, y) {
    const tip = TL.tooltip;
    if (k < 0) { tip.hidden = true; return; }
    const e = S.events[TL.i[k]];
    const proto = TL.lane[k] < PROTOCOLS.length ? PROTOCOLS[TL.lane[k]] : (e ? e.proto : 'ETH');
    tip.replaceChildren(
      h('div', { class: 'tip-head' },
        h('span', { class: 'badge ' + protoClass(proto) }, proto),
        h('b', null, ' ' + ((e ? e.type : TL.type[k]) || '')),
        h('span', { class: 'mono dim' }, '  ' + fmtTime(TL.ts[k]))),
      e && e.summary ? h('div', { class: 'tip-summary' }, e.summary) : null,
    );
    tip.hidden = false;
    const tw = tip.offsetWidth, th = tip.offsetHeight;
    let left = x + 14;
    if (left + tw > TL.w - 8) left = Math.max(TL.gutter, x - tw - 14);
    let top = y + 12;
    if (top + th > TL.hgt - 4) top = Math.max(2, y - th - 10);
    tip.style.left = left + 'px';
    tip.style.top = top + 'px';
  }

  /* ────────── timeline: rendering ────────── */

  function tlLayout() {
    const hCss = laneCount() * TL.laneH + TL.axisH;
    TL.wrap.style.height = hCss + 'px';
    tlResize();
  }

  function tlResize() {
    const rect = TL.wrap.getBoundingClientRect();
    TL.dpr = window.devicePixelRatio || 1;
    TL.w = Math.max(60, rect.width);
    TL.hgt = Math.max(40, rect.height);
    TL.canvas.width = Math.round(TL.w * TL.dpr);
    TL.canvas.height = Math.round(TL.hgt * TL.dpr);
    tlSchedule();
  }

  function tlSchedule() {
    if (!TL.raf && !S.closed) TL.raf = requestAnimationFrame(tlDraw);
  }

  function niceStep(target) {
    if (!(target > 0) || !isFinite(target)) return 1;
    const pow = Math.pow(10, Math.floor(Math.log10(target)));
    for (const m of [1, 2, 5]) {
      if (m * pow >= target) return m * pow;
    }
    return 10 * pow;
  }

  function fmtAxis(t, step) {
    if (Math.abs(t) < step * 1e-6) t = 0;
    if (step >= 0.1) {
      const dec = Math.max(0, Math.min(3, -Math.floor(Math.log10(step))));
      return t.toFixed(dec) + ' s';
    }
    const stepMs = step * 1000;
    const dec = Math.max(0, Math.min(3, -Math.floor(Math.log10(stepMs))));
    return (t * 1000).toFixed(dec) + ' ms';
  }

  function drawMark(ctx, x, lane, kIdx, emph) {
    const yMid = lane * TL.laneH + TL.laneH / 2;
    const color = kIdx === 2 ? ERROR_COLOR : laneColor(lane);
    if (kIdx === 1) {
      /* transition: diamond, taller than packet ticks */
      const r = 5;
      ctx.fillStyle = color;
      ctx.beginPath();
      ctx.moveTo(x, yMid - r - 1);
      ctx.lineTo(x + r - 1, yMid);
      ctx.lineTo(x, yMid + r + 1);
      ctx.lineTo(x - r + 1, yMid);
      ctx.closePath();
      ctx.fill();
    } else if (kIdx === 2) {
      /* decode error: cross */
      ctx.strokeStyle = color;
      ctx.lineWidth = 1.6;
      ctx.beginPath();
      ctx.moveTo(x - 3.5, yMid - 3.5); ctx.lineTo(x + 3.5, yMid + 3.5);
      ctx.moveTo(x + 3.5, yMid - 3.5); ctx.lineTo(x - 3.5, yMid + 3.5);
      ctx.stroke();
    } else {
      /* packet: thin vertical tick */
      ctx.fillStyle = color;
      ctx.fillRect(x - 0.75, yMid - 5, 1.5, 10);
    }
    if (emph) {
      ctx.strokeStyle = 'rgba(232,234,237,0.9)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.arc(x, yMid, 7, 0, Math.PI * 2);
      ctx.stroke();
    }
  }

  function tlDraw() {
    TL.raf = 0;
    if (S.closed) return;
    const ctx = TL.canvas.getContext('2d');
    if (!ctx) return;
    /* expose the visible window for tests and tooling */
    TL.canvas.dataset.t0 = TL.t0.toFixed(6);
    TL.canvas.dataset.t1 = TL.t1.toFixed(6);
    ctx.setTransform(TL.dpr, 0, 0, TL.dpr, 0, 0);
    const w = TL.w, hh = TL.hgt;
    const L = laneCount();
    const chartB = L * TL.laneH;
    const plotL = TL.gutter;
    ctx.clearRect(0, 0, w, hh);
    ctx.fillStyle = '#15181d';
    ctx.fillRect(0, 0, w, hh);

    /* lane zebra bands */
    for (let li = 0; li < L; li++) {
      if (li % 2 === 1) {
        ctx.fillStyle = 'rgba(255,255,255,0.025)';
        ctx.fillRect(plotL, li * TL.laneH, w - plotL, TL.laneH);
      }
    }

    /* time grid + axis labels */
    const span = TL.t1 - TL.t0;
    const step = niceStep(span / Math.max(2, Math.floor((w - plotL) / 90)));
    ctx.font = '10px ' + MONO_FONT;
    ctx.textAlign = 'center';
    ctx.textBaseline = 'top';
    ctx.strokeStyle = 'rgba(255,255,255,0.05)';
    ctx.beginPath();
    const kFirst = Math.ceil(TL.t0 / step - 1e-9);
    const labels = [];
    for (let ki = kFirst; ki * step <= TL.t1 + step * 1e-9; ki++) {
      const tv = ki * step;
      const x = Math.round(xOf(tv)) + 0.5;
      if (x < plotL) continue;
      ctx.moveTo(x, 0);
      ctx.lineTo(x, chartB);
      labels.push([x, fmtAxisLabel(tv, step)]);
    }
    ctx.stroke();
    ctx.fillStyle = '#8b949e';
    for (const [x, txt] of labels) {
      ctx.fillText(txt, Math.min(Math.max(x, plotL + 24), w - 28), chartB + 6);
    }

    /* lane separators + axis baseline */
    ctx.strokeStyle = 'rgba(255,255,255,0.06)';
    ctx.beginPath();
    for (let li = 1; li <= L; li++) {
      const y = li * TL.laneH + 0.5;
      ctx.moveTo(0, y);
      ctx.lineTo(w, y);
    }
    ctx.stroke();

    /* markers (per lane+kind pixel dedup keeps redraw cost bounded) */
    const lastPx = new Array(L * 3).fill(-9999);
    let selK = -1;
    const kStart = tlLowerBound(TL.t0);
    for (let k = kStart; k < TL.count; k++) {
      const ts = TL.ts[k];
      if (ts > TL.t1) break;
      if (!tlVisibleMark(k)) continue;
      if (TL.i[k] === S.selected) selK = k;
      const lane = TL.lane[k];
      const kIdx = TL.kind[k];
      const x = Math.round(xOf(ts));
      const slot = lane * 3 + kIdx;
      if (x === lastPx[slot] && k !== TL.hoverIdx && TL.i[k] !== S.selected) continue;
      lastPx[slot] = x;
      drawMark(ctx, x, lane, kIdx, false);
    }

    /* hover + selection on top */
    if (TL.hoverIdx >= 0 && TL.hoverIdx < TL.count) {
      const k = TL.hoverIdx;
      if (TL.ts[k] >= TL.t0 && TL.ts[k] <= TL.t1) {
        drawMark(ctx, Math.round(xOf(TL.ts[k])), TL.lane[k], TL.kind[k], true);
      }
    }
    if (selK >= 0) {
      const x = Math.round(xOf(TL.ts[selK])) + 0.5;
      ctx.strokeStyle = 'rgba(232,234,237,0.35)';
      ctx.lineWidth = 1;
      ctx.beginPath();
      ctx.moveTo(x, 0);
      ctx.lineTo(x, chartB);
      ctx.stroke();
      drawMark(ctx, Math.round(xOf(TL.ts[selK])), TL.lane[selK], TL.kind[selK], true);
      const lbl = fmtTime(TL.ts[selK]);
      ctx.font = '10px ' + MONO_FONT;
      const tw = ctx.measureText(lbl).width;
      let lx = Math.min(Math.max(x + 4, plotL + 2), w - tw - 6);
      ctx.fillStyle = 'rgba(21,24,29,0.9)';
      ctx.fillRect(lx - 2, chartB + 4, tw + 6, 13);
      ctx.fillStyle = '#e8eaed';
      ctx.textAlign = 'left';
      ctx.fillText(lbl, lx + 1, chartB + 6);
    }

    /* user markers: amber dashed verticals with a flag + label at the top */
    if (MK.list.length) {
      ctx.font = '10px ' + MONO_FONT;
      ctx.textAlign = 'left';
      ctx.textBaseline = 'top';
      for (const m of MK.list) {
        if (m.ts < TL.t0 || m.ts > TL.t1) continue;
        const mx = Math.round(xOf(m.ts)) + 0.5;
        if (mx < plotL) continue;
        ctx.strokeStyle = MARKER_COLOR;
        ctx.lineWidth = 1;
        ctx.setLineDash([4, 3]);
        ctx.beginPath();
        ctx.moveTo(mx, 0);
        ctx.lineTo(mx, chartB);
        ctx.stroke();
        ctx.setLineDash([]);
        ctx.fillStyle = MARKER_COLOR;
        ctx.beginPath();
        ctx.moveTo(mx, 0);
        ctx.lineTo(mx + 6, 3.5);
        ctx.lineTo(mx, 7);
        ctx.closePath();
        ctx.fill();
        if (m.label) {
          const mlbl = m.label.length > 24 ? m.label.slice(0, 23) + '…' : m.label;
          const mtw = ctx.measureText(mlbl).width;
          const mlx = Math.min(mx + 8, w - mtw - 4);
          ctx.fillStyle = 'rgba(21,24,29,0.85)';
          ctx.fillRect(mlx - 2, 1, mtw + 4, 12);
          ctx.fillStyle = MARKER_COLOR;
          ctx.fillText(mlbl, mlx, 2);
        }
      }
    }

    /* gutter: lane labels (opaque, drawn last) */
    ctx.fillStyle = '#101318';
    ctx.fillRect(0, 0, plotL - 1, hh);
    ctx.strokeStyle = 'rgba(255,255,255,0.08)';
    ctx.beginPath();
    ctx.moveTo(plotL - 0.5, 0);
    ctx.lineTo(plotL - 0.5, chartB);
    ctx.stroke();
    ctx.textAlign = 'left';
    ctx.textBaseline = 'middle';
    ctx.font = '600 10px system-ui, sans-serif';
    for (let li = 0; li < L; li++) {
      ctx.fillStyle = laneColor(li);
      ctx.fillText(laneName(li), 8, li * TL.laneH + TL.laneH / 2 + 0.5);
    }
  }

  tlCanvas.addEventListener('wheel', tlWheel, { passive: false });
  tlCanvas.addEventListener('pointerdown', tlPointerDown);
  tlCanvas.addEventListener('pointermove', tlPointerMove);
  tlCanvas.addEventListener('pointerup', tlPointerUp);
  tlCanvas.addEventListener('pointerleave', tlLeave);
  tlCanvas.addEventListener('dblclick', (ev) => {
    /* Fit only on empty timeline space — a double-click on a marker keeps the
       selection (from pointerup) instead of zooming the whole view out. */
    const rect = TL.canvas.getBoundingClientRect();
    if (tlHitTest(ev.clientX - rect.left, ev.clientY - rect.top) >= 0) return;
    tlFit(true);
  });

  const resizeObs = new ResizeObserver(() => { if (!S.closed) tlResize(); });
  resizeObs.observe(tlWrap);

  /* ────────── pane resize: shift + right-click (drag) ──────────
     shift+right-click (and drag) between the events table and the inspector
     moves the split to the pointer; on the timeline it adjusts the lane
     height. Both persist in localStorage. Note: Firefox may still open the
     native context menu (shift bypasses page contextmenu handlers by
     design), but the resize is applied from the pointerdown position, so a
     single shift+right-click always works. */

  let splitDrag = false;

  function applySplit(pct) {
    pct = Math.min(100, Math.max(0, pct));   /* full range so either side collapses */
    eventsPanel.style.flex = '0 0 ' + pct.toFixed(1) + '%';
    eventsPanel.classList.toggle('is-collapsed', pct < 3.5);   /* table hidden */
    inspectorPanel.classList.toggle('is-collapsed', pct > 96.5); /* inspector hidden */
    try { localStorage.setItem(SPLIT_KEY, pct.toFixed(1)); } catch (err) { /* ignore */ }
    scheduleTable();             /* visible row window may have changed */
  }

  /* visible divider: normal left-drag resizes; double-click resets to default;
     dragging to an edge fully collapses that pane (the gutter stays grabbable) */
  const DEFAULT_SPLIT = 58;
  let gutterDrag = false;
  function gutterMove(ev) {
    if (!gutterDrag) return;
    const rect = mainSplit.getBoundingClientRect();
    const column = getComputedStyle(mainSplit).flexDirection === 'column';
    const frac = column
      ? (ev.clientY - rect.top) / Math.max(1, rect.height)
      : (ev.clientX - rect.left) / Math.max(1, rect.width);
    applySplit(frac * 100);
  }
  splitGutter.addEventListener('pointerdown', (ev) => {
    if (ev.button !== 0) return;
    ev.preventDefault();
    gutterDrag = true;
    document.body.classList.add('col-resizing');
    try { splitGutter.setPointerCapture(ev.pointerId); } catch (err) { /* ignore */ }
  });
  splitGutter.addEventListener('pointermove', gutterMove);
  const endGutter = (ev) => {
    if (!gutterDrag) return;
    gutterDrag = false;
    document.body.classList.remove('col-resizing');
    try { splitGutter.releasePointerCapture(ev.pointerId); } catch (err) { /* ignore */ }
  };
  splitGutter.addEventListener('pointerup', endGutter);
  splitGutter.addEventListener('pointercancel', endGutter);
  splitGutter.addEventListener('dblclick', () => applySplit(DEFAULT_SPLIT));

  function splitFromPointer(ev) {
    const rect = mainSplit.getBoundingClientRect();
    const column = getComputedStyle(mainSplit).flexDirection === 'column';
    const frac = column
      ? (ev.clientY - rect.top) / Math.max(1, rect.height)
      : (ev.clientX - rect.left) / Math.max(1, rect.width);
    applySplit(frac * 100);
  }

  mainSplit.addEventListener('pointerdown', (ev) => {
    if (ev.button !== 2 || !ev.shiftKey) return;
    ev.preventDefault();
    splitDrag = true;
    try { mainSplit.setPointerCapture(ev.pointerId); } catch (err) { /* ignore */ }
    splitFromPointer(ev);
  });
  mainSplit.addEventListener('pointermove', (ev) => { if (splitDrag) splitFromPointer(ev); });
  const endSplitDrag = () => { splitDrag = false; };
  mainSplit.addEventListener('pointerup', endSplitDrag);
  mainSplit.addEventListener('pointercancel', endSplitDrag);
  mainSplit.addEventListener('contextmenu', (ev) => { if (ev.shiftKey) ev.preventDefault(); });

  {
    /* restore the stored split (incl. a collapsed pane) */
    const storedSplit = parseFloat(localStorage.getItem(SPLIT_KEY) || '');
    if (storedSplit >= 0 && storedSplit <= 100) applySplit(storedSplit);
  }

  /* timeline lane-height resize (shift+right-drag vertically) */
  let laneDrag = false;
  tlWrap.addEventListener('pointerdown', (ev) => {
    if (ev.button !== 2 || !ev.shiftKey) return;
    ev.preventDefault();
    laneDrag = true;
    try { tlWrap.setPointerCapture(ev.pointerId); } catch (err) { /* ignore */ }
  });
  tlWrap.addEventListener('pointermove', (ev) => {
    if (!laneDrag) return;
    const rect = tlWrap.getBoundingClientRect();
    const hLane = (ev.clientY - rect.top - TL.axisH) / Math.max(1, laneCount());
    TL.laneH = Math.min(44, Math.max(14, hLane));
    try { localStorage.setItem(LANEH_KEY, TL.laneH.toFixed(1)); } catch (err) { /* ignore */ }
    tlLayout();
  });
  const endLaneDrag = () => { laneDrag = false; };
  tlWrap.addEventListener('pointerup', endLaneDrag);
  tlWrap.addEventListener('pointercancel', endLaneDrag);
  tlWrap.addEventListener('contextmenu', (ev) => { if (ev.shiftKey) ev.preventDefault(); });

  /* ────────── header / status ────────── */

  function updateHeaderMeta() {
    const m = S.meta;
    if (!m) return;
    titleEl.textContent = m.name || id;
    document.title = (m.name || id) + ' — AVB Introspection';
    statusSlot.replaceChildren(sessionStatusBadge(m));
    const bits = [];
    bits.push(fmtInt(m.packets) + ' pkts');
    bits.push(fmtInt(m.events) + ' events');
    if (m.decode_errors) bits.push(fmtInt(m.decode_errors) + ' decode errors');
    if (typeof m.duration === 'number') bits.push(fmtDur(m.duration));
    countsEl.textContent = bits.join(' · ');
    if (m.status === 'error') {
      errBanner.textContent = 'Analysis failed: ' + (m.error || 'unknown error');
      errBanner.hidden = false;
    } else {
      errBanner.hidden = true;
    }
    if (m.protocols) {
      for (const p of PROTOCOLS) {
        const c = protoChips.get(p);
        const v = m.protocols[p];
        c.cnt.textContent = typeof v === 'number' ? fmtInt(v) : '';
      }
    }
    updateTimeModeCtl();
    updateProgress();
    updateCounts();
  }

  function updateProgress() {
    const running = S.meta && S.meta.status === 'running' && !S.done;
    progressEl.hidden = !running;
    if (running) {
      const pk = S.progress ? S.progress.packets : (S.meta ? S.meta.packets : 0);
      const evn = S.progress ? S.progress.events : (S.meta ? S.meta.events : 0);
      progressEl.querySelector('.progress-text').textContent =
        'analyzing — ' + fmtInt(pk) + ' pkts · ' + fmtInt(evn) + ' events';
    }
  }

  async function refreshMeta() {
    try {
      const m = await api('/api/sessions/' + encodeURIComponent(id));
      if (S.closed) return;
      S.meta = m;
      updateHeaderMeta();
    } catch (err) {
      if (!S.closed) toast(err.message, 'error');
    }
  }

  /* ────────── live feed: WebSocket with polling fallback ────────── */

  let ws = null;
  let pingTimer = 0;
  let pollTimer = 0;
  let polling = false;
  let wsQueue = Promise.resolve();
  let finished = false;   /* complete handled (final refresh done) */

  function haveAllEvents() {
    return S.meta && S.meta.status !== 'running'
      && S.events.length >= (S.meta.events || 0);
  }

  function startFeed() {
    if (S.closed) return;
    let sock;
    const wsProto = location.protocol === 'https:' ? 'wss://' : 'ws://';
    const url = wsProto + location.host + BASE + '/api/ws?token='
      + encodeURIComponent(token) + '&session=' + encodeURIComponent(id);
    try {
      sock = new WebSocket(url);
    } catch (err) {
      startPolling();
      return;
    }
    ws = sock;
    sock.binaryType = 'arraybuffer';
    sock.addEventListener('open', () => {
      if (S.closed) { sock.close(); return; }
      pingTimer = setInterval(() => {
        try { sock.send(JSON.stringify({ type: 'ping' })); } catch (err) { /* ignore */ }
      }, 25000);
    });
    sock.addEventListener('message', (ev) => {
      wsQueue = wsQueue.then(() => handleWsFrame(ev.data)).catch((err) => {
        console.warn('ws frame decode failed', err);
      });
    });
    sock.addEventListener('close', (ev) => {
      clearInterval(pingTimer);
      pingTimer = 0;
      if (ws === sock) ws = null;
      if (S.closed) return;
      if (ev.code === 4001) { authLost(); return; }
      if (ev.code === 4004) { toast('unknown session — it may have been deleted', 'error'); return; }
      if (!haveAllEvents()) {
        toast('event stream disconnected — falling back to polling', 'error');
        startPolling();
      }
    });
  }

  async function handleWsFrame(data) {
    if (S.closed) return;
    let text;
    if (typeof data === 'string') {
      text = data;
    } else {
      /* binary frame: one complete zlib (RFC1950) stream holding UTF-8 JSON */
      const ds = new DecompressionStream('deflate');
      text = await new Response(new Blob([data]).stream().pipeThrough(ds)).text();
    }
    const msg = JSON.parse(text);
    if (S.closed) return;
    if (msg.type === 'batch') {
      appendEvents(msg.events || []);
    } else if (msg.type === 'progress') {
      S.progress = msg;
      updateProgress();
    } else if (msg.type === 'complete') {
      await onAnalysisComplete();
    } else if (msg.type === 'error') {
      toast('analysis error: ' + (msg.error || 'unknown'), 'error');
      await refreshMeta();
    }
    /* pong: ignored */
  }

  async function onAnalysisComplete() {
    if (finished || S.closed) return;
    finished = true;
    S.done = true;
    stopPolling();
    await refreshMeta();
    loadCompact();     /* refresh the compact timeline */
    loadState();       /* refresh reconstructed state */
    loadInfo();        /* refresh device inventory + names */
    updateProgress();
    updateCounts();
  }

  function startPolling() {
    if (polling || S.closed) return;
    polling = true;
    pollOnce();
  }

  function stopPolling() {
    polling = false;
    clearTimeout(pollTimer);
    pollTimer = 0;
  }

  async function pollOnce() {
    if (!polling || S.closed) return;
    try {
      const m = await api('/api/sessions/' + encodeURIComponent(id));
      if (S.closed) return;
      S.meta = m;
      updateHeaderMeta();
      let guard = 0;
      while (!S.closed && polling && S.events.length < (m.events || 0) && guard < 400) {
        guard++;
        const page = await api('/api/sessions/' + encodeURIComponent(id)
          + '/events?offset=' + S.events.length + '&limit=5000');
        if (!page || !Array.isArray(page.events) || !page.events.length) break;
        appendEvents(page.events);
      }
      if (m.status !== 'running' && S.events.length >= (m.events || 0)) {
        polling = false;
        if (!finished) await onAnalysisComplete();
        return;
      }
    } catch (err) {
      /* transient — keep polling */
    }
    if (polling && !S.closed) pollTimer = setTimeout(pollOnce, 2000);
  }

  /* ────────── init ────────── */

  loadMarkers();
  renderInspector();
  updateCounts();
  updateTimeModeCtl();
  tlLayout();

  (async () => {
    try {
      S.meta = await api('/api/sessions/' + encodeURIComponent(id));
    } catch (err) {
      if (S.closed) return;
      toast('session ' + id + ': ' + err.message, 'error');
      if (token) navigate('#/home');   /* on 401 authLost() already routed to login */
      return;
    }
    if (S.closed) return;
    updateHeaderMeta();
    loadInfo();                /* device names for src/dst labels everywhere */
    if (S.meta.status !== 'running') {
      S.done = true;
      finished = true;         /* a later WS `complete` needs no re-fetch */
      loadCompact();
      loadState();
    }
    startFeed();               /* WS delivers the full event stream either way */
  })();

  return {
    destroy() {
      S.closed = true;
      stopPolling();
      clearTimeout(searchTimer);
      clearInterval(pingTimer);
      if (ws) { try { ws.close(); } catch (err) { /* ignore */ } ws = null; }
      closeMachineWins();
      window.removeEventListener('pagehide', closeMachineWins);
      document.removeEventListener('keydown', onKey);
      resizeObs.disconnect();
      if (TL.raf) cancelAnimationFrame(TL.raf);
      if (tableRaf) cancelAnimationFrame(tableRaf);
      document.title = 'AVB Introspection';
    },
  };
}

/* ────────────────────────── boot ────────────────────────── */

function boot() {
  /* keep canvas + CSS in one truth: push the JS palette into CSS custom props */
  const rootStyle = document.documentElement.style;
  for (const p of PROTOCOLS) rootStyle.setProperty('--c-' + p.toLowerCase(), PROTO_COLORS[p]);
  rootStyle.setProperty('--c-err', ERROR_COLOR);
  rootStyle.setProperty('--c-other', OTHER_COLOR);

  const logoutBtn = document.getElementById('logout-btn');
  if (logoutBtn) logoutBtn.addEventListener('click', doLogout);

  /* presence chip: click toggles the popover, hover opens it */
  const presenceWrap = document.getElementById('presence-wrap');
  const presenceBtn = document.getElementById('presence');
  if (presenceWrap && presenceBtn) {
    presenceBtn.addEventListener('click', () => setPresenceOpen(!presenceOpen));
    presenceWrap.addEventListener('mouseenter', () => setPresenceOpen(true));
    presenceWrap.addEventListener('mouseleave', () => setPresenceOpen(false));
    document.addEventListener('click', (ev) => {
      if (presenceOpen && !presenceWrap.contains(ev.target)) setPresenceOpen(false);
    });
  }
  setInterval(presenceTick, 10000);   /* heartbeat + list refresh cadence */

  window.addEventListener('hashchange', render);
  updateUserbox();
  render();

  /* validate the stored token once so a stale one drops straight to login;
     also learns/refreshes the cached role (shows/hides #admin-link) */
  refreshRole();
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
else boot();

})();
