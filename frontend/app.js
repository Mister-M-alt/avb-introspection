/* AVB Introspection — frontend. Vanilla ES2022, no dependencies, works offline.
   Talks to the backend API described in docs/API.md via relative URLs. */
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
const MONO_FONT = 'ui-monospace, "SF Mono", "Cascadia Mono", Menlo, Consolas, "Liberation Mono", monospace';

const TOKEN_KEY = 'avb.token';
const USER_KEY = 'avb.user';
const ROW_H = 24;               /* events table row height, px (matches CSS) */

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
  }
  updateUserbox();
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
    throw new Error((body && body.error) ? body.error : (res.status + ' ' + res.statusText));
  }
  return body;
}

async function doLogout() {
  try { await api('/api/logout', { method: 'POST' }); } catch (err) { /* best effort */ }
  setAuth('', '');
  navigate('#/login');
}

function updateUserbox() {
  const box = document.getElementById('userbox');
  const name = document.getElementById('user-name');
  if (!box || !name) return;
  box.hidden = !token;
  name.textContent = username;
}

/* ────────────────────────── router ────────────────────────── */

let currentView = null;   /* { destroy() } */

function parseRoute() {
  const hash = location.hash || '';
  if (hash.startsWith('#/session/')) {
    return { view: 'session', id: decodeURIComponent(hash.slice('#/session/'.length)) };
  }
  if (hash === '#/home') return { view: 'home' };
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
  if (r.view === 'login') currentView = loginView(app);
  else if (r.view === 'session') currentView = sessionView(app, r.id);
  else currentView = homeView(app);
}

/* ────────────────────────── login view ────────────────────────── */

function loginView(app) {
  let mode = 'login';
  let busy = false;

  const errBox = h('div', { class: 'form-error', hidden: true });
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
    submitBtn.textContent = mode === 'login' ? 'Log in' : 'Register';
    toggle.textContent = mode === 'login' ? 'No account? Register' : 'Have an account? Log in';
    hint.hidden = mode === 'login';
    errBox.hidden = true;
  }

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
        await api('/api/register', { method: 'POST', json: { username: u, password: p }, auth: false });
      }
      const r = await api('/api/login', { method: 'POST', json: { username: u, password: p }, auth: false });
      setAuth(r.token, r.username || u);
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
  const fileIn = h('input', {
    type: 'file', accept: '.pcap,.pcapng,.cap', hidden: true,
    onchange: () => { if (fileIn.files && fileIn.files[0]) uploadFile(fileIn.files[0]); },
  });
  const uploadBtn = h('button', {
    class: 'btn btn-primary', type: 'button',
    onclick: () => { fileIn.value = ''; fileIn.click(); },
  }, 'Upload pcap…');
  const pathIn = h('input', {
    class: 'input mono', placeholder: '/data/traces/capture.pcap', spellcheck: 'false',
    onkeydown: (ev) => { if (ev.key === 'Enter') openPath(); },
  });
  const openBtn = h('button', { class: 'btn', type: 'button', onclick: openPath }, 'Open');

  app.appendChild(
    h('div', { class: 'home' },
      metricsBox,
      h('div', { class: 'home-cols' },
        h('section', { class: 'panel' },
          h('div', { class: 'panel-head' }, h('h2', null, 'Uploaded pcaps'), uploadBtn, fileIn),
          pcapList,
        ),
        h('section', { class: 'panel' },
          h('div', { class: 'panel-head' }, h('h2', null, 'Open by server path')),
          h('div', { class: 'path-row' }, pathIn, openBtn),
          h('p', { class: 'dim small' },
            'Path must be visible to the backend (e.g. a mounted volume). pcap and pcapng are accepted.'),
        ),
      ),
      h('section', { class: 'panel' },
        h('div', { class: 'panel-head' }, h('h2', null, 'Analysis sessions')),
        h('div', { class: 'slist-head' },
          h('span', null, 'Name'), h('span', null, 'Status'), h('span', { class: 'num' }, 'Packets'),
          h('span', { class: 'num' }, 'Events'), h('span', { class: 'num' }, 'Errors'),
          h('span', { class: 'num' }, 'Duration'), h('span', null, 'Created'), h('span', null, ''),
        ),
        sessList,
      ),
    ),
  );

  async function uploadFile(file) {
    uploadBtn.disabled = true;
    uploadBtn.textContent = 'Uploading…';
    try {
      const p = await api('/api/pcaps?name=' + encodeURIComponent(file.name), {
        method: 'POST', body: file, contentType: 'application/octet-stream',
      });
      const s = await api('/api/sessions', { method: 'POST', json: { pcap_id: p.id } });
      toast('uploaded ' + file.name + ' — analysis started');
      navigate('#/session/' + encodeURIComponent(s.id));
    } catch (err) {
      toast('upload failed: ' + err.message, 'error');
      uploadBtn.disabled = false;
      uploadBtn.textContent = 'Upload pcap…';
    }
  }

  async function openPath() {
    const path = pathIn.value.trim();
    if (!path) { toast('enter a path first', 'error'); return; }
    openBtn.disabled = true;
    try {
      const s = await api('/api/sessions', { method: 'POST', json: { path } });
      navigate('#/session/' + encodeURIComponent(s.id));
    } catch (err) {
      toast('open failed: ' + err.message, 'error');
      openBtn.disabled = false;
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

  function renderPcaps(pcaps) {
    if (!pcaps.length) {
      pcapList.replaceChildren(h('div', { class: 'empty' }, 'No pcaps yet — upload one.'));
      return;
    }
    pcapList.replaceChildren(...pcaps.map((p) => {
      const btn = h('button', { class: 'btn btn-sm', type: 'button' }, 'Analyze');
      btn.addEventListener('click', () => analyzePcap(p.id, btn));
      return h('div', { class: 'prow' },
        h('span', { class: 'prow-name', title: p.name }, p.name),
        h('span', { class: 'dim mono small' }, fmtBytes(p.size)),
        h('span', { class: 'dim small' }, fmtDate(p.uploaded_at)),
        btn,
      );
    }));
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

  function metric(label, value, title) {
    return h('div', { class: 'metric', title: title || '' },
      h('div', { class: 'm-label' }, label),
      h('div', { class: 'm-value mono' }, value),
    );
  }

  function renderMetrics(m) {
    if (!m || !m.process) { metricsBox.replaceChildren(); return; }
    const pr = m.process;
    const pool = m.pool || {};
    const cpu = (pr.cpu_user_s || 0) + (pr.cpu_sys_s || 0);
    metricsBox.replaceChildren(
      metric('CPU', cpu.toFixed(1) + ' s', 'user ' + (pr.cpu_user_s || 0) + ' s + sys ' + (pr.cpu_sys_s || 0) + ' s'),
      metric('RSS', ((pr.rss_kb || 0) / 1024).toFixed(1) + ' MB'),
      metric('Uptime', fmtUptime(pr.uptime_s)),
      metric('Threads', String(pr.threads !== undefined ? pr.threads : '—')),
      metric('Pool', (pool.active || 0) + ' active / ' + (pool.threads || 0) + ' (max ' + (pool.max_threads || 0) + ')'),
      metric('Queued', fmtInt(pool.queued)),
      metric('Clients', fmtInt((m.clients || []).length)),
      metric('Sessions', fmtInt((m.sessions || []).length)),
    );
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
    if (results[0].status === 'fulfilled') renderPcaps(results[0].value.pcaps || []);
    else anyErr = results[0].reason;
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

/* ────────────────────────── session view ────────────────────────── */

function sessionView(app, id) {
  /* ── mutable view state ── */
  const S = {
    meta: null,
    events: [],              /* dense array indexed by event index i */
    nToI: new Map(),         /* packet number n -> event index i (packet events) */
    filtered: [],            /* event indices passing the filters, ascending */
    protoOn: new Set(PROTOCOLS),
    kindOn: new Set(KINDS),
    query: '',
    selected: -1,            /* selected event index i, or -1 */
    lonePacket: 0,           /* packet number shown without a selected event */
    tab: 'inspect',          /* 'inspect' | 'state' | 'notes' */
    stateData: null,
    stateLoading: false,
    entityNames: new Map(),
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
      h('span', { class: 'tl-hint dim' }, 'wheel zoom · drag pan · dblclick fit'),
      tlFitBtn,
    ),
  );
  TL.canvas = tlCanvas;
  TL.wrap = tlWrap;
  TL.tooltip = tlTooltip;

  /* ── events table DOM (virtualized) ── */
  const tableHead = h('div', { class: 'etable-head' },
    h('span', { class: 'c-idx' }, '#'),
    h('span', { class: 'c-ts' }, 'Time'),
    h('span', { class: 'c-proto' }, 'Proto'),
    h('span', { class: 'c-type' }, 'Type'),
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
  const inspBody = h('div', { class: 'insp-body' });

  /* ── assemble ── */
  app.appendChild(
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
          h('span', { class: 'toolbar-spacer' }),
          shownEl,
        ),
        errBanner,
      ),
      tlWrap,
      h('div', { class: 'session-main' },
        h('div', { class: 'events-panel' }, tableHead, tableBody, tableEmpty),
        h('div', { class: 'inspector-panel' },
          h('div', { class: 'tabs' }, tabInspBtn, tabStateBtn, tabNotesBtn),
          inspBody,
        ),
      ),
    ),
  );

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
      const glyph = e.kind === 'transition'
        ? h('span', { class: 'kg kg-tr' }, '◆ ')
        : (e.kind === 'error' ? h('span', { class: 'kg kg-err' }, '✕ ') : null);
      frag.appendChild(h('div', { class: cls, dataset: { i: String(i) }, title: e.summary || '' },
        h('span', { class: 'c-idx mono' }, i),
        h('span', { class: 'c-ts mono' }, fmtTs(e.ts)),
        h('span', { class: 'c-proto' }, h('span', { class: 'badge ' + protoClass(e.proto) }, e.proto)),
        h('span', { class: 'c-type' }, glyph, e.type || ''),
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

  /* ────────── selection ────────── */

  let inspNeedsEvent = -1;   /* selected-but-not-yet-loaded event index */

  function selectEvent(i, opts) {
    opts = opts || {};
    S.selected = i;
    S.lonePacket = 0;
    scheduleTable();
    const e = S.events[i];
    if (e) tlCenterOn(e.ts); /* keep the selection visible in the timeline */
    tlSchedule();
    if (opts.scroll) scrollToSelected();
    if (S.tab !== 'inspect') setTab('inspect');
    else renderInspector();
  }

  function clearSelection() {
    if (S.selected < 0 && !S.lonePacket) return;
    S.selected = -1;
    S.lonePacket = 0;
    scheduleTable();
    tlSchedule();
    if (S.tab === 'inspect') renderInspector();
  }

  function jumpToPacket(n) {
    const i = S.nToI.get(n);
    if (i !== undefined) {
      selectEvent(i, { scroll: true });
    } else {
      S.selected = -1;
      S.lonePacket = n;
      scheduleTable();
      tlSchedule();
      if (S.tab !== 'inspect') setTab('inspect');
      else renderInspector();
    }
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
    if (S.tab === 'notes' && t !== 'notes' && N.dirty) saveNotes();   /* auto-save on leave */
    S.tab = t;
    tabInspBtn.classList.toggle('active', t === 'inspect');
    tabStateBtn.classList.toggle('active', t === 'state');
    tabNotesBtn.classList.toggle('active', t === 'notes');
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
    const name = S.entityNames.get(idStr);
    return h('span', { class: 'ent' },
      name ? h('b', null, name + ' ') : null,
      h('span', { class: 'mono' }, idStr));
  }

  function renderInspector() {
    if (S.tab === 'state') { renderStateTab(); return; }
    if (S.tab === 'notes') { renderNotesTab(); return; }
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
    metaRows.push(metaRow('time', h('span', { class: 'mono' }, fmtTs(e.ts))));
    metaRows.push(metaRow('proto / kind',
      h('span', { class: 'badge ' + protoClass(e.proto) }, e.proto), ' ',
      h('span', { class: 'dim' }, e.kind)));
    metaRows.push(metaRow('type', h('span', { class: 'mono' }, e.type || '')));
    if (e.src || e.dst) {
      metaRows.push(metaRow('src → dst',
        h('span', { class: 'mono' }, e.src || '—'),
        h('span', { class: 'dim' }, ' → '),
        h('span', { class: 'mono' }, e.dst || '—')));
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
            h('span', { class: 'f-val mono' }, typeof v === 'object' ? JSON.stringify(v) : String(v)),
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
            h('span', { class: 'f-val mono' }, f.value),
          ]),
        ),
      ));
    return h('div', { class: 'packet-view' },
      h('div', { class: 'pkt-head' },
        h('b', null, 'packet #' + pkt.n),
        h('span', { class: 'dim mono small' },
          '  ' + fmtTs(pkt.ts) + ' · ' + pkt.len + ' B'
          + (pkt.caplen !== undefined && pkt.caplen !== pkt.len ? ' (captured ' + pkt.caplen + ')' : '')),
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

  function stateClass(sName) {
    const u = String(sName || '').toUpperCase();
    if (u.includes('FAIL') || u.includes('TIMED_OUT') || u === 'LOST'
      || u === 'MISMATCH' || u === 'NOT_AS_CAPABLE' || u.includes('ERROR')) return 'st-bad';
    if (u === 'DEFENDING') return 'st-serious';
    if (u === 'AVAILABLE' || u === 'ESTABLISHED' || u === 'REGISTERED' || u === 'ACQUIRED'
      || u === 'CONNECTED' || u === 'READY' || u === 'SUCCESS' || u === 'ADVERTISE'
      || u === 'HEALTHY' || u === 'MATCH' || u === 'GM_PRESENT'
      || u === 'AS_CAPABLE' || u === 'MASTER') return 'st-good';
    if (u === 'PENDING' || u === 'PROBING' || u === 'CONNECTING' || u === 'LEAVING'
      || u === 'DEPARTING' || u === 'DISCONNECTING' || u === 'NO_GM'
      || u.includes('ASKING')) return 'st-warn';
    return 'st-neutral';
  }

  function stateBadge(sName, small) {
    return h('span', { class: 'sbadge ' + stateClass(sName) + (small ? ' sm' : '') }, String(sName));
  }

  function historyBlock(hist) {
    if (!Array.isArray(hist) || !hist.length) return null;
    return h('details', { class: 'history' },
      h('summary', null, 'history (' + hist.length + ')'),
      h('div', { class: 'hist-rows' },
        hist.map((t) => h('div', { class: 'hist-row' },
          h('span', { class: 'mono hist-ts' }, fmtTs(t.ts)),
          stateBadge(t.from, true),
          h('span', { class: 'dim' }, '→'),
          stateBadge(t.to, true),
          h('span', { class: 'hist-why', title: t.why || '' }, t.why || ''),
          (typeof t.n === 'number' && t.n > 0)
            ? h('button', { class: 'linklike mono', type: 'button', onclick: () => jumpToPacket(t.n) }, 'pkt ' + t.n)
            : null,
        )),
      ),
    );
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
        ['last seen', fmtTs(en.last_seen)],
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
        ]),
        null, d.history);
    });

    const gptpPortSec = stateSection('gPTP ports', gptp.ports, (p) => {
      const pd = p.pdelay || {};
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
        ]),
        null, p.history);
    });

    inspBody.replaceChildren(h('div', { class: 'insp-scroll' },
      h('div', { class: 'state-actions' },
        h('span', { class: 'dim small' }, 'Reconstructed protocol state'),
        h('span', { class: 'toolbar-spacer' }),
        refreshBtn),
      entitySec, resvSec, vlanSec, domSec, maapSec, connSec, aecpSec,
      gptpDomSec, gptpPortSec,
    ));
  }

  /* ────────── inspector: notes tab ────────── */

  const N = { loaded: false, loading: false, dirty: false, saving: false, preview: false };

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
  const notesWrap = h('div', { class: 'notes-wrap' },
    h('div', { class: 'notes-toolbar' },
      notesSaveBtn, notesPreviewBtn,
      h('span', { class: 'toolbar-spacer' }),
      notesStatus),
    notesTa, notesPreview,
  );
  notesTa.addEventListener('input', () => {
    N.dirty = true;
    if (!N.saving) setNotesStatus('dirty');
  });

  function setNotesStatus(state, msg) {
    const text = { saved: 'saved', dirty: 'unsaved changes', saving: 'saving…', loading: 'loading…' };
    notesStatus.dataset.state = state;
    notesStatus.classList.toggle('errtext', state === 'error');
    notesStatus.textContent = state === 'error' ? (msg || 'save failed') : text[state];
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
    try {
      await api('/api/sessions/' + encodeURIComponent(id) + '/notes', {
        method: 'PUT', json: { markdown: text },
      });
      if (S.closed) return;
      N.dirty = notesTa.value !== text;     /* stay dirty if edited mid-flight */
      setNotesStatus(N.dirty ? 'dirty' : 'saved');
    } catch (err) {
      if (S.closed) return;
      setNotesStatus('error', 'save failed: ' + err.message);
      if (S.tab !== 'notes') toast('notes save failed: ' + err.message, 'error');
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
    const dy = ev.deltaMode === 1 ? ev.deltaY * 20 : ev.deltaY;
    zoomAround(tOf(x), Math.exp(dy * 0.0016));
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
        h('span', { class: 'mono dim' }, '  ' + fmtTs(TL.ts[k]))),
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
      labels.push([x, fmtAxis(tv, step)]);
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
      const lbl = fmtTs(TL.ts[selK]);
      ctx.font = '10px ' + MONO_FONT;
      const tw = ctx.measureText(lbl).width;
      let lx = Math.min(Math.max(x + 4, plotL + 2), w - tw - 6);
      ctx.fillStyle = 'rgba(21,24,29,0.9)';
      ctx.fillRect(lx - 2, chartB + 4, tw + 6, 13);
      ctx.fillStyle = '#e8eaed';
      ctx.textAlign = 'left';
      ctx.fillText(lbl, lx + 1, chartB + 6);
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
  tlCanvas.addEventListener('dblclick', () => tlFit(true));

  const resizeObs = new ResizeObserver(() => { if (!S.closed) tlResize(); });
  resizeObs.observe(tlWrap);

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

  renderInspector();
  updateCounts();
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

  window.addEventListener('hashchange', render);
  updateUserbox();
  render();

  /* validate the stored token once so a stale one drops straight to login */
  if (token) {
    api('/api/me').then((me) => {
      if (me && me.username && me.username !== username) {
        username = me.username;
        localStorage.setItem(USER_KEY, username);
        updateUserbox();
      }
    }).catch(() => { /* 401 already handled by api() */ });
  }
}

if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
else boot();

})();
