/* HoneySlop /pot, operator dashboard.
 *
 * SECURITY: everything coming from the API is attacker-controlled (paths, headers, bodies,
 * user agents, even geo strings). It is ONLY ever put into the DOM via textContent / text
 * nodes (see h()). innerHTML is used exclusively for the static, hard-coded SVG icons below.
 */
'use strict';
(() => {
  const API = '/pot/api';
  const BODY_LIMIT = 20000;      // chars rendered before "show all"
  const PAGE_SIZE = 100;         // timeline page size
  const MAX_ROWS = 1500;         // cap on IP rows kept in the DOM
  const STATS_EVERY = 15000;

  /* ------------------------------------------------------------------ helpers */

  const $ = (id) => document.getElementById(id);

  /** Safe element builder. Strings become text nodes, never parsed as HTML. */
  function h(tag, props, ...kids) {
    const el = document.createElement(tag);
    if (props) {
      for (const k in props) {
        const v = props[k];
        if (v == null || v === false) continue;
        if (k === 'class') el.className = v;
        else if (k === 'text') el.textContent = v;
        else if (k.startsWith('on') && typeof v === 'function') el.addEventListener(k.slice(2), v);
        else el.setAttribute(k, v === true ? '' : String(v));
      }
    }
    for (const c of kids.flat(Infinity)) {
      if (c == null || c === false) continue;
      el.append(c instanceof Node ? c : String(c));
    }
    return el;
  }

  // Static, trusted icon markup (no data ever flows in here).
  const ICONS = {
    search: '<circle cx="11" cy="11" r="7"/><path d="m20 20-3.5-3.5"/>',
    copy: '<rect x="9" y="9" width="12" height="12" rx="2.5"/><path d="M5 15h-.5A1.5 1.5 0 0 1 3 13.5v-9A1.5 1.5 0 0 1 4.5 3h9A1.5 1.5 0 0 1 15 4.5V5"/>',
    check: '<path d="M20 6 9 17l-5-5"/>',
    sliders: '<path d="M4 7h9M17 7h3M4 17h3M11 17h9"/><circle cx="15" cy="7" r="2"/><circle cx="9" cy="17" r="2"/>',
    logout: '<path d="M9 21H5a2 2 0 0 1-2-2V5a2 2 0 0 1 2-2h4"/><path d="m16 17 5-5-5-5"/><path d="M21 12H9"/>',
    trash: '<path d="M3 6h18"/><path d="M8 6V4.5A1.5 1.5 0 0 1 9.5 3h5A1.5 1.5 0 0 1 16 4.5V6"/><path d="M18.5 6 17.6 19.2A2 2 0 0 1 15.6 21H8.4a2 2 0 0 1-2-1.8L5.5 6"/>',
    chev: '<path d="m9 6 6 6-6 6"/>',
    x: '<path d="M18 6 6 18M6 6l12 12"/>',
    back: '<path d="M19 12H5M11 18l-6-6 6-6"/>',
    bolt: '<path d="M13 2 4 14h7l-1 8 9-12h-7z"/>',
    crosshair: '<circle cx="12" cy="12" r="8"/><path d="M12 2v4M12 18v4M2 12h4M18 12h4"/><circle cx="12" cy="12" r="1.2"/>',
  };
  function icon(name, cls) {
    const s = document.createElement('span');
    s.className = 'ico' + (cls ? ' ' + cls : '');
    s.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true">' + ICONS[name] + '</svg>';
    return s;
  }
  function hydrateIcons(root) {
    for (const el of root.querySelectorAll('.ico[data-icon]')) {
      const name = el.getAttribute('data-icon');
      if (ICONS[name] && !el.firstChild) el.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true">' + ICONS[name] + '</svg>';
    }
  }

  const str = (v) => (v == null ? '' : String(v));
  const pad = (n) => (n < 10 ? '0' : '') + n;
  const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

  function fmtClock(ts) { const d = new Date(ts); return pad(d.getHours()) + ':' + pad(d.getMinutes()) + ':' + pad(d.getSeconds()); }
  function fmtDay(ts) {
    const d = new Date(ts), now = new Date();
    const s = MONTHS[d.getMonth()] + ' ' + d.getDate();
    return d.getFullYear() === now.getFullYear() ? s : s + ', ' + d.getFullYear();
  }
  function fmtFull(ts) { return ts ? fmtDay(ts) + ' ' + fmtClock(ts) : '–'; }
  function fmtRel(ts) {
    if (!ts) return '–';
    const s = Math.max(0, Math.round((Date.now() - ts) / 1000));
    if (s < 5) return 'just now';
    if (s < 60) return s + 's ago';
    const m = Math.floor(s / 60);
    if (m < 60) return m + 'm ago';
    const hr = Math.floor(m / 60);
    if (hr < 48) return hr + 'h ago';
    return Math.floor(hr / 24) + 'd ago';
  }
  function fmtLat(ms) {
    if (ms == null || ms < 0) return '';
    if (ms < 1000) return Math.round(ms) + 'ms';
    return (ms / 1000).toFixed(ms < 10000 ? 2 : 1) + 's';
  }
  function fmtNum(n) { return n == null ? '–' : Number(n).toLocaleString('en-US'); }
  function fmtBytes(n) { return n < 1024 ? n + ' B' : (n / 1024).toFixed(1) + ' KB'; }
  function plural(n, one, many) { return fmtNum(n) + ' ' + (n === 1 ? one : (many || one + 's')); }

  /** Element whose text is a relative time that the global ticker keeps fresh. */
  function relEl(tag, cls, ts) {
    const el = h(tag, { class: cls, text: fmtRel(ts) });
    setRel(el, ts);
    return el;
  }
  function setRel(el, ts) {
    el.dataset.ts = String(ts || 0);
    const t = fmtRel(ts);
    if (el.textContent !== t) el.textContent = t;
    if (ts) el.title = fmtFull(ts);
  }

  function flagEmoji(cc) {
    cc = str(cc).toUpperCase();
    if (!/^[A-Z]{2}$/.test(cc)) return '';
    return String.fromCodePoint(0x1F1E6 + cc.charCodeAt(0) - 65, 0x1F1E6 + cc.charCodeAt(1) - 65);
  }
  /** Fill a flag element according to geo state. */
  function paintFlag(el, info, baseCls) {
    const geo = info.geo;
    let cls = baseCls, text = '', title = '';
    if (geo === 'pending') { cls += ' flag-pending'; title = 'Geo lookup in progress'; }
    else if (geo === 'private') { cls += ' flag-txt'; text = 'LAN'; title = 'Private / loopback address'; }
    else {
      const f = flagEmoji(info.country_code);
      if (f) { text = f; title = str(info.country); }
      else { cls += ' flag-txt'; text = '??'; title = geo === 'failed' ? 'Geo lookup failed' : 'Unknown location'; }
    }
    if (el.className !== cls) el.className = cls;
    if (el.textContent !== text) el.textContent = text;
    el.title = title;
  }

  function locText(info) {
    if (info.geo === 'pending') return 'locating…';
    if (info.geo === 'private') return 'Private network';
    const parts = [info.city, info.country].filter(Boolean);
    if (parts.length) return parts.join(', ');
    return info.geo === 'failed' ? 'Unknown location' : '-';
  }
  function orgText(info) {
    return [info.asn, info.org || info.isp].filter(Boolean).join(' · ');
  }

  async function copyText(text, btn) {
    let ok = false;
    try {
      if (navigator.clipboard && window.isSecureContext) { await navigator.clipboard.writeText(text); ok = true; }
    } catch (_) { /* fall through */ }
    if (!ok) {
      const ta = h('textarea', { style: 'position:fixed;left:-9999px;top:0;opacity:0', readonly: true });
      ta.value = text;
      document.body.append(ta);
      ta.select();
      try { ok = document.execCommand('copy'); } catch (_) { ok = false; }
      ta.remove();
    }
    if (btn) {
      btn.classList.toggle('copied', ok);
      const ico = btn.querySelector('.ico');
      if (ico && ok) {
        ico.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true">' + ICONS.check + '</svg>';
        clearTimeout(btn._t);
        btn._t = setTimeout(() => {
          btn.classList.remove('copied');
          ico.innerHTML = '<svg viewBox="0 0 24 24" aria-hidden="true">' + ICONS.copy + '</svg>';
        }, 1400);
      }
    }
    if (!ok) toast('Copy failed, select the text manually', 'err');
    return ok;
  }

  function toast(msg, kind) {
    const t = h('div', { class: 'toast ' + (kind || ''), role: 'status' }, str(msg));
    $('toasts').append(t);
    setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 300); }, kind === 'err' ? 5000 : 3000);
  }

  /* ------------------------------------------------------------------ api */

  class HttpError extends Error {
    constructor(status, message) { super(message); this.status = status; }
  }

  async function api(method, path, body) {
    const opts = { method, credentials: 'same-origin', headers: { Accept: 'application/json' }, cache: 'no-store' };
    if (method !== 'GET') {
      opts.headers['Content-Type'] = 'application/json';
      opts.body = JSON.stringify(body || {});
    }
    let res;
    try { res = await fetch(API + path, opts); }
    catch (_) { throw new HttpError(0, 'Network error, is the server reachable?'); }
    let data = null;
    try { data = await res.json(); } catch (_) { data = null; }
    if (!res.ok) {
      const msg = (data && typeof data.error === 'string' && data.error) || ('HTTP ' + res.status);
      // Login / password-change failures are 401s about the *password*, not the session.
      if (res.status === 401 && path !== '/login' && path !== '/password') onUnauthorized();
      throw new HttpError(res.status, msg);
    }
    return data;
  }

  function reportError(err) {
    if (err && err.status === 401) return; // handled by onUnauthorized
    toast((err && err.message) || 'Something went wrong', 'err');
  }

  /* ------------------------------------------------------------------ state */

  const S = {
    version: '',
    authed: false,
    settings: null,
    stats: null,
    ips: new Map(),       // ip -> { info, el, refs }
    selected: null,
    query: '',
    queryToken: 0,
    tl: null,             // { ip, items: Map<id, {ev, el, full}>, minId, more, loading, token }
    tlToken: 0,
    es: null,
    esRetry: 0,
    esResync: false,
    statsTimer: null,
    statsSoon: null,
  };

  /* ------------------------------------------------------------------ auth screens */

  let authMode = 'login';

  function showAuth(mode, msg) {
    authMode = mode;
    S.authed = false;
    stopLive();
    closeModals();
    resetData();
    $('boot').hidden = true;
    $('app').hidden = true;
    $('auth').hidden = false;
    const setup = mode === 'setup';
    $('auth-title').textContent = setup ? 'Create admin password' : 'Sign in';
    $('auth-sub').textContent = setup
      ? 'First run. Choose the password that protects this dashboard (min. 8 characters).'
      : 'Enter the admin password to watch the honeypot.';
    $('auth-confirm-wrap').hidden = !setup;
    $('auth-pass').setAttribute('autocomplete', setup ? 'new-password' : 'current-password');
    $('auth-submit').textContent = setup ? 'Create password & open dashboard' : 'Sign in';
    $('auth-pass').value = '';
    $('auth-confirm').value = '';
    $('auth-version').textContent = S.version ? 'v' + S.version : '';
    authError(msg || '');
    setTimeout(() => $('auth-pass').focus(), 30);
  }

  function authError(msg) {
    const el = $('auth-error');
    el.textContent = msg;
    el.hidden = !msg;
  }

  async function onAuthSubmit(e) {
    e.preventDefault();
    const pw = $('auth-pass').value;
    const setup = authMode === 'setup';
    if (!pw) return authError('Enter a password.');
    if (setup) {
      if (pw.length < 8) return authError('Password must be at least 8 characters.');
      if (pw !== $('auth-confirm').value) return authError('Passwords do not match.');
    }
    const btn = $('auth-submit');
    btn.disabled = true;
    authError('');
    try {
      await api('POST', setup ? '/setup' : '/login', { password: pw });
      $('auth-pass').value = '';
      $('auth-confirm').value = '';
      await startDashboard();
    } catch (err) {
      if (setup && err.status === 409) { showAuth('login', 'A password is already set. Sign in instead.'); }
      else if (err.status === 401) { authError('Wrong password.'); $('auth-pass').select(); }
      else if (err.status === 429) { authError(err.message && !/^HTTP/.test(err.message) ? err.message : 'Too many attempts. Wait a moment and try again.'); }
      else authError(err.message);
    } finally {
      btn.disabled = false;
    }
  }

  function onUnauthorized() {
    if (!S.authed) return;
    showAuth('login', 'Your session has ended. Please sign in again.');
  }

  async function logout() {
    try { await api('POST', '/logout', {}); } catch (_) { /* ignore */ }
    showAuth('login');
  }

  /* ------------------------------------------------------------------ boot */

  async function boot() {
    hydrateIcons(document);
    bindStatic();
    let st;
    try { st = await api('GET', '/state'); }
    catch (err) {
      $('boot').hidden = true;
      showAuth('login', 'Cannot reach the server: ' + err.message);
      return;
    }
    S.version = str(st.version);
    if (st.setup) showAuth('setup');
    else if (!st.authed) showAuth('login');
    else await startDashboard();
  }

  async function startDashboard() {
    S.authed = true;
    $('boot').hidden = true;
    $('auth').hidden = true;
    $('app').hidden = false;
    connectStream();
    await Promise.all([
      loadSettings().catch(reportError),
      loadStats().catch(reportError),
      loadIPs().catch(reportError),
    ]);
    if (!S.authed) return;
    const fromHash = ipFromHash();
    if (fromHash) selectIP(fromHash, { fromHash: true });
    else renderDetailEmpty();
    clearInterval(S.statsTimer);
    S.statsTimer = setInterval(() => { if (S.authed && !document.hidden) loadStats().catch(() => {}); }, STATS_EVERY);
  }

  function resetData() {
    S.ips.clear();
    $('ip-list').textContent = '';
    S.selected = null;
    S.tl = null;
    S.tlToken++;
    $('timeline').textContent = '';
    $('ip-header').textContent = '';
    clearInterval(S.statsTimer);
  }

  /* ------------------------------------------------------------------ live stream */

  function connectStream() {
    stopLive();
    if (!S.authed) return;
    setLive('connecting');
    const es = new EventSource(API + '/stream');
    S.es = es;
    es.onopen = () => {
      if (S.es !== es) return;
      S.esRetry = 0;
      setLive('live');
      if (S.esResync) { S.esResync = false; resync(); }
    };
    es.onerror = () => {
      if (S.es !== es) return;
      setLive('down');
      S.esResync = true;
      if (es.readyState === EventSource.CLOSED) {
        // Browser gave up (e.g. 401 or non-SSE response). Check auth, then retry ourselves.
        es.close();
        S.es = null;
        const delay = Math.min(30000, 1000 * Math.pow(2, S.esRetry++));
        setTimeout(async () => {
          if (!S.authed || S.es) return;
          try {
            const st = await api('GET', '/state');
            if (!st.authed) { onUnauthorized(); return; }
          } catch (_) { /* server down, keep retrying */ }
          if (S.authed && !S.es) connectStream();
        }, delay);
      }
    };
    const on = (name, fn) => es.addEventListener(name, (m) => {
      if (S.es !== es) return;
      let data;
      try { data = JSON.parse(m.data); } catch (_) { return; }
      try { fn(data); } catch (err) { console.error('stream handler', name, err); }
    });
    on('hit', onHit);
    on('ip', (info) => { if (info && info.ip) upsertIP(info, { move: false }); refreshHeaderIf(info); });
    on('cleared', onCleared);
    on('settings', (s) => applySettings(s));
  }

  function stopLive() {
    if (S.es) { S.es.close(); S.es = null; }
  }

  function setLive(state) {
    const el = $('live');
    el.dataset.state = state;
    $('live-label').textContent = state === 'live' ? 'Live' : state === 'down' ? 'Reconnecting' : 'Connecting';
    el.title = state === 'live' ? 'Event stream connected' : 'Event stream disconnected, retrying';
  }

  /** After a reconnect we may have missed hits: reload what's on screen. */
  function resync() {
    loadStats().catch(() => {});
    loadIPs().catch(() => {});
    if (S.selected) loadTimeline(S.selected, { keepOpen: true });
  }

  function onHit(msg) {
    const info = msg && msg.ip;
    const ev = msg && msg.event;
    if (!info || !info.ip) return;
    upsertIP(info, { move: true, flash: true });
    if (S.selected === info.ip) {
      refreshHeaderIf(info);
      if (ev && S.tl && S.tl.ip === info.ip && !S.tl.loading) prependEvent(ev);
    }
    renderListMeta();
    statsSoon();
  }

  function onCleared() {
    S.ips.clear();
    $('ip-list').textContent = '';
    S.selected = null;
    S.tl = null;
    S.tlToken++;
    if (location.hash) history.replaceState(null, '', location.pathname + location.search);
    renderListMeta();
    renderDetailEmpty();
    loadStats().catch(() => {});
    toast('All data was cleared', 'ok');
  }

  /* ------------------------------------------------------------------ stats */

  async function loadStats() {
    const st = await api('GET', '/stats');
    const prev = S.stats;
    S.stats = st;
    const set = (id, v, pv) => {
      const el = $(id);
      const t = fmtNum(v);
      if (el.textContent !== t) {
        el.textContent = t;
        if (prev && pv !== v) { el.classList.add('bump'); setTimeout(() => el.classList.remove('bump'), 50); }
      }
    };
    set('st-events24', st.events_24h, prev && prev.events_24h);
    set('st-ips24', st.ips_24h, prev && prev.ips_24h);
    set('st-ai24', st.ai_calls_24h, prev && prev.ai_calls_24h);
    set('st-term24', st.terminal_cmds_24h, prev && prev.terminal_cmds_24h);
    set('st-total', st.events_total, prev && prev.events_total);
    if (S.settings && typeof st.ai_enabled === 'boolean' && st.ai_enabled !== S.settings.ai_enabled) {
      // Stats are fresher than our cached settings? re-fetch to stay consistent.
      loadSettings().catch(() => {});
    } else renderAI();
  }

  function statsSoon() {
    if (S.statsSoon) return;
    S.statsSoon = setTimeout(() => { S.statsSoon = null; if (S.authed) loadStats().catch(() => {}); }, 1500);
  }

  /* ------------------------------------------------------------------ settings + AI toggle */

  async function loadSettings() {
    applySettings(await api('GET', '/settings'));
  }

  function applySettings(s) {
    if (!s || typeof s !== 'object') return;
    S.settings = s;
    renderAI();
    const domain = str(s.domain) || location.host;
    $('curl-hint').textContent = 'curl http://' + domain + '/.env';
    if (!$('settings-modal').hidden) fillSettingsStatic();
  }

  function aiReady() {
    const s = S.settings;
    if (s) return !!(s.ai_enabled && s.openrouter_key_set);
    return !!(S.stats && S.stats.ai_ready);
  }

  function renderAI() {
    const s = S.settings;
    const enabled = s ? !!s.ai_enabled : !!(S.stats && S.stats.ai_enabled);
    const sw = $('ai-switch');
    sw.setAttribute('aria-checked', String(enabled));
    const wrap = $('ai-toggle');
    const stateEl = $('ai-state');
    if (!enabled) {
      wrap.dataset.state = 'off';
      stateEl.textContent = 'Off';
      wrap.title = 'AI is off, attackers get static fallback responses';
    } else if (!aiReady()) {
      wrap.dataset.state = 'warn';
      stateEl.textContent = 'No key';
      wrap.title = 'AI is enabled but no OpenRouter key is set, fallback responses are served. Click to configure.';
    } else {
      wrap.dataset.state = 'on';
      stateEl.textContent = 'On';
      wrap.title = 'AI is on' + (s && s.model ? ', ' + s.model : '');
    }
  }

  async function toggleAI() {
    const sw = $('ai-switch');
    const next = sw.getAttribute('aria-checked') !== 'true';
    sw.setAttribute('aria-checked', String(next));
    sw.disabled = true;
    try {
      applySettings(await api('PUT', '/settings', { ai_enabled: next }));
      if (next && !aiReady()) toast('AI enabled, but no OpenRouter key is set yet', 'warn');
      else toast(next ? 'AI responses enabled' : 'AI responses disabled, serving fallbacks', next ? 'ok' : '');
      loadStats().catch(() => {});
    } catch (err) {
      renderAI();
      reportError(err);
    } finally {
      sw.disabled = false;
    }
  }

  /* settings modal */

  let keyClear = false;

  function fillSettingsStatic() {
    const s = S.settings || {};
    const hint = $('set-key-hint');
    if (keyClear) {
      hint.textContent = 'The key will be removed when you save.';
      hint.className = 'field-help warn';
    } else if (s.openrouter_key_set) {
      hint.textContent = 'Current key: ' + (str(s.openrouter_key_hint) || 'set') + ', leave empty to keep it.';
      hint.className = 'field-help';
    } else {
      hint.textContent = 'No key configured. Get one at openrouter.ai/keys.';
      hint.className = 'field-help warn';
    }
    $('set-key').placeholder = s.openrouter_key_set ? str(s.openrouter_key_hint) || '••••••••' : 'sk-or-v1-…';
    $('set-key-clear').textContent = keyClear ? 'Undo' : 'Clear key';
    $('set-key-clear').hidden = !s.openrouter_key_set;
    const dl = $('model-list');
    dl.textContent = '';
    for (const m of (Array.isArray(s.model_suggestions) ? s.model_suggestions : [])) dl.append(h('option', { value: str(m) }));
    const lim = s.limits || {};
    $('lim-minute').textContent = lim.minute != null ? fmtNum(lim.minute) : '–';
    $('lim-hour').textContent = lim.hour != null ? fmtNum(lim.hour) : '–';
    $('lim-day').textContent = lim.day != null ? fmtNum(lim.day) : '–';
    $('lim-domain').textContent = str(s.domain) || location.host;
    $('lim-domain').title = str(s.domain) || location.host;
  }

  async function openSettings() {
    keyClear = false;
    try { await loadSettings(); } catch (err) { reportError(err); if (!S.settings) return; }
    const s = S.settings;
    $('set-key').value = '';
    $('set-model').value = str(s.model);
    $('set-persona').value = str(s.persona);
    $('pw-current').value = '';
    $('pw-new').value = '';
    setResult('set-test-result', '', '');
    setResult('pw-result', '', '');
    settingsError('');
    fillSettingsStatic();
    openModal('settings-modal');
    setTimeout(() => $('set-model').focus(), 30);
  }

  function settingsPatch() {
    const s = S.settings || {};
    const patch = {};
    const key = $('set-key').value.trim();
    if (key) patch.openrouter_key = key;
    else if (keyClear) patch.openrouter_key = '';
    const model = $('set-model').value.trim();
    if (model !== str(s.model)) patch.model = model;
    const persona = $('set-persona').value;
    if (persona !== str(s.persona)) patch.persona = persona;
    return patch;
  }

  function settingsError(msg) { const el = $('settings-error'); el.textContent = msg; el.hidden = !msg; }

  async function saveSettings(opts) {
    const patch = settingsPatch();
    if (!Object.keys(patch).length) return true;
    if ('model' in patch && !patch.model) { settingsError('Model cannot be empty.'); return false; }
    try {
      applySettings(await api('PUT', '/settings', patch));
      keyClear = false;
      $('set-key').value = '';
      fillSettingsStatic();
      settingsError('');
      if (!opts || !opts.quiet) toast('Settings saved', 'ok');
      return true;
    } catch (err) {
      settingsError(err.message);
      return false;
    }
  }

  async function onSaveSettings() {
    const btn = $('settings-save');
    btn.disabled = true;
    const ok = await saveSettings();
    btn.disabled = false;
    if (ok) closeModals();
  }

  function setResult(id, cls, ...content) {
    const el = $(id);
    el.className = 'test-result' + (cls ? ' ' + cls : '');
    el.textContent = '';
    el.append(...content.filter((c) => c !== ''));
  }

  async function testConnection() {
    const btn = $('set-test');
    btn.disabled = true;
    setResult('set-test-result', '', h('span', { class: 'spin' }), 'Testing…');
    try {
      // Test what the user sees in the form: persist unsaved key/model first.
      const dirty = Object.keys(settingsPatch()).length > 0;
      if (dirty && !(await saveSettings({ quiet: true }))) { setResult('set-test-result', 'err', 'Fix the errors above first'); return; }
      const r = await api('POST', '/settings/test', {});
      if (r.ok) {
        setResult('set-test-result', 'ok', '✓ Connected', h('span', { class: 'mono', text: [str(r.model), fmtLat(r.latency_ms)].filter(Boolean).join(' · ') }));
      } else {
        setResult('set-test-result', 'err', '✕ ' + (str(r.error) || 'Test failed'), r.latency_ms ? h('span', { class: 'mono', text: fmtLat(r.latency_ms) }) : '');
      }
      if (dirty) toast('Unsaved changes were saved before testing', '');
    } catch (err) {
      setResult('set-test-result', 'err', '✕ ' + err.message);
    } finally {
      btn.disabled = false;
    }
  }

  async function changePassword() {
    const cur = $('pw-current').value, nw = $('pw-new').value;
    if (!cur || !nw) return setResult('pw-result', 'err', 'Enter your current and new password.');
    if (nw.length < 8) return setResult('pw-result', 'err', 'New password must be at least 8 characters.');
    const btn = $('pw-save');
    btn.disabled = true;
    try {
      await api('POST', '/password', { current: cur, new: nw });
      $('pw-current').value = '';
      $('pw-new').value = '';
      setResult('pw-result', 'ok', '✓ Password changed. Other sessions were signed out.');
    } catch (err) {
      setResult('pw-result', 'err', err.status === 401 || err.status === 403 ? 'Current password is wrong.' : err.message);
    } finally {
      btn.disabled = false;
    }
  }

  /* clear all */

  function openClear() {
    const st = S.stats;
    $('clear-counts').textContent = st
      ? plural(st.events_total || 0, 'event') + ' and ' + plural(st.ips_total || 0, 'IP')
      : 'all events and IPs';
    $('clear-input').value = '';
    $('clear-confirm').disabled = true;
    const e = $('clear-error'); e.hidden = true; e.textContent = '';
    openModal('clear-modal');
    setTimeout(() => $('clear-input').focus(), 30);
  }

  async function doClear() {
    if ($('clear-input').value.trim().toLowerCase() !== 'clear') return;
    const btn = $('clear-confirm');
    btn.disabled = true;
    try {
      await api('POST', '/clear', {});
      closeModals();
      // The SSE `cleared` message will also arrive; make local state consistent right away.
      if (S.ips.size || S.selected) onCleared();
    } catch (err) {
      const e = $('clear-error'); e.textContent = err.message; e.hidden = false;
      btn.disabled = false;
    }
  }

  /* modal plumbing */

  let lastFocus = null;
  function openModal(id) {
    lastFocus = document.activeElement;
    $(id).hidden = false;
  }
  function closeModals() {
    let closed = false;
    for (const m of document.querySelectorAll('.modal-wrap')) if (!m.hidden) { m.hidden = true; closed = true; }
    if (closed && lastFocus && document.contains(lastFocus)) { try { lastFocus.focus(); } catch (_) {} }
    return closed;
  }
  const anyModalOpen = () => [...document.querySelectorAll('.modal-wrap')].some((m) => !m.hidden);

  /* ------------------------------------------------------------------ IP list */

  async function loadIPs() {
    const token = ++S.queryToken;
    const q = S.query;
    const data = await api('GET', '/ips' + (q ? '?q=' + encodeURIComponent(q) : ''));
    if (token !== S.queryToken || !S.authed) return;
    const list = Array.isArray(data && data.ips) ? data.ips : [];
    const frag = document.createDocumentFragment();
    const next = new Map();
    for (const info of list) {
      if (!info || !info.ip || next.has(info.ip)) continue;
      let e = S.ips.get(info.ip);
      if (e) e.info = info; else e = makeRow(info);
      paintRow(e);
      e.el.hidden = false;
      e.el.classList.remove('new', 'flash');
      next.set(info.ip, e);
      frag.append(e.el);
    }
    // Keep the selected IP visible even if the search hides it server-side.
    S.ips = next;
    const listEl = $('ip-list');
    listEl.textContent = '';
    listEl.append(frag);
    markSelected();
    renderListMeta();
  }

  function makeRow(info) {
    const r = {};
    const el = h('div', { class: 'ip-row', role: 'option', 'aria-selected': 'false' },
      r.flag = h('span', { class: 'flag' }),
      h('div', { class: 'ip-main' },
        h('div', { class: 'ip-l1' },
          r.ip = h('span', { class: 'ip-addr' }),
          r.ago = h('span', { class: 'ip-ago' })),
        h('div', { class: 'ip-l2' },
          r.loc = h('span', { class: 'ip-loc' }),
          r.org = h('span', { class: 'ip-org' })),
        h('div', { class: 'ip-l3' },
          r.last = h('span', { class: 'ip-last' }, r.method = h('b'), r.path = document.createTextNode('')),
          h('span', { class: 'ip-counts' },
            r.count = h('span', { class: 'cnt', title: 'Requests' }),
            r.ai = h('span', { class: 'cnt cnt-ai', title: 'AI generated responses' })))));
    el.dataset.ip = info.ip;
    return { info, el, refs: r };
  }

  function setText(node, t) { if (node.textContent !== t) node.textContent = t; }

  function paintRow(e) {
    const { info, refs: r, el } = e;
    paintFlag(r.flag, info, 'flag');
    setText(r.ip, str(info.ip));
    r.ip.title = str(info.ip);
    setRel(r.ago, info.last_seen);
    el.classList.toggle('recent', Date.now() - (info.last_seen || 0) < 60000);
    setText(r.loc, locText(info));
    r.loc.classList.toggle('pending', info.geo === 'pending');
    const org = orgText(info);
    setText(r.org, org);
    r.org.title = org;
    setText(r.method, str(info.last_method));
    const p = str(info.last_path);
    if (r.path.data !== p) r.path.data = p;
    r.last.title = (str(info.last_method) + ' ' + p).trim();
    setText(r.count, fmtNum(info.count || 0));
    setText(r.ai, 'ai ' + fmtNum(info.ai_count || 0));
    r.ai.classList.toggle('zero', !info.ai_count);
  }

  function matchesQuery(info) {
    const q = S.query.trim().toLowerCase();
    if (!q) return true;
    return [info.ip, info.country, info.city, info.org].some((f) => str(f).toLowerCase().includes(q));
  }

  function upsertIP(info, opts) {
    const listEl = $('ip-list');
    let e = S.ips.get(info.ip);
    const isNew = !e;
    if (isNew) {
      if (!matchesQuery(info)) return;
      e = makeRow(info);
      S.ips.set(info.ip, e);
    } else {
      // Ignore stale updates (e.g. out-of-order geo message carrying older counters).
      const old = e.info;
      if ((old.last_seen || 0) > (info.last_seen || 0) && (old.count || 0) > (info.count || 0)) {
        info = Object.assign({}, info, { last_seen: old.last_seen, count: old.count, ai_count: old.ai_count,
          terminal_count: old.terminal_count, last_method: old.last_method, last_path: old.last_path, last_ua: old.last_ua });
      }
      e.info = info;
    }
    paintRow(e);
    e.el.hidden = !matchesQuery(info);
    if (isNew) {
      if (opts.move) listEl.prepend(e.el); else listEl.append(e.el);
      e.el.classList.add('new');
      setTimeout(() => e.el.classList.remove('new'), 1700);
      if (e.info.ip === S.selected) markSelected();
      trimRows();
    } else if (opts.move) {
      if (listEl.firstElementChild !== e.el) listEl.prepend(e.el);
      if (opts.flash) {
        e.el.classList.remove('flash');
        void e.el.offsetWidth; // restart animation
        e.el.classList.add('flash');
      }
    }
    if (isNew) renderListMeta();
  }

  function trimRows() {
    const listEl = $('ip-list');
    while (S.ips.size > MAX_ROWS) {
      let last = listEl.lastElementChild;
      if (last && last.dataset.ip === S.selected) last = last.previousElementSibling;
      if (!last) break;
      S.ips.delete(last.dataset.ip);
      last.remove();
    }
  }

  function applyClientFilter() {
    for (const e of S.ips.values()) e.el.hidden = !matchesQuery(e.info);
    renderListMeta();
  }

  function renderListMeta() {
    let visible = 0;
    for (const e of S.ips.values()) if (!e.el.hidden) visible++;
    $('ip-count').textContent = plural(visible, 'attacker') + (S.query ? ' matching' : '');
    const empty = visible === 0;
    $('list-empty').hidden = !empty;
    if (empty) {
      $('list-empty-t').textContent = S.query ? 'No matches' : 'No attackers yet';
      $('list-empty-s').textContent = S.query ? 'Nothing matches “' + S.query + '”.' : 'They usually show up within minutes.';
    }
    if (!S.selected) renderDetailEmpty();
  }

  function visibleRows() {
    return [...$('ip-list').children].filter((r) => !r.hidden);
  }

  function markSelected() {
    for (const e of S.ips.values()) {
      const sel = e.info.ip === S.selected;
      if (e.el.classList.contains('selected') !== sel) {
        e.el.classList.toggle('selected', sel);
        e.el.setAttribute('aria-selected', String(sel));
      }
    }
  }

  function moveSelection(delta) {
    const rows = visibleRows();
    if (!rows.length) return;
    let i = rows.findIndex((r) => r.dataset.ip === S.selected);
    i = i < 0 ? (delta > 0 ? 0 : rows.length - 1) : Math.max(0, Math.min(rows.length - 1, i + delta));
    const row = rows[i];
    selectIP(row.dataset.ip);
    row.scrollIntoView({ block: 'nearest' });
  }

  /* ------------------------------------------------------------------ detail / timeline */

  function ipFromHash() {
    const m = /^#\/ip\/(.+)$/.exec(location.hash);
    if (!m) return null;
    try { return decodeURIComponent(m[1]); } catch (_) { return null; }
  }

  function selectIP(ip, opts) {
    if (!ip) return;
    const same = S.selected === ip && S.tl && S.tl.ip === ip;
    S.selected = ip;
    markSelected();
    $('app').classList.add('detail-open');
    const want = '#/ip/' + encodeURIComponent(ip);
    if (location.hash !== want && !(opts && opts.fromHash)) history.replaceState(null, '', want);
    if (!same) loadTimeline(ip);
  }

  function deselect() {
    S.selected = null;
    S.tl = null;
    S.tlToken++;
    markSelected();
    $('app').classList.remove('detail-open');
    history.replaceState(null, '', location.pathname + location.search);
    renderDetailEmpty();
  }

  function renderDetailEmpty() {
    if (S.selected) return;
    const none = S.ips.size === 0 && !S.query;
    $('detail-body').hidden = true;
    $('empty-none').hidden = !none;
    $('empty-select').hidden = none;
  }

  function showDetailBody() {
    $('empty-none').hidden = true;
    $('empty-select').hidden = true;
    $('detail-body').hidden = false;
  }

  async function loadTimeline(ip, opts) {
    const token = ++S.tlToken;
    const keepOpen = opts && opts.keepOpen && S.tl && S.tl.ip === ip;
    const openIds = keepOpen ? [...S.tl.items.values()].filter((it) => it.el.classList.contains('open')).map((it) => it.ev.id) : [];
    showDetailBody();
    const tlEl = $('timeline');
    if (!keepOpen) {
      $('detail').scrollTop = 0;
      const cached = S.ips.get(ip);
      if (cached) renderHeader(cached.info); else $('ip-header').textContent = '';
      tlEl.textContent = '';
      for (let i = 0; i < 6; i++) tlEl.append(h('li', { class: 'tl-skel', style: 'opacity:' + (1 - i * 0.15) }));
      $('tl-count').textContent = '';
      $('load-older').hidden = true;
      $('tl-end').hidden = true;
    }
    S.tl = { ip, items: new Map(), minId: Infinity, more: false, loading: true, token };
    let data;
    try {
      data = await api('GET', '/ips/' + encodeURIComponent(ip) + '/events?limit=' + PAGE_SIZE);
    } catch (err) {
      if (token !== S.tlToken) return;
      S.tl.loading = false;
      tlEl.textContent = '';
      if (err.status === 404) {
        tlEl.append(h('li', { class: 'tl-empty', text: 'This IP is not in the database (maybe it was cleared).' }));
      } else {
        tlEl.append(h('li', { class: 'tl-empty', text: 'Failed to load events: ' + err.message }));
        reportError(err);
      }
      return;
    }
    if (token !== S.tlToken) return;
    if (data.ip && data.ip.ip) {
      renderHeader(data.ip);
      if (S.ips.has(data.ip.ip)) upsertIP(data.ip, { move: false });
    }
    tlEl.textContent = '';
    S.tl.loading = false;
    appendEvents(Array.isArray(data.events) ? data.events : [], !!data.more);
    for (const id of openIds) { const it = S.tl.items.get(id); if (it) toggleEvent(it, true); }
    if (!S.tl.items.size) tlEl.append(h('li', { class: 'tl-empty', text: 'No events recorded for this IP.' }));
  }

  function appendEvents(events, more) {
    const tl = S.tl;
    const frag = document.createDocumentFragment();
    for (const ev of events) {
      if (!ev || ev.id == null || tl.items.has(ev.id)) continue;
      const it = makeEvent(ev);
      tl.items.set(ev.id, it);
      frag.append(it.el);
      if (ev.id < tl.minId) tl.minId = ev.id;
    }
    $('timeline').append(frag);
    tl.more = more;
    renderTlMeta();
  }

  function renderTlMeta() {
    const tl = S.tl;
    if (!tl) return;
    const cached = S.ips.get(tl.ip);
    const total = cached ? cached.info.count : null;
    const n = tl.items.size;
    $('tl-count').textContent = total && total > n ? fmtNum(n) + ' of ' + plural(total, 'event') : plural(n, 'event');
    $('load-older').hidden = !tl.more;
    $('tl-end').hidden = tl.more || n === 0;
  }

  async function loadOlder() {
    const tl = S.tl;
    if (!tl || !tl.more || tl.loading || !isFinite(tl.minId)) return;
    tl.loading = true;
    const btn = $('load-older');
    btn.disabled = true;
    btn.textContent = 'Loading…';
    try {
      const data = await api('GET', '/ips/' + encodeURIComponent(tl.ip) + '/events?before=' + encodeURIComponent(tl.minId) + '&limit=' + PAGE_SIZE);
      if (S.tl !== tl) return;
      appendEvents(Array.isArray(data.events) ? data.events : [], !!data.more);
    } catch (err) {
      reportError(err);
    } finally {
      tl.loading = false;
      btn.disabled = false;
      btn.textContent = 'Load older events';
    }
  }

  function prependEvent(ev) {
    const tl = S.tl;
    if (!ev || ev.id == null || tl.items.has(ev.id)) return;
    const tlEl = $('timeline');
    const empty = tlEl.querySelector('.tl-empty');
    if (empty) empty.remove();
    const it = makeEvent(ev);
    tl.items.set(ev.id, it);
    if (ev.id < tl.minId) tl.minId = ev.id;
    it.el.classList.add('new');
    tlEl.prepend(it.el);
    setTimeout(() => it.el.classList.remove('new'), 2100);
    renderTlMeta();
  }

  /* header */

  let headerRefs = null;

  function refreshHeaderIf(info) {
    if (info && S.selected === info.ip && S.tl && S.tl.ip === info.ip) {
      renderHeader(S.ips.has(info.ip) ? S.ips.get(info.ip).info : info);
      renderTlMeta();
    }
  }

  function kv(label, value, opts) {
    const v = str(value);
    const valEl = h('div', { class: 'kv-v' + (opts && opts.mono ? ' mono' : '') + (v ? '' : ' dim'), title: v || null }, v || '-');
    if (opts && opts.sub) valEl.append(h('span', { class: 'kv-sub', text: opts.sub }));
    return h('div', { class: 'kv' }, h('div', { class: 'kv-k', text: label }), valEl);
  }

  function renderHeader(info) {
    const root = $('ip-header');
    const geoParts = info.geo === 'pending' ? [] : [info.city, info.region, info.country].filter(Boolean);
    const geoLine = info.geo === 'pending' ? 'Locating…'
      : info.geo === 'private' ? 'Private / loopback address'
        : geoParts.length ? geoParts.join(' · ') + (info.country_code ? ' (' + str(info.country_code).toUpperCase() + ')' : '')
          : 'Location unknown';
    const active = Date.now() - (info.last_seen || 0) < 120000;
    const flag = h('span', { class: 'iph-flag' });
    paintFlag(flag, info, 'iph-flag');
    const copyBtn = h('button', { type: 'button', class: 'btn btn-ghost btn-xs', title: 'Copy IP', 'aria-label': 'Copy IP' }, icon('copy'));
    copyBtn.addEventListener('click', () => copyText(str(info.ip), copyBtn));
    const backBtn = h('button', { type: 'button', class: 'btn btn-ghost btn-icon btn-sm iph-back', title: 'Back', 'aria-label': 'Back to list' }, icon('back'));
    backBtn.addEventListener('click', deselect);
    const status = h('span', { class: 'iph-status' + (active ? ' active' : '') },
      h('span', { class: 'live-dot', style: 'position:relative' }),
      active ? 'active · ' : 'last seen ', relEl('span', '', info.last_seen));

    const grid = h('div', { class: 'iph-grid' },
      kv('ISP', info.isp),
      kv('Organization', info.org),
      kv('ASN', info.asn, { mono: true }),
      kv('Region', [info.region, info.country].filter(Boolean).join(', ')),
      kv('First seen', fmtFull(info.first_seen), { mono: true }),
      kv('Last seen', fmtFull(info.last_seen), { mono: true }));

    const foot = h('div', { class: 'iph-foot' },
      h('span', { class: 'pill' }, h('b', { text: fmtNum(info.count || 0) }), (info.count === 1 ? 'request' : 'requests')),
      h('span', { class: 'pill pill-ai' }, h('b', { text: fmtNum(info.ai_count || 0) }), info.ai_count === 1 ? 'AI response' : 'AI responses'),
      h('span', { class: 'pill' }, h('b', { text: fmtNum(info.terminal_count || 0) }), info.terminal_count === 1 ? 'shell cmd' : 'shell cmds'),
      info.last_ua ? h('span', { class: 'iph-ua', title: str(info.last_ua) }, h('span', { text: 'UA' }), h('span', { text: str(info.last_ua) })) : null);

    root.textContent = '';
    root.append(
      h('div', { class: 'iph-top' },
        backBtn, flag,
        h('div', { class: 'iph-title' },
          h('div', { class: 'iph-ip' }, h('span', { class: 'ip-big', text: str(info.ip) }), copyBtn),
          h('div', { class: 'iph-geo' + (info.geo === 'pending' ? ' pending' : ''), text: geoLine })),
        status),
      grid, foot);
    headerRefs = { status };
  }

  /* event cards */

  function statusClass(code) {
    const c = Math.floor((code || 0) / 100);
    return 'status s' + (c >= 2 && c <= 5 ? c : 0);
  }

  function makeEvent(ev) {
    const kind = str(ev.kind) || 'http';
    const source = str(ev.source);
    const isTerm = kind === 'terminal';
    const chev = icon('chev', 'ev-chev');

    let req;
    if (isTerm) {
      req = h('span', { class: 'ev-req' },
        ev.cwd ? h('span', { class: 'ev-cwd', text: str(ev.cwd), title: str(ev.cwd) }) : h('span', { class: 'ev-cwd', text: '' }),
        h('span', { class: 'ev-path', text: str(ev.cmd), title: str(ev.cmd) }));
    } else {
      const m = str(ev.method).toUpperCase();
      req = h('span', { class: 'ev-req' },
        h('span', { class: 'ev-method m-' + m.toLowerCase().replace(/[^a-z]/g, ''), text: m }),
        h('span', { class: 'ev-path', text: str(ev.path), title: str(ev.path) }));
    }

    const meta = h('span', { class: 'ev-meta' },
      h('span', { class: 'ev-st' }, !isTerm && ev.status ? h('span', { class: statusClass(ev.status), text: String(ev.status), title: 'HTTP ' + ev.status + ' ' + (STATUS_TEXT[ev.status] || '') }) : null),
      h('span', { class: 'ev-src' }, source ? h('span', { class: 'src src-' + source.replace(/[^a-z]/g, ''), text: source, title: SOURCE_TITLE[source] || source }) : null),
      h('span', { class: 'ev-lat', text: fmtLat(ev.latency_ms), title: 'Response latency' }),
      relEl('span', 'ev-rel', ev.ts),
      chev);

    const head = h('button', { type: 'button', class: 'ev-head', 'aria-expanded': 'false' },
      h('span', { class: 'ev-time', title: new Date(ev.ts).toString() },
        h('span', { class: 't', text: fmtClock(ev.ts) }),
        h('span', { class: 'd', text: fmtDay(ev.ts) })),
      h('span', { class: 'ev-kind' }, h('span', { class: 'badge k-' + kind.replace(/[^a-z]/g, ''), text: kind === 'http' ? 'HTTP' : kind === 'terminal' ? 'TERMINAL' : kind.toUpperCase() })),
      req, meta);

    const body = h('div', { class: 'ev-body', hidden: true });
    const el = h('li', { class: 'ev ev-k-' + kind.replace(/[^a-z]/g, '') + ' ev-s-' + source.replace(/[^a-z]/g, '') },
      h('span', { class: 'ev-dot' }),
      h('div', { class: 'ev-card' }, head, body));

    const it = { ev, el, head, body, full: 'resp_headers' in ev || 'req_headers' in ev, built: false, tab: 'resp' };
    head.addEventListener('click', () => toggleEvent(it));
    return it;
  }

  const SOURCE_TITLE = {
    ai: 'Generated by the LLM',
    static: 'Built-in static response',
    disabled: 'AI disabled or no key, fallback response',
    ratelimited: 'Per-IP LLM rate limit hit, fallback response',
    error: 'LLM call failed, fallback response',
  };

  const STATUS_TEXT = {
    100: 'Continue', 101: 'Switching Protocols', 200: 'OK', 201: 'Created', 202: 'Accepted', 204: 'No Content',
    206: 'Partial Content', 301: 'Moved Permanently', 302: 'Found', 303: 'See Other', 304: 'Not Modified',
    307: 'Temporary Redirect', 308: 'Permanent Redirect', 400: 'Bad Request', 401: 'Unauthorized', 403: 'Forbidden',
    404: 'Not Found', 405: 'Method Not Allowed', 406: 'Not Acceptable', 408: 'Request Timeout', 409: 'Conflict',
    410: 'Gone', 411: 'Length Required', 413: 'Payload Too Large', 414: 'URI Too Long', 415: 'Unsupported Media Type',
    418: "I'm a teapot", 422: 'Unprocessable Entity', 429: 'Too Many Requests', 500: 'Internal Server Error',
    501: 'Not Implemented', 502: 'Bad Gateway', 503: 'Service Unavailable', 504: 'Gateway Timeout',
  };

  async function toggleEvent(it, forceOpen) {
    const open = forceOpen != null ? forceOpen : !it.el.classList.contains('open');
    it.el.classList.toggle('open', open);
    it.head.setAttribute('aria-expanded', String(open));
    it.body.hidden = !open;
    if (!open || it.built) return;
    if (!it.full) {
      it.body.textContent = '';
      it.body.append(h('div', { class: 'ev-loading' }, h('span', { class: 'spin' }), 'Loading full event…'));
      try {
        const full = await api('GET', '/events/' + encodeURIComponent(it.ev.id));
        it.ev = Object.assign({}, it.ev, full);
        it.full = true;
      } catch (err) {
        it.body.textContent = '';
        it.body.append(h('div', { class: 'ev-loading', text: 'Failed to load event: ' + err.message }));
        return;
      }
    }
    it.built = true;
    buildBody(it);
  }

  /** Header map {Name: [values]} → sorted [name, value] pairs. */
  function headerPairs(obj) {
    const out = [];
    if (!obj || typeof obj !== 'object') return out;
    for (const k of Object.keys(obj).sort((a, b) => a.localeCompare(b))) {
      const v = obj[k];
      for (const one of Array.isArray(v) ? v : [v]) out.push([k, str(one)]);
    }
    return out;
  }

  /** Builds a <pre> with highlighted first line + headers + (truncated) body. Returns { pre, raw, extra }. */
  function rawBlock(firstLine, headers, body) {
    const pre = h('pre', { class: 'raw' });
    const lines = [firstLine];
    pre.append(h('span', { class: 'rl', text: firstLine }), '\n');
    for (const [k, v] of headers) {
      pre.append(h('span', { class: 'hk', text: k + ':' }), ' ', h('span', { class: 'hv', text: v }), '\n');
      lines.push(k + ': ' + v);
    }
    const b = str(body);
    const raw = lines.join('\r\n') + '\r\n\r\n' + b;
    pre.append('\n');
    let extra = null;
    if (!b) {
      pre.append(h('span', { class: 'nobody', text: '(empty body)' }));
    } else if (b.length > BODY_LIMIT) {
      const bd = h('span', { class: 'bd', text: b.slice(0, BODY_LIMIT) });
      const tr = h('span', { class: 'trunc', text: '\n\n… ' + fmtNum(b.length - BODY_LIMIT) + ' more characters' });
      pre.append(bd, tr);
      extra = h('button', { type: 'button', class: 'btn btn-sm show-all', text: 'Show all (' + fmtBytes(b.length) + ')' });
      extra.addEventListener('click', () => {
        const full = bd.textContent.length < b.length;
        bd.textContent = full ? b : b.slice(0, BODY_LIMIT);
        tr.hidden = full;
        extra.textContent = full ? 'Collapse' : 'Show all (' + fmtBytes(b.length) + ')';
      });
    } else {
      pre.append(h('span', { class: 'bd', text: b }));
    }
    return { pre, raw, extra };
  }

  function requestRaw(ev) {
    const proto = str(ev.proto) || 'HTTP/1.1';
    const pairs = headerPairs(ev.req_headers);
    if (ev.host && !pairs.some(([k]) => k.toLowerCase() === 'host')) pairs.unshift(['Host', str(ev.host)]);
    else {
      const i = pairs.findIndex(([k]) => k.toLowerCase() === 'host');
      if (i > 0) pairs.unshift(pairs.splice(i, 1)[0]);
    }
    return rawBlock(str(ev.method) + ' ' + str(ev.path) + ' ' + proto, pairs, ev.req_body);
  }

  function responseRaw(ev) {
    const proto = str(ev.proto) || 'HTTP/1.1';
    const code = ev.status || 0;
    return rawBlock(proto + ' ' + code + (STATUS_TEXT[code] ? ' ' + STATUS_TEXT[code] : ''), headerPairs(ev.resp_headers), ev.resp_body);
  }

  function terminalBlock(ev) {
    const pre = h('pre', { class: 'raw term' });
    const cwd = str(ev.cwd) || '~';
    const out = str(ev.resp_body);
    pre.append(h('span', { class: 'p-cwd', text: cwd }), h('span', { class: 'p-sym', text: ' $ ' }), h('span', { class: 'p-cmd', text: str(ev.cmd) }), '\n');
    let extra = null;
    if (out.length > BODY_LIMIT) {
      const o = h('span', { class: 'out', text: out.slice(0, BODY_LIMIT) });
      pre.append(o, h('span', { class: 'trunc', text: '\n… truncated' }));
      extra = h('button', { type: 'button', class: 'btn btn-sm show-all', text: 'Show all (' + fmtBytes(out.length) + ')' });
      extra.addEventListener('click', () => { o.textContent = out; pre.lastChild.remove(); extra.remove(); });
    } else {
      pre.append(h('span', { class: 'out', text: out }));
    }
    return { pre, raw: cwd + ' $ ' + str(ev.cmd) + '\n' + out, extra };
  }

  function metaRow(ev) {
    const items = [];
    const add = (k, v) => { if (v !== '' && v != null) items.push(h('span', null, k, h('b', { text: str(v) }))); };
    add('id', ev.id);
    add('time', fmtFull(ev.ts));
    if (ev.kind !== 'terminal') add('url', (ev.scheme ? ev.scheme + '://' : '') + str(ev.host));
    add('model', ev.model);
    add('tokens', ev.tokens ? fmtNum(ev.tokens) : '');
    add('latency', fmtLat(ev.latency_ms));
    add('session', ev.session);
    if (ev.kind === 'terminal') add('ua', ev.user_agent);
    return h('div', { class: 'ev-metarow' }, items);
  }

  function buildBody(it) {
    const ev = it.ev;
    const body = it.body;
    body.textContent = '';
    if (ev.kind === 'terminal') {
      const t = terminalBlock(ev);
      const copy = h('button', { type: 'button', class: 'btn btn-ghost btn-xs', title: 'Copy transcript' }, icon('copy'), 'Copy');
      copy.addEventListener('click', (e) => { e.stopPropagation(); copyText(t.raw, copy); });
      body.append(
        h('div', { class: 'ev-tabs' }, h('button', { type: 'button', class: 'tab active', text: 'Transcript' }), h('span', { class: 'spacer' }), copy),
        h('div', { class: 'ev-pane' }, t.pre, t.extra ? h('div', { class: 'ev-pane-foot' }, t.extra) : null),
        metaRow(ev));
      return;
    }
    const panes = { req: requestRaw(ev), resp: responseRaw(ev) };
    const reqLen = str(ev.req_body).length, respLen = str(ev.resp_body).length;
    const tabs = {
      req: h('button', { type: 'button', class: 'tab', role: 'tab' }, 'Request', h('span', { class: 'tab-n', text: reqLen ? fmtBytes(reqLen) : '' })),
      resp: h('button', { type: 'button', class: 'tab', role: 'tab' }, 'Response', h('span', { class: 'tab-n', text: respLen ? fmtBytes(respLen) : '' })),
    };
    const paneEl = h('div', { class: 'ev-pane' });
    const copy = h('button', { type: 'button', class: 'btn btn-ghost btn-xs', title: 'Copy raw' }, icon('copy'), 'Copy raw');
    const show = (which) => {
      it.tab = which;
      tabs.req.classList.toggle('active', which === 'req');
      tabs.resp.classList.toggle('active', which === 'resp');
      tabs.req.setAttribute('aria-selected', String(which === 'req'));
      tabs.resp.setAttribute('aria-selected', String(which === 'resp'));
      paneEl.textContent = '';
      const p = panes[which];
      paneEl.append(p.pre);
      if (p.extra) paneEl.append(h('div', { class: 'ev-pane-foot' }, p.extra));
    };
    tabs.req.addEventListener('click', () => show('req'));
    tabs.resp.addEventListener('click', () => show('resp'));
    copy.addEventListener('click', () => copyText(panes[it.tab].raw, copy));
    body.append(
      h('div', { class: 'ev-tabs', role: 'tablist' }, tabs.req, tabs.resp, h('span', { class: 'spacer' }), copy),
      paneEl,
      metaRow(ev));
    show('req');
  }

  /* ------------------------------------------------------------------ tickers */

  function tick() {
    if (!S.authed || document.hidden) return;
    const now = Date.now();
    for (const el of document.querySelectorAll('[data-ts]')) {
      const ts = +el.dataset.ts;
      if (!ts) continue;
      // Old timestamps change at most once a minute; skip most work for them.
      const age = now - ts;
      if (age > 3600000 && (now / 1000 | 0) % 30 !== 0) continue;
      const t = fmtRel(ts);
      if (el.textContent !== t) el.textContent = t;
    }
    for (const e of S.ips.values()) {
      const recent = now - (e.info.last_seen || 0) < 60000;
      if (e.el.classList.contains('recent') !== recent) e.el.classList.toggle('recent', recent);
    }
    if (headerRefs && headerRefs.status && S.selected && S.ips.has(S.selected)) {
      const info = S.ips.get(S.selected).info;
      const active = now - (info.last_seen || 0) < 120000;
      if (headerRefs.status.classList.contains('active') !== active) renderHeader(info);
    }
  }

  /* ------------------------------------------------------------------ events wiring */

  let searchTimer = null;

  function bindStatic() {
    $('auth-form').addEventListener('submit', onAuthSubmit);
    $('ai-switch').addEventListener('click', toggleAI);
    $('ai-state').addEventListener('click', () => { if ($('ai-toggle').dataset.state === 'warn') openSettings(); });
    $('btn-settings').addEventListener('click', openSettings);
    $('btn-clear').addEventListener('click', openClear);
    $('btn-logout').addEventListener('click', logout);
    $('load-older').addEventListener('click', loadOlder);
    $('copy-curl').addEventListener('click', () => copyText($('curl-hint').textContent, $('copy-curl')));

    $('ip-list').addEventListener('click', (e) => {
      const row = e.target.closest('.ip-row');
      if (row) selectIP(row.dataset.ip);
    });

    $('search').addEventListener('input', () => {
      S.query = $('search').value.trim();
      applyClientFilter();
      clearTimeout(searchTimer);
      searchTimer = setTimeout(() => loadIPs().catch(reportError), 250);
    });
    $('search').addEventListener('keydown', (e) => {
      if (e.key === 'Escape') {
        e.stopPropagation();
        if ($('search').value) { $('search').value = ''; $('search').dispatchEvent(new Event('input')); }
        else $('search').blur();
      } else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        e.preventDefault();
        moveSelection(e.key === 'ArrowDown' ? 1 : -1);
      } else if (e.key === 'Enter') {
        const rows = visibleRows();
        if (rows.length && !rows.some((r) => r.dataset.ip === S.selected)) selectIP(rows[0].dataset.ip);
        $('search').blur();
      }
    });

    // modals
    for (const el of document.querySelectorAll('[data-close]')) el.addEventListener('click', closeModals);
    $('settings-save').addEventListener('click', onSaveSettings);
    $('settings-form').addEventListener('submit', (e) => { e.preventDefault(); onSaveSettings(); });
    $('set-test').addEventListener('click', testConnection);
    $('set-key-clear').addEventListener('click', () => { keyClear = !keyClear; $('set-key').value = ''; fillSettingsStatic(); });
    $('set-key').addEventListener('input', () => { if ($('set-key').value && keyClear) { keyClear = false; fillSettingsStatic(); } });
    $('pw-save').addEventListener('click', changePassword);
    $('pw-new').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); changePassword(); } });
    $('clear-input').addEventListener('input', () => { $('clear-confirm').disabled = $('clear-input').value.trim().toLowerCase() !== 'clear'; });
    $('clear-input').addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); doClear(); } });
    $('clear-confirm').addEventListener('click', doClear);

    // global keys
    document.addEventListener('keydown', (e) => {
      if (!S.authed || $('app').hidden) return;
      if (e.key === 'Escape') {
        if (closeModals()) { e.preventDefault(); return; }
        if (window.matchMedia('(max-width: 860px)').matches && S.selected) deselect();
        return;
      }
      if (anyModalOpen()) return;
      const t = e.target;
      const typing = t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.isContentEditable);
      if (typing || e.metaKey || e.ctrlKey || e.altKey) return;
      if (e.key === '/') { e.preventDefault(); $('search').focus(); $('search').select(); }
      else if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
        // Let arrows scroll the timeline if focus is inside it.
        if (t && t.closest && t.closest('.detail') && t !== document.body) return;
        e.preventDefault();
        moveSelection(e.key === 'ArrowDown' ? 1 : -1);
      }
    });

    window.addEventListener('hashchange', () => {
      const ip = ipFromHash();
      if (ip && ip !== S.selected && S.authed) selectIP(ip, { fromHash: true });
    });

    document.addEventListener('visibilitychange', () => {
      if (!document.hidden && S.authed) { tick(); loadStats().catch(() => {}); }
    });

    // Infinite scroll for older events.
    if ('IntersectionObserver' in window) {
      const io = new IntersectionObserver((entries) => {
        if (entries.some((en) => en.isIntersecting) && S.tl && S.tl.more && !S.tl.loading) loadOlder();
      }, { root: $('detail'), rootMargin: '0px 0px 400px 0px' });
      io.observe($('tl-foot'));
    }

    setInterval(tick, 1000);
  }

  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', boot);
  else boot();
})();
