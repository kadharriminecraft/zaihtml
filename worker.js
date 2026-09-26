/* ============================================================
 * z.ai pocket — Cloudflare Worker relay (v5)
 * ------------------------------------------------------------
 * WHAT THIS DOES (v5 — the "no-navigation" architecture)
 *   The phone's browser NEVER opens this worker as a web page.
 *   The saved pocket file (zai-pocket.html) is the app shell: it
 *   FETCHES every document, script, stylesheet and API call
 *   through this worker with plain CORS fetch() — nothing ever
 *   navigates to the worker origin — and paints the app inside a
 *   locked null-origin sandbox frame in the file itself.
 *   Organization web filters intercept NAVIGATIONS (that is the
 *   "blocked by your organization" page); fetch() calls from a
 *   saved local file sail past them. This is the same concept the
 *   Relay "super worker" uses, rebuilt custom for z.ai.
 *
 *   On top of that, the worker's own root serves only a small
 *   neutral status page — never z.ai content — so the hostname
 *   can never be content-classified as an AI-chatbot site, and
 *   every upstream URL stays an opaque /__t/<token> (v4 scheme).
 *
 * HISTORY
 *   v3 — dropped Cloudflare-edge headers before forwarding (WAF
 *        bait), added the one-shot 403/429 clean retry, /__diag.
 *   v4 — opaque tokens for every cross-host URL in HTML/CSS/
 *        redirects/runtime mapping: no readable upstream hostname
 *        in any request the phone makes.
 *   v5 — THE BIG ONE: sandbox-first serving. (1) Root and every
 *        bare path answer a neutral page/JSON — the transparent
 *        chat.z.ai catch-all is GONE, so nothing at this origin
 *        looks like z.ai to a classifier. (2) Documents served
 *        through /__t/<token> now carry cfg.sd (sandbox mode):
 *        the injected runtime patch boots a fake location object
 *        (__zaiLoc) whose reads report the REAL upstream URL and
 *        whose writes postMessage the shell instead of navigating
 *        the frame. (3) Served JavaScript gets a conservative
 *        location-assignment rewrite (location.href = X →
 *        __zaiLoc.href = X etc.) so SPA redirects never navigate
 *        the sandbox frame. (4) /__status gains "entry": the
 *        tokenized root-document path, so the pocket file can
 *        boot the app without knowing the token key.
 *
 * DEPLOY (you already have a worker)
 *   1. dash.cloudflare.com → Workers & Pages → your worker
 *   2. "Edit code" / Quick Edit → select all → paste this file
 *   3. Save & Deploy
 *   4. (optional) Settings → Variables → PROXY_TOKEN with a long
 *      random string, and/or EXTRA_HOSTS="a.com,b.com" to
 *      allowlist more first-party hosts.
 *   5. Save the new zai-pocket.html on the phone and use its
 *      "Open Z.ai (sandboxed)" button — the app streams into the
 *      file through this worker. Do NOT open the worker URL in
 *      the browser; it is only a relay now.
 *
 * ROUTES
 *   /            -> neutral service page (token setup form when
 *                   PROXY_TOKEN is set). NEVER z.ai content.
 *   /__t/<token> -> https://<upstream-url>   the ONLY content
 *                   route: opaque token = absolute upstream URL
 *                   XOR-encrypted + base64url'd. CORS-open for
 *                   every origin (the pocket file fetches it),
 *                   every method, cookies relayed via x-set-cookie
 *                   + x-cookie, final URL reported as x-final-url.
 *   /__status    -> health-check JSON + "entry" (the tokenized
 *                   root document path — the pocket file's app
 *                   boot handle). Neutral: no z.ai strings.
 *   /__diag      -> live upstream probe report (three probes,
 *                   plain-English verdict).
 *   /__clear     -> expire session cookies, back to /
 *   /favicon.ico -> 204 (neutral — never a proxied page)
 *   /p/<host>/*  -> legacy v3 form, still accepted for stale
 *                   caches, never emitted.
 *   anything else (bare path) -> neutral 404 JSON. The transparent
 *                   chat.z.ai mirroring is GONE in v5: the phone
 *                   never navigates here, so it serves nothing.
 *
 * SECURITY
 *   - Only z.ai / chatglm.cn / chatglm.site family hosts are
 *     proxied. This is NOT an open proxy.
 *   - With PROXY_TOKEN set, everything except the token page,
 *     /__status and /__diag requires the token.
 *   - Upstream set-cookies are relayed to the sandbox runtime via
 *     the CORS-exposed x-set-cookie header; the runtime replays
 *     them as x-cookie. Nothing is stored at this origin.
 * ============================================================ */

const VERSION = 'zp service 5.0';

/* z.ai first-party family (suffix match — covers subdomains) */
const ALLOW = [
  'z.ai',               // chat.z.ai, zcode.z.ai, *.space-z.ai sandboxes, ...
  'chatglm.cn',         // z-cdn.chatglm.cn (frontend assets), z-cdn-media, cdn-proxy, sdata
  'chatglm.site',       // artifacts-cdn, adapter-prod, test envs
  'glm-chat.oss-cn-hongkong.aliyuncs.com', // file upload/download bucket
  'alicdn.com',         // o.alicdn.com — z.ai's shared frontend libs (jquery …)
  'aliyuncs.com'        // sdk.rum / log endpoints the z.ai frontend loads at boot
];

/* ---- v4: opaque request tokens ----------------------------------------
 * Every upstream URL this worker embeds in a response (attr values,
 * css url()s, redirect Locations) and every cross-host URL the
 * runtime patch maps in the browser is XOR-obfuscated + base64url'd
 * as /__t/<token> so NO upstream hostname (z.ai, chatglm.cn,
 * alicdn …) is ever readable in a request the phone makes.
 * Organization content filters decode query strings and paths and
 * category-block those hosts even though the request already flows
 * through this worker — opaque tokens end that. The key is shared
 * with the runtime patch via window.__ZAI__.key (build asserts the
 * template carries exactly one TOK_KEY definition). ?url= is NOT
 * accepted: tokens are the only way in. */
const TOK_KEY = 'zaiwtok-4-0-0-K9mVx2qT';

function encTok(u) {
  const bytes = new TextEncoder().encode(String(u));
  let s = '';
  for (let i = 0; i < bytes.length; i++) {
    s += String.fromCharCode(bytes[i] ^ TOK_KEY.charCodeAt(i % TOK_KEY.length));
  }
  return btoa(s).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
}

function decTok(t) {
  try {
    const s = atob(String(t || '').replace(/-/g, '+').replace(/_/g, '/').trim());
    const bytes = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) {
      bytes[i] = s.charCodeAt(i) ^ TOK_KEY.charCodeAt(i % TOK_KEY.length);
    }
    return new TextDecoder().decode(bytes);
  } catch (e) { return null; }
}

function tokPath(absUrl) {
  try { return '/__t/' + encTok(absUrl); } catch (e) { return null; }
}

/* upstream origin for the /chat route (env CHAT_UPSTREAM overrides, e.g. for staging) */
function chatUpstream(event) { return envOf(event).CHAT_UPSTREAM || 'https://chat.z.ai'; }
function chatHost(event) {
  try { return new URL(chatUpstream(event)).host; } catch (e) { return 'chat.z.ai'; }
}

/* markers filled by the build script */
const PATCH_JS = [
"/* ============================================================",
" * z.ai pocket \u2014 runtime patch (v4)",
" * Injected by the proxy worker into every proxied HTML document",
" * as the FIRST script inside <head>. It rewrites every network",
" * call, navigation and popup so the SPA believes it lives on its",
" * real origin while every byte actually flows through the worker.",
" *",
" * v4 \u2014 OPAQUE TOKENS: every cross-host URL mapped here becomes",
" * /__t/<gibberish> (the absolute upstream URL XOR-encrypted +",
" * base64url'd with the key the worker injected as __ZAI__.key).",
" * NO request the browser makes carries a readable upstream",
" * hostname \u2014 organization content filters read URLs and",
" * category-block z.ai / chatglm / alicdn hosts, which is what",
" * killed the /p/<host>/\u2026 form this patch used to emit.",
" *",
" * NOTE: this source is embedded inside a <script> tag in proxied",
" * pages, so it must never contain the literal sequence \"</scr\" +",
" * \"ipt>\" \u2014 keep it that way.",
" * ============================================================ */",
"(function () {",
"  'use strict';",
"  if (window.__ZAI_PATCHED__) return;",
"  window.__ZAI_PATCHED__ = true;",
"",
"  var CFG = window.__ZAI__ || {};",
"  var PFX = CFG.pfx || '';            // proxy prefix for this document, '' = transparent root",
"  var HOST = (CFG.host || '').toLowerCase(); // upstream host this document belongs to",
"  var WORKER = CFG.worker || '';      // worker origin, e.g. https://name.workers.dev",
"  var TOKEN = CFG.token || '';        // optional shared proxy token",
"  var ALLOW = CFG.allow || [];        // allowlisted host suffixes",
"  var KEY = CFG.key || '';            // v4 opaque-token key (shared with the worker)",
"  var TOK = !!CFG.tok;                // true when this doc was served through /__t/<token>",
"  var DOC = CFG.doc || '';            // that token's absolute upstream URL (TOK mode)",
"  var SD = !!CFG.sd;                  // v5: sandbox mode \u2014 this document is being",
"                                      // painted into a null-origin srcdoc frame by",
"                                      // the pocket shell. NEVER navigate: every",
"                                      // destination goes to the shell by postMessage.",
"",
"  var jar = [];                       // fallback cookie jar (mirrored by the shell)",
"  var lsMirror = {};                  // fallback localStorage mirror (for browsers that block it in iframes)",
"  var upQueue = [];",
"",
"  /* ---------- v5: absolute worker URLs --------------------------------",
"   * Inside the sandbox frame the document sits at about:srcdoc, so a",
"   * mapped path like /__t/<token> is unresolvable on its own \u2014 it must",
"   * be absolutized against the worker origin for fetch/XHR/ES/beacons. */",
"  function absW(p) {",
"    try {",
"      if (!SD || typeof p !== 'string' || !/^\\//.test(p)) return p;",
"      return WORKER.replace(/\\/$/, '') + p;",
"    } catch (e) { return p; }",
"  }",
"",
"  /* ---------- v5: is this URL the WORKER's own (already proxied)? ------",
"   * The worker rewrites HTML attrs into ABSOLUTE worker URLs",
"   * (https://worker/__t/\u2026). Those are NOT \"external\" \u2014 but the",
"   * allowlist only knows upstream hosts, so every nav branch must",
"   * recognize worker-origin URLs FIRST or it would eat them as",
"   * outside-the-proxy links (the auto-submit E2E caught exactly that:",
"   * a rewritten form action dropped as \"external\"). */",
"  function isWorkerUrl(u) {",
"    try {",
"      if (!SD || !WORKER) return false;",
"      var s = String(u || '');",
"      var w = WORKER.replace(/\\/$/, '');",
"      return s === w || s.indexOf(w + '/') === 0 || s.indexOf(w.replace(/^http/, 'ws')) === 0;",
"    } catch (e) { return false; }",
"  }",
"",
"  /* ---------- v5: navigation request to the shell ---------------------",
"   * nav(u) sends the shell everything it needs to re-render the app at",
"   * a new URL as a FRESH sandboxed document: the worker path to fetch",
"   * (tokenized here \u2014 the shell has no key) and the upstream URL for",
"   * its address bar / history entry. POST navigations (form submits)",
"   * carry method/body/content-type too. */",
"  function nav(u, method, body, ct) {",
"    try {",
"      var s = (u == null) ? '' : String(u);",
"      var mapped = mapUrl(s);",
"      var upUrl = '';",
"      try { upUrl = new URL(s, DOC || location.href).href; } catch (eU) { upUrl = s; }",
"      up({ type: 'navreq', url: mapped, up: upUrl, method: method || 'GET', body: body || null, ct: ct || null });",
"      return s;",
"    } catch (e) { return u; }",
"  }",
"",
"  /* ---------- v5: fake location (window.__zaiLoc) ---------------------",
"   * The worker's JS pass rewrites location.<prop> tokens in served",
"   * scripts to __zaiLoc.<prop>. Reads answer the REAL upstream URL",
"   * (SPA routers hydrate as if the page lived at chat.z.ai); the href",
"   * setter (and assign/replace/reload) turn navigations into nav()",
"   * postMessages instead of steering the sandbox frame anywhere. */",
"  function makeLoc() {",
"    var u = null;",
"    try { u = DOC ? new URL(DOC) : null; } catch (e) { u = null; }",
"    function prop(name, fb) {",
"      try { return u ? u[name] : fb; } catch (e) { return fb; }",
"    }",
"    var loc = {};",
"    Object.defineProperty(loc, 'href', {",
"      get: function () { return u ? u.href : (DOC || 'about:srcdoc'); },",
"      set: function (v) { nav(v); return v; },",
"      configurable: true",
"    });",
"    loc.assign = function (v) { nav(v); };",
"    loc.replace = function (v) { nav(v); };",
"    loc.reload = function () { up({ type: 'reloadreq' }); };",
"    loc.toString = function () { return u ? u.href : (DOC || 'about:srcdoc'); };",
"    ['origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash'].forEach(function (k) {",
"      try {",
"        Object.defineProperty(loc, k, {",
"          get: function () {",
"            if (!u) return k === 'origin' || k === 'host' || k === 'hostname' ? '' : (k === 'protocol' ? 'https:' : (k === 'pathname' ? '/' : ''));",
"            return u[k];",
"          },",
"          configurable: true",
"        });",
"      } catch (e) { /* ignore */ }",
"    });",
"    return loc;",
"  }",
"  if (SD) {",
"    try { window.__zaiLoc = makeLoc(); } catch (eL) { /* ignore */ }",
"    /* document.URL / baseURI / documentURI \u2014 the parser reports",
"     * about:srcdoc; SPA hydration wants the real upstream URL. These",
"     * are plain accessors on Document.prototype (NOT unforgeable),",
"     * so they can be re-pointed at the upstream doc URL. */",
"    try {",
"      ['URL', 'baseURI', 'documentURI'].forEach(function (k) {",
"        Object.defineProperty(Document.prototype, k, {",
"          get: function () { return DOC || 'about:srcdoc'; },",
"          configurable: true",
"        });",
"      });",
"    } catch (eD) { /* ignore */ }",
"  }",
"",
"  /* ---------- v5: window.name boot hydration --------------------------",
"   * The shell stamps the frame's name with a snapshot {zp:1, ls, jar}",
"   * BEFORE assigning the srcdoc \u2014 it is readable synchronously here,",
"   * so the app's own scripts (which run after this patch) find their",
"   * session cookies and localStorage already populated. No race. */",
"  try {",
"    if (SD && window.name) {",
"      var boot = JSON.parse(window.name);",
"      if (boot && boot.zp === 1) {",
"        if (boot.ls && typeof boot.ls === 'object') {",
"          Object.keys(boot.ls).forEach(function (k) { if (!(k in lsMirror)) lsMirror[k] = String(boot.ls[k]); });",
"        }",
"        if (Array.isArray(boot.jar)) {",
"          var jarMap = {};",
"          jar.forEach(function (c) { if (c && c.name) jarMap[c.name] = c; });",
"          boot.jar.forEach(function (c) { if (c && c.name) jarMap[c.name] = c; });",
"          jar = Object.keys(jarMap).map(function (k) { return jarMap[k]; });",
"        }",
"      }",
"    }",
"  } catch (eN) { /* ignore */ }",
"",
"  /* ---------- messaging ---------- */",
"  function up(msg) {",
"    try {",
"      msg.zai = 1;",
"      if (window.parent && window.parent !== window) window.parent.postMessage(msg, '*');",
"    } catch (e) { /* ignore */ }",
"  }",
"",
"  /* ---------- on-page toast (top-level mode: no shell above us) ---------- */",
"  var toastCount = 0;",
"  function pageToast(msg) {",
"    try {",
"      if (window.parent && window.parent !== window) return; // shell handles messages",
"      if (toastCount >= 4) return;",
"      toastCount++;",
"      var d = document.createElement('div');",
"      d.textContent = msg;",
"      d.setAttribute('style', 'position:fixed;left:12px;right:12px;bottom:max(18px,env(safe-area-inset-bottom));z-index:2147483647;background:#20232F;color:#E7E9EE;border:1px solid rgba(255,255,255,.16);border-radius:14px;padding:13px 15px;font:13px/1.5 -apple-system,BlinkMacSystemFont,system-ui,\"Segoe UI\",Roboto,sans-serif;box-shadow:0 12px 32px rgba(0,0,0,.45);word-break:break-all;opacity:0;transition:opacity .25s;pointer-events:none');",
"      (document.body || document.documentElement).appendChild(d);",
"      var raf = window.requestAnimationFrame || function (f) { setTimeout(f, 16); };",
"      raf(function () { d.style.opacity = '1'; });",
"      setTimeout(function () {",
"        try { d.style.opacity = '0'; setTimeout(function () { d.remove(); }, 300); } catch (e) { /* ignore */ }",
"      }, 4500);",
"    } catch (e) { /* ignore */ }",
"  }",
"",
"  /* ---------- host matching ---------- */",
"  function allowedHost(h) {",
"    h = (h || '').toLowerCase().replace(/\\.$/, '');",
"    if (!h) return false;",
"    for (var i = 0; i < ALLOW.length; i++) {",
"      var a = String(ALLOW[i]).toLowerCase();",
"      if (h === a || h.slice(-(a.length + 1)) === '.' + a) return true;",
"    }",
"    return false;",
"  }",
"",
"  /* ---------- v4 opaque tokens (mirror of the worker's encTok) ---------- */",
"  function encTok(u) {",
"    try {",
"      if (!KEY) return null;",
"      var bytes = new TextEncoder().encode(String(u));",
"      var s = '';",
"      for (var i = 0; i < bytes.length; i++) {",
"        s += String.fromCharCode(bytes[i] ^ KEY.charCodeAt(i % KEY.length));",
"      }",
"      return btoa(s).replace(/\\+/g, '-').replace(/\\//g, '_').replace(/=+$/, '');",
"    } catch (e) { return null; }",
"  }",
"  function tokPath(absUrl) {",
"    var t = encTok(absUrl);",
"    return t ? '/__t/' + t : null;",
"  }",
"",
"  /* ---------- proxy-path bookkeeping ----------",
"   * Guards against double-prefixing and recognises URLs that already",
"   * point at the worker (same-origin) instead of the upstream host.",
"   */",
"  function originStr() {",
"    try { return location.origin || (location.protocol + '//' + location.host); } catch (e) { return ''; }",
"  }",
"  function hasPfx(str) {",
"    if (!PFX) return true;",
"    if (str === PFX) return true;",
"    return str.indexOf(PFX) === 0 && /^[\\/?#;]/.test(str.charAt(PFX.length));",
"  }",
"  function isCrossHostPath(str) { // \"/p/<allowlisted host>/\u2026\"",
"    if (/^\\/p\\//.test(str)) {",
"      var h = str.slice(3).split(/[\\/?#]/)[0].toLowerCase();",
"      if (allowedHost(h)) return true;",
"    }",
"    return false;",
"  }",
"  function isProxyPath(p) {",
"    if (!p) return false;",
"    if (hasPfx(p)) return true;",
"    if (isCrossHostPath(p)) return true;",
"    if (/^\\/__t\\//.test(p)) return true; // v4 opaque token path",
"    if (/^\\/__(status|clear)([\\/?#]|$)/.test(p)) return true;",
"    return false;",
"  }",
"",
"  /* ---------- URL mapping (v4: opaque tokens for cross-host URLs) ----------",
"   * absolute / protocol-relative allowlisted URLs -> /__t/<token>",
"   * same-host (chat) absolute URLs -> bare worker paths (no hostname)",
"   * root-absolute paths -> PFX + path  (they belong to this doc's upstream host)",
"   * relative / data: / blob: / #...   -> untouched",
"   * TOK mode (doc served through /__t/<token>): every reference is",
"   *   absolutized against DOC and tokenized \u2014 there is no prefix to",
"   *   re-attach inside a token document.",
"   */",
"  function mapUrl(u) {",
"    /* v5 sandbox wrapper: every mapped worker path becomes ABSOLUTE",
"     * (https://worker/__t/\u2026) because about:srcdoc has no base to",
"     * resolve \"/__t/\u2026\" against \u2014 DOM attributes, CSS url() text, fetch",
"     * URLs and nav postMessages all need the absolute form. absW() is",
"     * idempotent, and in non-sandbox mode it is a no-op. */",
"    return absW(mapUrl0(u));",
"  }",
"",
"  function mapUrl0(u) {",
"    try {",
"      if (u == null) return u;",
"      if (typeof u === 'object' && u instanceof URL) {",
"        var s0 = mapUrl(u.href);",
"        return s0;",
"      }",
"      if (typeof u !== 'string') return u;",
"      var str = u.trim();",
"      if (!str) return str;",
"      if (/^(data|blob|about|javascript|mailto|tel|sms|intent|ms-|chrome|file|ws|wss):/i.test(str)) {",
"        // wss/ws handled by the WebSocket wrapper below; here pass through",
"        return str;",
"      }",
"      if (str.charAt(0) === '#') return str;",
"      var m;",
"      if ((m = str.match(/^https?:\\/\\/([^\\/?#]+)/i))) {",
"        var host = m[1].toLowerCase();",
"        var org = originStr();",
"        if (org && (str === org || str.indexOf(org + '/') === 0)) {",
"          // same-origin (worker) absolute URL \u2014 either already proxied",
"          // (\"/\u2026\", \"/p/host/\u2026\", \"/__t/\u2026\") or a bare worker-root path that",
"          // still belongs to this document's upstream",
"          var sp = str.slice(org.length) || '/';",
"          if (isProxyPath(sp)) return sp;",
"          return PFX + sp;",
"        }",
"        if (!allowedHost(host)) return str;                    // external: leave (usually analytics)",
"        if (host === HOST && !TOK) {",
"          var rest = str.slice(m[0].length) || '/';",
"          return PFX + rest;                                    // chat host: bare worker path",
"        }",
"        var t1 = tokPath(str);                                 // everything else: opaque token",
"        if (t1) return t1;",
"        return '/p/' + host + (str.slice(m[0].length) || '/'); // keyless legacy fallback",
"      }",
"      if ((m = str.match(/^\\/\\/([^\\/?#]+)/))) {",
"        var h2 = m[1].toLowerCase();",
"        if (!allowedHost(h2)) return str;",
"        if (h2 === HOST && !TOK) {",
"          var rest2 = str.slice(m[0].length) || '/';",
"          return PFX + rest2;",
"        }",
"        var t2 = tokPath('https:' + str);",
"        if (t2) return t2;",
"        return '/p/' + h2 + (str.slice(m[0].length) || '/');",
"      }",
"      if (str.charAt(0) === '/' && str.charAt(1) !== '/') {",
"        /* v5 order fix: in TOK mode there IS no prefix to carry \u2014 a",
"         * root-absolute path belongs to the DOC's upstream and MUST be",
"         * absolutized + tokenized. But the EXPLICIT already-proxied",
"         * forms (a token path the worker rewrote into an attr, a legacy",
"         * /p/<host>/ path, a worker meta route) pass through untouched \u2014",
"         * hasPfx() alone would swallow EVERYTHING when PFX is ''. */",
"        if (TOK && DOC) {",
"          if (/^\\/__t\\//.test(str)) return str;",
"          if (isCrossHostPath(str)) return str;",
"          if (/^\\/__(status|clear|diag)([\\/?#]|$)/.test(str)) return str;",
"          try {",
"            var t3 = tokPath(new URL(str, DOC).href);",
"            if (t3) return t3;",
"          } catch (e3) { /* fall through */ }",
"        }",
"        if (hasPfx(str)) return str;          // already carries this doc's proxy prefix",
"        if (isCrossHostPath(str)) return str; // already a legacy /p/<host>/ proxy path",
"        if (/^\\/__t\\//.test(str)) return str; // already an opaque token path",
"        return PFX + str;",
"      }",
"      if (TOK && DOC && !/^[a-z][a-z0-9+.-]*:/i.test(str)) {",
"        try {",
"          var t4 = tokPath(new URL(str, DOC).href);",
"          if (t4) return t4;",
"        } catch (e4) { /* fall through */ }",
"      }",
"      return str; // relative \u2192 resolves against the proxied document URL",
"    } catch (e) { return u; }",
"  }",
"",
"  /* ---------- cookies ---------- */",
"  function docCookies() {",
"    var out = [];",
"    if (SD) {",
"      /* v5 sandbox: document.cookie is shimmed to the memory jar below \u2014",
"       * reads come from the jar (seeded from window.name at boot and",
"       * refreshed by x-set-cookie on every proxied response). */",
"      jar.forEach(function (c) { if (c && c.name && !c.del) out.push(c.name + '=' + c.value); });",
"      return out;",
"    }",
"    try {",
"      (document.cookie || '').split(';').forEach(function (kv) {",
"        kv = kv.trim();",
"        if (kv) out.push(kv);",
"      });",
"    } catch (e) { /* ignore */ }",
"    return out;",
"  }",
"",
"  function cookieHeader() {",
"    var seen = {};",
"    var parts = [];",
"    docCookies().forEach(function (kv) {",
"      var name = kv.split('=')[0];",
"      if (!seen[name]) { seen[name] = 1; parts.push(kv); }",
"    });",
"    jar.forEach(function (c) {",
"      if (c && c.name && !seen[c.name]) { seen[c.name] = 1; parts.push(c.name + '=' + c.value); }",
"    });",
"    return parts.join('; ');",
"  }",
"",
"  function ingestSetCookie(hdrVal) {",
"    try {",
"      if (!hdrVal) return;",
"      var arr = JSON.parse(decodeURIComponent(hdrVal));",
"      if (!Array.isArray(arr)) return;",
"      var map = {};",
"      jar.forEach(function (c) { map[c.name] = c; });",
"      arr.forEach(function (raw) {",
"        var bits = String(raw).split(';');",
"        var nv = bits[0];",
"        var eq = nv.indexOf('=');",
"        if (eq < 1) return;",
"        var c = { name: nv.slice(0, eq).trim(), value: nv.slice(eq + 1).trim() };",
"        for (var i = 1; i < bits.length; i++) {",
"          var b = bits[i].trim();",
"          var k = b.split('=')[0].toLowerCase();",
"          if (k === 'max-age') {",
"            var ma = parseInt(b.slice(8), 10);",
"            if (ma === 0) { c.del = true; }",
"            c.maxAge = ma;",
"          }",
"        }",
"        if (c.del) delete map[c.name];",
"        else map[c.name] = c;",
"      });",
"      jar = [];",
"      Object.keys(map).forEach(function (k) { jar.push(map[k]); });",
"      up({ type: 'cookies', cookies: jar });",
"    } catch (e) { /* ignore */ }",
"  }",
"",
"  function seedDocumentCookies() {",
"    if (SD) return; /* v5 sandbox: cookies live in the memory jar only */",
"    jar.forEach(function (c) {",
"      try {",
"        document.cookie = c.name + '=' + c.value + '; path=/; Max-Age=31536000; Secure; SameSite=None; Partitioned';",
"      } catch (e) { /* ignore */ }",
"    });",
"  }",
"",
"  /* ---------- v5: document.cookie shim (sandbox mode) -----------------",
"   * In a null-origin srcdoc frame real cookie writes go nowhere (and",
"   * reads can throw on some engines). The instance property is",
"   * shadowed with an in-memory jar view: reads join the jar, writes",
"   * merge into it and are echoed to the shell so the session survives",
"   * the next srcdoc swap. Cookie-header replay to the worker rides on",
"   * the x-cookie header the wrappers already set. */",
"  try {",
"    if (SD) {",
"      var _cookieDesc = Object.getOwnPropertyDescriptor(Document.prototype, 'cookie');",
"      Object.defineProperty(document, 'cookie', {",
"        get: function () { return docCookies().join('; '); },",
"        set: function (str) {",
"          try {",
"            var bits = String(str).split(';');",
"            var nv = bits[0];",
"            var eq = nv.indexOf('=');",
"            if (eq >= 0) {",
"              var name = nv.slice(0, eq).trim();",
"              var value = nv.slice(eq + 1).trim();",
"              var del = false;",
"              for (var i = 1; i < bits.length; i++) {",
"                var b = bits[i].trim().toLowerCase();",
"                if (b === 'max-age=0' || b.indexOf('expires=thu, 01 jan 1970') === 0) del = true;",
"              }",
"              if (name) {",
"                var found = false;",
"                for (var j = 0; j < jar.length; j++) {",
"                  if (jar[j].name === name) { found = true; if (del) { jar.splice(j, 1); } else { jar[j].value = value; } break; }",
"                }",
"                if (!found && !del) jar.push({ name: name, value: value });",
"                up({ type: 'cookies', cookies: jar });",
"              }",
"            }",
"          } catch (eC) { /* ignore */ }",
"        },",
"        configurable: true",
"      });",
"    }",
"  } catch (eCookieShim) { /* ignore */ }",
"",
"  /* ---------- header injection ---------- */",
"  function applyHeaders(h) {",
"    try {",
"      var ch = cookieHeader();",
"      if (ch && !h.has('x-cookie')) h.set('x-cookie', ch);",
"      if (TOKEN && !h.has('x-proxy-token')) h.set('x-proxy-token', TOKEN);",
"    } catch (e) { /* ignore */ }",
"    return h;",
"  }",
"",
"  /* ---------- fetch ---------- */",
"  var _fetch = window.fetch ? window.fetch.bind(window) : null;",
"  if (_fetch) {",
"    window.fetch = function (input, init) {",
"      try {",
"        if (input && typeof input === 'object' && typeof input.url === 'string' && input.constructor && input.constructor.name === 'Request') {",
"          var mapped = mapUrl(input.url);",
"          if (mapped !== input.url) {",
"            try { input = new Request(absW(mapped), input); } catch (e2) { /* keep original */ }",
"          }",
"        } else if (typeof input === 'string' || input instanceof URL) {",
"          var u2 = mapUrl(String(input));",
"          if (u2 !== String(input)) input = absW(u2);",
"        }",
"        init = init || {};",
"        var H;",
"        try { H = (init.headers instanceof Headers) ? init.headers : new Headers(init.headers || {}); }",
"        catch (e3) { H = new Headers(); }",
"        init.headers = applyHeaders(H);",
"        var p = _fetch(input, init);",
"        p.then(function (r) {",
"          try { ingestSetCookie(r.headers && r.headers.get('x-set-cookie')); } catch (e4) { /* ignore */ }",
"        }, function () { /* network error \u2014 swallow */ });",
"        return p;",
"      } catch (e) {",
"        return _fetch(input, init);",
"      }",
"    };",
"  }",
"",
"  /* ---------- XMLHttpRequest ---------- */",
"  try {",
"    var _open = XMLHttpRequest.prototype.open;",
"    XMLHttpRequest.prototype.open = function (method, url) {",
"      try {",
"        var mu = mapUrl(String(url));",
"        if (mu !== String(url)) {",
"          mu = absW(mu);",
"          if (arguments.length > 2) {",
"            arguments[1] = mu;",
"            return _open.apply(this, arguments);",
"          }",
"          return _open.call(this, method, mu);",
"        }",
"      } catch (e) { /* ignore */ }",
"      return _open.apply(this, arguments);",
"    };",
"    var _send = XMLHttpRequest.prototype.send;",
"    XMLHttpRequest.prototype.send = function () {",
"      try {",
"        var ch = cookieHeader();",
"        if (ch) this.setRequestHeader('x-cookie', ch);",
"        if (TOKEN) this.setRequestHeader('x-proxy-token', TOKEN);",
"      } catch (e) { /* ignore */ }",
"      var xhr = this;",
"      try {",
"        xhr.addEventListener('loadend', function () {",
"          try { ingestSetCookie(xhr.getResponseHeader && xhr.getResponseHeader('x-set-cookie')); } catch (e2) { /* ignore */ }",
"        });",
"      } catch (e3) { /* ignore */ }",
"      return _send.apply(this, arguments);",
"    };",
"  } catch (e) { /* ignore */ }",
"",
"  /* ---------- EventSource ---------- */",
"  try {",
"    if (window.EventSource) {",
"      var _ES = window.EventSource;",
"      window.EventSource = function (url, cfg) {",
"        try {",
"          var mu = absW(mapUrl(String(url)));",
"          /* EventSource cannot set headers \u2014 carry the token in the query */",
"          if (TOKEN && mu !== String(url) && String(mu).indexOf('__t=') < 0) {",
"            mu += (mu.indexOf('?') < 0 ? '?' : '&') + '__t=' + encodeURIComponent(TOKEN);",
"          }",
"          url = mu;",
"        } catch (e) { /* ignore */ }",
"        return new _ES(url, cfg);",
"      };",
"      window.EventSource.prototype = _ES.prototype;",
"    }",
"  } catch (e) { /* ignore */ }",
"",
"  /* ---------- WebSocket ---------- */",
"  try {",
"    if (window.WebSocket) {",
"      var _WS = window.WebSocket;",
"      window.WebSocket = function (url, protocols) {",
"        try {",
"          var s = String(url);",
"          var m = s.match(/^(wss?):\\/\\/([^\\/?#]+)(\\/.*)?$/i);",
"          if (m) {",
"            var host = m[2].toLowerCase();",
"            var scheme = m[1].toLowerCase() === 'ws' ? 'ws' : 'wss';",
"            if (allowedHost(host)) {",
"              var rest = m[3] || '/';",
"              var path;",
"              if (host === HOST && !TOK) {",
"                path = PFX + rest; // chat host: the worker root IS the ws endpoint",
"              } else {",
"                var wtok = encTok(s); // the whole original ws:// URL in one opaque token",
"                path = wtok ? '/__t/' + wtok : '/p/' + host + rest; // keyless legacy fallback",
"              }",
"              if (TOKEN && path.indexOf('__t=') < 0) {",
"                path += (path.indexOf('?') < 0 ? '?' : '&') + '__t=' + encodeURIComponent(TOKEN);",
"              }",
"              /* v5 sandbox: location.host is EMPTY at about:srcdoc \u2014 the",
"               * worker origin comes from cfg instead. */",
"              var wOrigin = (SD && WORKER) ? WORKER : (location.protocol + '//' + location.host);",
"              url = (wOrigin.indexOf('https:') === 0 ? 'wss' : scheme) + '://' + wOrigin.replace(/^https?:\\/\\//i, '') + path;",
"            }",
"          }",
"        } catch (e) { /* ignore */ }",
"        return protocols === undefined ? new _WS(url) : new _WS(url, protocols);",
"      };",
"      window.WebSocket.prototype = _WS.prototype;",
"      window.WebSocket.CONNECTING = _WS.CONNECTING;",
"      window.WebSocket.OPEN = _WS.OPEN;",
"      window.WebSocket.CLOSING = _WS.CLOSING;",
"      window.WebSocket.CLOSED = _WS.CLOSED;",
"    }",
"  } catch (e) { /* ignore */ }",
"",
"  /* ---------- sendBeacon ---------- */",
"  try {",
"    if (navigator.sendBeacon) {",
"      var _sb = navigator.sendBeacon.bind(navigator);",
"      navigator.sendBeacon = function (url, data) {",
"        try {",
"          var mu = absW(mapUrl(String(url)));",
"          if (mu !== String(url)) {",
"            // beacons cannot carry custom headers; fall back to keepalive fetch",
"            return _fetch(mu, { method: 'POST', body: data, keepalive: true, mode: 'no-cors' }) ? true : true;",
"          }",
"        } catch (e) { /* ignore */ }",
"        return _sb(url, data);",
"      };",
"    }",
"  } catch (e) { /* ignore */ }",
"",
"  /* ---------- navigation reporting ---------- */",
"  function curUrl() {",
"    if (SD) return DOC || 'about:srcdoc'; /* v5: the shell wants the real upstream URL */",
"    return location.pathname + location.search + location.hash;",
"  }",
"  function reportNav() { up({ type: 'nav', url: curUrl(), title: document.title || '' }); }",
"",
"  try {",
"    var _push = history.pushState;",
"    var _replace = history.replaceState;",
"    // SPA history entries must stay inside the proxy prefix: a bare",
"    // \"/login\" pushed from \"/chat/\" would escape the sandbox on the next",
"    // reload, and a cross-origin URL would throw SecurityError outright.",
"    function fixHistUrl(u) {",
"      try {",
"        var s = String(u);",
"        if (!s || s.charAt(0) === '#') return s;",
"        var org = originStr();",
"        if (org && (s === org || s.indexOf(org + '/') === 0)) {",
"          var p = s.slice(org.length) || '/';",
"          if (isProxyPath(p)) return p;",
"          return PFX + p;",
"        }",
"        var mapped = mapUrl(s);",
"        if (/^(https?:)?\\/\\//i.test(mapped)) return curUrl(); // cross-origin \u2192 would throw",
"        return mapped;",
"      } catch (e) { return u; }",
"    }",
"    history.pushState = function () {",
"      if (SD) {",
"        /* v5 sandbox: native pushState throws SecurityError (the URL is",
"         * cross-origin to about:srcdoc) and would kill the SPA. Treat it",
"         * as a SOFT transition: tell the shell the new URL (worker path +",
"         * upstream URL) \u2014 it updates its history entry and address bar;",
"         * the app renders the transition client-side exactly as built. */",
"        try {",
"          var su = (arguments.length > 2 && arguments[2] != null) ? String(arguments[2]) : '';",
"          if (su && su.charAt(0) !== '#') {",
"            var sAbs = '';",
"            try { sAbs = new URL(su, DOC || 'about:srcdoc').href; } catch (eA) { sAbs = su; }",
"            up({ type: 'hist', url: mapUrl(sAbs), up: sAbs });",
"          }",
"        } catch (eH) { /* ignore */ }",
"        reportNav();",
"        return undefined;",
"      }",
"      try { if (arguments.length > 2 && arguments[2] != null) arguments[2] = fixHistUrl(arguments[2]); } catch (e2) { /* ignore */ }",
"      var r = _push.apply(this, arguments); reportNav(); return r;",
"    };",
"    history.replaceState = function () {",
"      if (SD) {",
"        try {",
"          var ru = (arguments.length > 2 && arguments[2] != null) ? String(arguments[2]) : '';",
"          if (ru && ru.charAt(0) !== '#') {",
"            var rAbs = '';",
"            try { rAbs = new URL(ru, DOC || 'about:srcdoc').href; } catch (eB) { rAbs = ru; }",
"            up({ type: 'hist', url: mapUrl(rAbs), up: rAbs, replace: true });",
"          }",
"        } catch (eH2) { /* ignore */ }",
"        reportNav();",
"        return undefined;",
"      }",
"      try { if (arguments.length > 2 && arguments[2] != null) arguments[2] = fixHistUrl(arguments[2]); } catch (e2) { /* ignore */ }",
"      var r = _replace.apply(this, arguments); reportNav(); return r;",
"    };",
"    window.addEventListener('popstate', reportNav);",
"    window.addEventListener('hashchange', reportNav);",
"    window.addEventListener('pageshow', reportNav);",
"  } catch (e) { /* ignore */ }",
"",
"  /* ---------- Navigation API interception (Chrome/Edge) ----------",
"   * catches location.href=..., form submits, link clicks \u2014 anything",
"   * that would navigate this frame to an absolute or external URL.",
"   * v5 sandbox: EVERY navigation is intercepted \u2014 the frame must never",
"   * go anywhere; the shell re-renders a fresh srcdoc instead.",
"   */",
"  try {",
"    if (window.navigation && window.navigation.addEventListener) {",
"      window.navigation.addEventListener('navigate', function (e) {",
"        try {",
"          if (!e.canIntercept || !e.destination || e.destination.sameDocument) return;",
"          var dest = String(e.destination.url || '');",
"          if (!dest) return;",
"          if (SD) {",
"            e.preventDefault();",
"            if (isWorkerUrl(dest)) { nav(dest); return; } /* already proxied */",
"            if (/^https?:\\/\\//i.test(dest) && !allowedHost((dest.match(/^https?:\\/\\/([^\\/?#]+)/i) || [])[1])) {",
"              up({ type: 'ext', url: dest });",
"              pageToast('Blocked (outside the proxy): ' + dest);",
"              return;",
"            }",
"            nav(dest);",
"            return;",
"          }",
"          var org = originStr();",
"          if (org && (dest === org || dest.indexOf(org + '/') === 0)) {",
"            // same-origin destination on the worker itself: either an",
"            // already-proxied path (proceed natively \u2014 the old code used to",
"            // eat these as \"external\") or a bare worker-root path that must",
"            // regain this document's proxy prefix",
"            var p = dest.slice(org.length) || '/';",
"            if (isProxyPath(p)) return;",
"            e.preventDefault();",
"            location.href = PFX + p;",
"            return;",
"          }",
"          var mapped = mapUrl(dest);",
"          if (mapped !== dest) {",
"            // z.ai-family absolute URL \u2192 swap for the proxied path",
"            e.preventDefault();",
"            location.href = mapped;",
"            return;",
"          }",
"          if (/^https?:\\/\\//i.test(dest) || /^\\/\\//.test(dest)) {",
"            // external site \u2014 the phone will block it anyway; tell the user",
"            e.preventDefault();",
"            up({ type: 'ext', url: dest });",
"            pageToast('Blocked (outside the proxy): ' + dest);",
"          }",
"          // relative destinations proceed natively",
"        } catch (err) { /* ignore */ }",
"      });",
"    }",
"  } catch (e) { /* ignore */ }",
"",
"  /* ---------- window.open ---------- */",
"  function stubWindow() {",
"    return {",
"      closed: false,",
"      close: function () { this.closed = true; },",
"      focus: function () {}, blur: function () {},",
"      postMessage: function () {},",
"      location: { href: 'about:blank', replace: function () {}, assign: function () {} },",
"      document: { write: function () {}, open: function () {}, close: function () {}, createElement: function () { return { setAttribute: function () {}, appendChild: function () {} }; } }",
"    };",
"  }",
"  window.open = function (url) {",
"    try {",
"      var u = url == null ? '' : String(url);",
"      if (!u || u === 'about:blank') return stubWindow();",
"      if (SD) {",
"        /* v5 sandbox: no popups from the sandbox \u2014 in-app navigation or",
"         * the external notice, never a real window (its first navigation",
"         * would hit the org filter). */",
"        if (isWorkerUrl(u)) { nav(u); return stubWindow(); }",
"        if (/^https?:\\/\\//i.test(u) && !allowedHost((u.match(/^https?:\\/\\/([^\\/?#]+)/i) || [])[1])) {",
"          up({ type: 'ext', url: u });",
"          pageToast('Blocked (outside the proxy): ' + u);",
"          return stubWindow();",
"        }",
"        nav(u);",
"        return stubWindow();",
"      }",
"      var mapped = mapUrl(u);",
"      if (mapped !== u) { location.href = mapped; return stubWindow(); }",
"      if (/^(https?:)?\\/\\//i.test(u)) { up({ type: 'ext', url: u }); pageToast('Blocked (outside the proxy): ' + u); return stubWindow(); }",
"      location.href = u;",
"      return stubWindow();",
"    } catch (e) { return stubWindow(); }",
"  };",
"",
"  /* ---------- click / submit capture (fallback layer) ---------- */",
"  document.addEventListener('click', function (e) {",
"    try {",
"      if (e.defaultPrevented || (e.button !== undefined && e.button !== 0)) return;",
"      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;",
"      var el = e.target;",
"      var a = el && el.closest ? el.closest('a[' + 'href]') : null;",
"      if (!a) return;",
"      var href = a.getAttribute('href') || '';",
"      if (!href || href.charAt(0) === '#' || /^(data|blob|javascript|mailto|tel):/i.test(href)) return;",
"      var target = (a.target || '').toLowerCase();",
"      if (SD) {",
"        /* v5 sandbox: NOTHING navigates \u2014 every link becomes a nav()",
"         * postMessage and the shell re-renders a fresh srcdoc. */",
"        e.preventDefault();",
"        if (isWorkerUrl(href)) { nav(href); return; } /* worker-rewritten attr */",
"        if (/^https?:\\/\\//i.test(href) && !allowedHost((href.match(/^https?:\\/\\/([^\\/?#]+)/i) || [])[1])) {",
"          up({ type: 'ext', url: href });",
"          pageToast('Blocked (outside the proxy): ' + href);",
"          return;",
"        }",
"        nav(href);",
"        return;",
"      }",
"      var mapped = mapUrl(href);",
"      if (mapped !== href) {",
"        if (target === '_top' || target === '_parent' || target === '_blank') {",
"          e.preventDefault();",
"          location.href = mapped;",
"        } else {",
"          a.setAttribute('href', mapped); // let native navigation use the proxied href",
"        }",
"        return;",
"      }",
"      if (/^(https?:)?\\/\\//i.test(href)) {",
"        e.preventDefault();",
"        up({ type: 'ext', url: href });",
"        pageToast('Blocked (outside the proxy): ' + href);",
"        return;",
"      }",
"      if (target === '_top' || target === '_parent') {",
"        e.preventDefault();",
"        location.href = href;",
"      }",
"    } catch (err) { /* ignore */ }",
"  }, true);",
"",
"  /* ---------- v5: form serialization (sandbox submits) -----------------",
"   * A form submit must become a POST navigation the SHELL performs via",
"   * fetch(): method + enctype + all successful controls. Multipart",
"   * forms ship the FormData object itself (postMessage structured-clones",
"   * it); urlencoded forms ship a plain string. */",
"  function serializeForm(f) {",
"    var enctype = (f.getAttribute('enctype') || 'application/x-www-form-urlencoded').toLowerCase();",
"    var method = (f.getAttribute('method') || 'GET').toUpperCase();",
"    if (enctype.indexOf('multipart') >= 0) {",
"      try {",
"        var fd = new FormData(f);",
"        return { method: method === 'GET' ? 'POST' : method, body: fd, ct: null };",
"      } catch (eFD) { /* fall through to urlencoded */ }",
"    }",
"    var parts = [];",
"    try {",
"      var els = f.elements;",
"      for (var i = 0; i < els.length; i++) {",
"        var fe = els[i];",
"        if (!fe.name || fe.disabled) continue;",
"        var ft = (fe.type || '').toLowerCase();",
"        if (ft === 'checkbox' || ft === 'radio') { if (fe.checked) parts.push([fe.name, fe.value || '']); continue; }",
"        if (ft === 'file') {",
"          try {",
"            if (fe.files && fe.files[0]) parts.push([fe.name, fe.files[0].name]);",
"          } catch (eF) { /* ignore */ }",
"          continue;",
"        }",
"        if (ft === 'submit' || ft === 'button' || ft === 'image' || ft === 'reset') continue;",
"        if (fe.tagName === 'SELECT') {",
"          var opts = fe.selectedOptions || [];",
"          for (var oi = 0; oi < opts.length; oi++) parts.push([fe.name, opts[oi].value || '']);",
"          continue;",
"        }",
"        parts.push([fe.name, fe.value || '']);",
"      }",
"    } catch (eE) { /* ignore */ }",
"    /* the submit button that fired (name+value) is not in elements' values */",
"    try {",
"      if (f.__zpSubBtn && f.__zpSubBtn.name) parts.push([f.__zpSubBtn.name, f.__zpSubBtn.value || '']);",
"    } catch (eS) { /* ignore */ }",
"    var qs = parts.map(function (p) { return encodeURIComponent(p[0]) + '=' + encodeURIComponent(p[1] || ''); }).join('&');",
"    var ct = enctype.indexOf('text/plain') >= 0 ? 'text/plain' : 'application/x-www-form-urlencoded';",
"    return { method: method, body: qs, ct: ct };",
"  }",
"  try {",
"    if (SD) {",
"      /* remember the submit button that fired (its name/value is part of",
"       * the successful controls set per HTML spec) */",
"      document.addEventListener('click', function (e) {",
"        try {",
"          var b = e.target && e.target.closest ? e.target.closest('button, input[type=submit], input[type=image]') : null;",
"          if (b && b.form) b.form.__zpSubBtn = b;",
"        } catch (eB) { /* ignore */ }",
"      }, true);",
"      document.addEventListener('submit', function (e) {",
"        try {",
"          var f = e.target;",
"          if (!f || !f.getAttribute) return;",
"          e.preventDefault();",
"          var action = f.getAttribute('action') || '';",
"          var dest = action || curUrl();",
"          if (isWorkerUrl(dest)) {",
"            /* the action was already rewritten to the worker origin \u2014",
"             * navigate straight to it (the shell strips the origin) */",
"            var serW = serializeForm(f);",
"            if ((serW.method || 'GET') === 'GET') {",
"              var baseW = dest.split('#')[0].split('?')[0];",
"              nav(baseW + (serW.body ? '?' + serW.body : ''));",
"            } else {",
"              nav(dest, serW.method, serW.body, serW.ct);",
"            }",
"            return;",
"          }",
"          if (/^https?:\\/\\//i.test(dest) && !allowedHost((dest.match(/^https?:\\/\\/([^\\/?#]+)/i) || [])[1])) {",
"            up({ type: 'ext', url: dest });",
"            return;",
"          }",
"          var ser = serializeForm(f);",
"          if ((ser.method || 'GET') === 'GET') {",
"            /* GET forms: the body becomes the destination query */",
"            var base = dest.split('#')[0].split('?')[0];",
"            dest = base + (ser.body ? '?' + ser.body : '');",
"            nav(dest);",
"          } else {",
"            nav(dest, ser.method, ser.body, ser.ct);",
"          }",
"        } catch (errS) { /* ignore */ }",
"      }, true);",
"    }",
"  } catch (eSubArm) { /* ignore */ }",
"",
"  document.addEventListener('submit', function (e) {",
"    try {",
"      if (SD) return; /* handled by the sandbox submit arm above */",
"      var f = e.target;",
"      if (!f || !f.getAttribute) return;",
"      var action = f.getAttribute('action') || '';",
"      if (action) {",
"        var mapped = mapUrl(action);",
"        if (mapped !== action) f.setAttribute('action', mapped);",
"      }",
"      var target = (f.target || '').toLowerCase();",
"      if (target === '_top' || target === '_parent' || target === '_blank') {",
"        e.preventDefault();",
"        var dest = f.getAttribute('action') || curUrl();",
"        if (/^(https?:)?\\/\\//i.test(dest) && mapUrl(dest) === dest) { up({ type: 'ext', url: dest }); return; }",
"        location.href = dest;",
"      }",
"    } catch (err) { /* ignore */ }",
"  }, true);",
"",
"  /* ---------- service worker: never register ----------",
"   * a SW would bypass every patch we installed. In the sandbox the",
"   * navigator.serviceWorker PROPERTY itself throws SecurityError on",
"   * access (opaque origin) \u2014 so the whole getter is stubbed first.",
"   */",
"  try {",
"    var SW_STUB = {",
"      register: function () { return Promise.resolve({ scope: '/', active: null, installing: null, waiting: null, unregister: function () { return Promise.resolve(true); }, addEventListener: function () {}, state: 'activated' }); },",
"      getRegistration: function () { return Promise.resolve(undefined); },",
"      getRegistrations: function () { return Promise.resolve([]); },",
"      addEventListener: function () {},",
"      removeEventListener: function () {},",
"      ready: new Promise(function () {}),",
"      controller: null",
"    };",
"    if (SD) {",
"      try {",
"        Object.defineProperty(Navigator.prototype, 'serviceWorker', { configurable: true, get: function () { return SW_STUB; } });",
"      } catch (eSWP) {",
"        try { Object.defineProperty(navigator, 'serviceWorker', { configurable: true, get: function () { return SW_STUB; } }); } catch (eSWI) { /* ignore */ }",
"      }",
"    } else if (navigator.serviceWorker && navigator.serviceWorker.register) {",
"      navigator.serviceWorker.register = SW_STUB.register;",
"    }",
"  } catch (e) { /* ignore */ }",
"",
"  /* ---------- dynamic subresource rewriting ----------",
"   * The SPA builds absolute URLs at runtime for images, scripts,",
"   * stylesheets and downloads (e.g. https://z-cdn.chatglm.cn/\u2026).",
"   * Those would leave the proxy and die on a network that can only",
"   * reach the worker. Rewrite them as they are inserted \u2014 hosts that",
"   * are not allowlisted are left untouched (they fail quietly, like",
"   * analytics does on the real site in China).",
"   */",
"  var RES_ATTRS = { IMG: ['src', 'srcset'], SCRIPT: ['src'], LINK: ['href'], SOURCE: ['src', 'srcset'], AUDIO: ['src', 'poster'], VIDEO: ['src', 'poster'], IFRAME: ['src'], OBJECT: ['data'], EMBED: ['src'], IMAGE: ['href'] };",
"  function fixEl(el) {",
"    try {",
"      if (!el || !el.tagName || !el.getAttribute || !el.setAttribute) return;",
"      var attrs = RES_ATTRS[el.tagName.toUpperCase()];",
"      if (!attrs) return;",
"      for (var i = 0; i < attrs.length; i++) {",
"        var a = attrs[i];",
"        var v = el.getAttribute(a);",
"        if (!v) continue;",
"        var nv = mapUrl(v);",
"        if (nv !== v) el.setAttribute(a, nv);",
"      }",
"    } catch (e) { /* ignore */ }",
"  }",
"  function scanTree(node) {",
"    try {",
"      if (!node || node.nodeType !== 1) return;",
"      fixEl(node);",
"      if (node.tagName && node.tagName.toUpperCase() === 'STYLE') {",
"        try {",
"          var st = node.textContent;",
"          if (st) {",
"            var nst = mapCssUrls(st);",
"            if (nst !== st) node.textContent = nst;",
"          }",
"        } catch (e2) { /* ignore */ }",
"      }",
"      if (node.querySelectorAll) {",
"        var els = node.querySelectorAll('img,script,link,source,audio,video,iframe,object,embed,image,style');",
"        for (var i = 0; i < els.length; i++) {",
"          fixEl(els[i]);",
"          if (els[i].tagName && els[i].tagName.toUpperCase() === 'STYLE') {",
"            try {",
"              var st2 = els[i].textContent;",
"              if (st2) {",
"                var nst2 = mapCssUrls(st2);",
"                if (nst2 !== st2) els[i].textContent = nst2;",
"              }",
"            } catch (e3) { /* ignore */ }",
"          }",
"        }",
"      }",
"    } catch (e) { /* ignore */ }",
"  }",
"  try {",
"    if (window.MutationObserver && document.documentElement) {",
"      var mo = new MutationObserver(function (muts) {",
"        for (var i = 0; i < muts.length; i++) {",
"          var m = muts[i];",
"          if (m.type === 'attributes') { fixEl(m.target); continue; }",
"          if (m.type === 'characterData') {",
"            /* text data changed inside a <style> (appendData/insertData) */",
"            try {",
"              var pn = m.target && m.target.parentNode;",
"              if (pn && pn.tagName === 'STYLE') {",
"                var ts2 = pn.textContent;",
"                if (ts2) {",
"                  var mts2 = mapCssUrls(ts2);",
"                  if (mts2 !== ts2) pn.textContent = mts2;",
"                }",
"              }",
"            } catch (e6) { /* ignore */ }",
"            continue;",
"          }",
"          for (var j = 0; j < m.addedNodes.length; j++) {",
"            var an = m.addedNodes[j];",
"            if (an.nodeType === 3 && m.target && m.target.tagName === 'STYLE') {",
"              /* a raw text node was appended into a <style> */",
"              try {",
"                var ts = m.target.textContent;",
"                if (ts) {",
"                  var mts = mapCssUrls(ts);",
"                  if (mts !== ts) m.target.textContent = mts;",
"                }",
"              } catch (e5) { /* ignore */ }",
"            } else {",
"              scanTree(an);",
"            }",
"          }",
"        }",
"      });",
"      mo.observe(document.documentElement, { childList: true, subtree: true, characterData: true, attributes: true, attributeFilter: ['src', 'href', 'srcset', 'poster', 'data'] });",
"    }",
"  } catch (e) { /* ignore */ }",
"",
"  /* Detached elements bypass the observer: telemetry beacons and preload",
"   * probes set img.src (or setAttribute) without ever entering the DOM.",
"   * Patch the property setter and setAttribute so those URLs are mapped",
"   * onto the worker as well. */",
"  try {",
"    var imgProto = window.HTMLImageElement && window.HTMLImageElement.prototype;",
"    var srcDesc = imgProto && Object.getOwnPropertyDescriptor(imgProto, 'src');",
"    if (srcDesc && srcDesc.set) {",
"      Object.defineProperty(imgProto, 'src', {",
"        get: function () { return srcDesc.get.call(this); },",
"        set: function (v) {",
"          try {",
"            var mu = mapUrl(String(v));",
"            if (mu !== String(v)) v = mu;",
"          } catch (e) { /* ignore */ }",
"          return srcDesc.set.call(this, v);",
"        },",
"        configurable: true,",
"        enumerable: srcDesc.enumerable",
"      });",
"    }",
"  } catch (e) { /* ignore */ }",
"",
"  try {",
"    var _setattr = Element.prototype.setAttribute;",
"    Element.prototype.setAttribute = function (name, value) {",
"      try {",
"        var n = String(name).toLowerCase();",
"        if ((n === 'src' || n === 'href' || n === 'srcset' || n === 'poster' || n === 'data') &&",
"            typeof value === 'string' && this && this.tagName) {",
"          var attrs = RES_ATTRS[this.tagName.toUpperCase()];",
"          if (attrs && attrs.indexOf(n) >= 0) {",
"            var mu = mapUrl(value);",
"            if (mu !== value) value = mu;",
"          }",
"        }",
"      } catch (e) { /* ignore */ }",
"      return _setattr.call(this, name, value);",
"    };",
"  } catch (e) { /* ignore */ }",
"",
"  /* ---------- v4: property-setter + CSSOM coverage (leak hardening) ----",
"   * Frameworks assign .src/.href as PROPERTIES (bypassing setAttribute)",
"   * and paint backgrounds through the CSSOM (bypassing the style",
"   * attribute). Any allowlisted absolute URL slipping through those",
"   * paths would leave the proxy carrying a readable hostname \u2014 exactly",
"   * what organization filters block. Wrap the setters so mapUrl still",
"   * catches them. */",
"  function wrapProp(proto, prop, cssMode) {",
"    try {",
"      var d = Object.getOwnPropertyDescriptor(proto, prop);",
"      if (!d || !d.set) return;",
"      Object.defineProperty(proto, prop, {",
"        get: d.get,",
"        set: function (v) {",
"          try {",
"            if (typeof v === 'string') {",
"              var nv = cssMode ? (v.indexOf('url(') >= 0 ? mapCssUrls(v) : v) : mapUrl(v);",
"              if (nv !== v) v = nv;",
"            }",
"          } catch (e) { /* ignore */ }",
"          return d.set.call(this, v);",
"        },",
"        configurable: true,",
"        enumerable: d.enumerable",
"      });",
"    } catch (e) { /* ignore */ }",
"  }",
"  try {",
"    if (window.HTMLMediaElement) wrapProp(HTMLMediaElement.prototype, 'src');",
"    if (window.HTMLScriptElement) wrapProp(HTMLScriptElement.prototype, 'src');",
"    if (window.HTMLLinkElement) wrapProp(HTMLLinkElement.prototype, 'href');",
"    if (window.HTMLIFrameElement) wrapProp(HTMLIFrameElement.prototype, 'src');",
"  } catch (e) { /* ignore */ }",
"",
"  /* CSSOM writes: style.setProperty('background', 'url(https://\u2026)') and",
"   * the background-family property setters must map their url()s too.",
"   * v4.1: also maps @import \"\u2026\" strings and is reused for every CSS-TEXT",
"   * injection channel (style textContent, insertRule, replaceSync) \u2014",
"   * CSS fetched at runtime and re-injected as text would otherwise send",
"   * the browser straight to the upstream host (the CSS engine does not",
"   * go through the patched fetch). */",
"  function mapCssUrls(val) {",
"    try {",
"      var s = String(val);",
"      if (!/url\\(|@import/i.test(s)) return s;",
"      s = s.replace(/url\\(\\s*(['\"]?)([^'\")]+)\\1\\s*\\)/gi, function (w, q, u) {",
"        var nu = mapUrl(u);",
"        return nu === u ? w : 'url(\"' + nu + '\")';",
"      });",
"      s = s.replace(/@import\\s*(['\"])([^'\"]+)\\1/gi, function (w, q, u) {",
"        /* \\s* \u2014 minified css ships @import\"https://\u2026\" with no space */",
"        var nu = mapUrl(u);",
"        return nu === u ? w : '@import ' + q + nu + q;",
"      });",
"      return s;",
"    } catch (e) { return val; }",
"  }",
"  try {",
"    var _sp = CSSStyleDeclaration.prototype.setProperty;",
"    if (_sp) {",
"      CSSStyleDeclaration.prototype.setProperty = function (name, value, pri) {",
"        try {",
"          if (typeof value === 'string' && value.indexOf('url(') >= 0) value = mapCssUrls(value);",
"        } catch (e) { /* ignore */ }",
"        return _sp.call(this, name, value, pri);",
"      };",
"    }",
"  } catch (e) { /* ignore */ }",
"  try {",
"    if (window.CSSStyleDeclaration) {",
"      ['background', 'backgroundImage', 'content', 'maskImage', 'listStyleImage', 'borderImage'].forEach(function (prop) {",
"        wrapProp(CSSStyleDeclaration.prototype, prop, true);",
"      });",
"    }",
"  } catch (e) { /* ignore */ }",
"",
"  /* CSS TEXT injection channels \u2014 anything that hands raw CSS text to",
"   * the CSS engine at runtime (the SPA fills the empty <style nonce> tag",
"   * in the initial HTML this way, e.g. an @import for webfonts):",
"   *   - styleEl.textContent = '\u2026'   (Node property setter)",
"   *   - sheet.insertRule('\u2026')        (CSSOM)",
"   *   - sheet.replaceSync('\u2026') / sheet.replace('\u2026') (constructable)",
"   *   - <style> nodes arriving through the MutationObserver",
"   * Every url()/@import inside that text is mapped (tokens for cross-host",
"   * URLs) BEFORE the CSS engine ever sees it. */",
"  try {",
"    var _tcDesc = Object.getOwnPropertyDescriptor(Node.prototype, 'textContent');",
"    if (_tcDesc && _tcDesc.set) {",
"      Object.defineProperty(Node.prototype, 'textContent', {",
"        get: _tcDesc.get,",
"        set: function (v) {",
"          try {",
"            if (this && this.tagName === 'STYLE' && typeof v === 'string') {",
"              var nv = mapCssUrls(v);",
"              if (nv !== v) v = nv;",
"            }",
"          } catch (e) { /* ignore */ }",
"          return _tcDesc.set.call(this, v);",
"        },",
"        configurable: true,",
"        enumerable: _tcDesc.enumerable",
"      });",
"    }",
"  } catch (e) { /* ignore */ }",
"  try {",
"    if (window.CSSStyleSheet) {",
"      var _ir = CSSStyleSheet.prototype.insertRule;",
"      if (_ir) {",
"        CSSStyleSheet.prototype.insertRule = function (rule, idx) {",
"          try {",
"            if (typeof rule === 'string') { var nr = mapCssUrls(rule); if (nr !== rule) rule = nr; }",
"          } catch (e) { /* ignore */ }",
"          return _ir.call(this, rule, idx);",
"        };",
"      }",
"      var _rsync = CSSStyleSheet.prototype.replaceSync;",
"      if (_rsync) {",
"        CSSStyleSheet.prototype.replaceSync = function (txt) {",
"          try { if (typeof txt === 'string') { var nt = mapCssUrls(txt); if (nt !== txt) txt = nt; } } catch (e) { /* ignore */ }",
"          return _rsync.call(this, txt);",
"        };",
"      }",
"      var _rpl = CSSStyleSheet.prototype.replace;",
"      if (_rpl) {",
"        CSSStyleSheet.prototype.replace = function (txt) {",
"          try { if (typeof txt === 'string') { var nt2 = mapCssUrls(txt); if (nt2 !== txt) txt = nt2; } } catch (e) { /* ignore */ }",
"          return _rpl.call(this, txt);",
"        };",
"      }",
"    }",
"  } catch (e) { /* ignore */ }",
"",
"  /* ---------- analytics shims (their hosts are blocked anyway) ---------- */",
"  window.dataLayer = window.dataLayer || [];",
"  window.gtag = window.gtag || function () { window.dataLayer.push(arguments); };",
"",
"  /* ---------- localStorage fallback for browsers that block it in iframes ----------",
"   * backed by the shell through postMessage so sessions survive reloads.",
"   * v5 sandbox note: in a null-origin frame ACCESSING window.localStorage",
"   * THROWS SecurityError \u2014 the access must happen in its own try BEFORE",
"   * the usable() probe, or the exception skips the shim entirely (the",
"   * site's own `window.localStorage && ...` guard would then throw and",
"   * silently kill its boot logic). */",
"  (function setupStorage() {",
"    function usable(store) {",
"      try {",
"        var k = '__zai_probe__';",
"        store.setItem(k, '1');",
"        store.removeItem(k);",
"        return true;",
"      } catch (e) { return false; }",
"    }",
"    function makeShim(name) {",
"      var mem = (name === 'localStorage') ? lsMirror : {};",
"      return {",
"        getItem: function (k) { return Object.prototype.hasOwnProperty.call(mem, k) ? mem[k] : null; },",
"        setItem: function (k, v) { mem[k] = String(v); up({ type: 'ls', store: name, k: String(k), v: String(v) }); },",
"        removeItem: function (k) { delete mem[k]; up({ type: 'ls', store: name, k: String(k), v: null }); },",
"        clear: function () { mem = {}; up({ type: 'ls', store: name, k: '__clear__', v: null }); },",
"        key: function (i) { return Object.keys(mem)[i] || null; }",
"      };",
"    }",
"    ['localStorage', 'sessionStorage'].forEach(function (name) {",
"      var native = null;",
"      try { native = window[name]; } catch (eAcc) { native = null; }",
"      if (native && usable(native)) return; /* native storage works \u2014 keep it */",
"      try {",
"        Object.defineProperty(window, name, { value: makeShim(name), configurable: true, writable: false });",
"      } catch (eDef) { /* ignore */ }",
"    });",
"  })();",
"",
"  /* ---------- title watcher ---------- */",
"  function watchTitle() {",
"    try {",
"      var t = document.querySelector('title');",
"      if (t && window.MutationObserver) {",
"        new MutationObserver(reportNav).observe(t, { childList: true, characterData: true, subtree: true });",
"      }",
"    } catch (e) { /* ignore */ }",
"  }",
"  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', watchTitle);",
"  else watchTitle();",
"",
"  /* ---------- error forwarding (diagnostics) ---------- */",
"  var errCount = 0;",
"  window.addEventListener('error', function (e) {",
"    var msg = String((e && e.message) || e).slice(0, 300);",
"    if (errCount < 10) up({ type: 'err', msg: msg });",
"    if (errCount < 3) pageToast('Page error: ' + msg);",
"    errCount++;",
"  });",
"",
"  /* ---------- shell commands ---------- */",
"  window.addEventListener('message', function (e) {",
"    try {",
"      var d = e.data;",
"      if (!d || d.zai !== 1 || !d.cmd) return;",
"      /* trusted senders: the worker itself, and the saved pocket file",
"       * (file:// origin on Chrome, null on Safari) hosting the",
"       * sandboxed app view */",
"      if (e.origin !== 'null' && e.origin !== 'file://' && WORKER && e.origin !== WORKER) return;",
"      if (SD && d.cmd !== 'init' && d.cmd !== 'getstate') {",
"        /* v5 sandbox: back/forward/reload/navigate are SHELL-owned \u2014 the",
"         * shell re-renders entries itself; only state exchange reaches",
"         * the frame. Anything else still arrives (e.g. from the worker)",
"         * and is forwarded as a request. */",
"        if (d.cmd === 'back') { up({ type: 'goback' }); return; }",
"        if (d.cmd === 'forward') { up({ type: 'gofwd' }); return; }",
"        if (d.cmd === 'reload') { up({ type: 'reloadreq' }); return; }",
"        if (d.cmd === 'navigate') { if (d.url) nav(String(d.url)); return; }",
"      }",
"      switch (d.cmd) {",
"        case 'init':",
"          if (Array.isArray(d.jar)) {",
"            var jarM = {};",
"            jar.forEach(function (c) { if (c && c.name) jarM[c.name] = c; });",
"            d.jar.forEach(function (c) { if (c && c.name) jarM[c.name] = c; });",
"            jar = Object.keys(jarM).map(function (k) { return jarM[k]; });",
"          }",
"          if (d.ls) {",
"            Object.keys(d.ls).forEach(function (k) {",
"              if (!(k in lsMirror)) lsMirror[k] = d.ls[k];",
"            });",
"          }",
"          seedDocumentCookies();",
"          reportNav();",
"          break;",
"        case 'back': history.back(); break;",
"        case 'forward': history.forward(); break;",
"        case 'reload': location.reload(); break;",
"        case 'navigate':",
"          if (d.url) location.href = mapUrl(String(d.url));",
"          break;",
"        case 'getstate': reportNav(); break;",
"      }",
"    } catch (err) { /* ignore */ }",
"  });",
"",
"  /* ---------- v5: escape sentinel --------------------------------------",
"   * pagehide fires when this frame navigates ANYWHERE (the one thing",
"   * the location rewrites could not catch \u2014 e.g. `window.location = X`",
"   * left raw on purpose, or location.reload()). The shell re-arms this",
"   * around intentional srcdoc swaps; an UNARMED 'bye' means the document",
"   * escaped \u2014 the shell recovers by re-rendering the current entry. */",
"  try {",
"    if (SD) window.addEventListener('pagehide', function () { up({ type: 'bye' }); });",
"  } catch (eBye) { /* ignore */ }",
"",
"  /* ---------- boot ---------- */",
"  up({ type: 'hello', url: curUrl(), title: document.title || '' });",
"  reportNav();",
"})();",
""
].join("\n");

/* ============================================================ */

addEventListener('fetch', (event) => {
  event.respondWith(handle(event.request, event));
});

async function handle(req, event) {
  try {
    const url = new URL(req.url);
    const method = req.method.toUpperCase();

    /* ---- CORS preflight ---- */
    if (method === 'OPTIONS') {
      return new Response(null, { status: 204, headers: corsHeaders(req, new Headers()) });
    }

    /* ---- public endpoints ---- */
    if (url.pathname === '/__status') {
      const env = envOf(event);
      const token = env.PROXY_TOKEN || '';
      let tokenOk = null;
      if (token) {
        const supplied = url.searchParams.has('__t') || req.headers.get('x-proxy-token') != null;
        if (supplied) tokenOk = (url.searchParams.get('__t') === token || req.headers.get('x-proxy-token') === token);
      }
      /* v5: "entry" is the tokenized ROOT DOCUMENT path — the saved
       * pocket file fetches it to boot the app without ever knowing
       * the token key or the upstream host. Neutral JSON: no z.ai
       * strings anywhere in this body. */
      const entry = tokPath(chatUpstream(event) + '/');
      return json({ ok: true, name: VERSION, time: new Date().toISOString(), token_required: !!token, token_ok: tokenOk, entry: entry }, req);
    }

    /* ---- neutral favicon: never a proxied page ---- */
    if (url.pathname === '/favicon.ico' || url.pathname === '/favicon.png') {
      return new Response(null, { status: 204, headers: corsHeaders(req, new Headers()) });
    }


    /* ---- live upstream probe report (v3) ----
     * Public like /__status: no secrets, and it must stay reachable
     * in every cookie/token state — when the app "opens straight to
     * a blocked page", this page tells the user WHY. */
    if (url.pathname === '/__diag') {
      return diagPage(req, event);
    }


    /* ---- token gate ---- */
    const env = envOf(event);
    const token = env.PROXY_TOKEN || '';
    if (token && !(await checkToken(req, url, token))) {
      const accept = req.headers.get('accept') || '';
      if (method === 'GET' && accept.includes('text/html')) {
        /* a human navigation with a wrong/missing token → the setup page
         * (with the "not accepted" hint only when a token was tried) */
        const attempted = url.searchParams.has('__t') || req.headers.get('x-proxy-token') != null;
        return landing(event, attempted);
      }
      return json({ error: 'unauthorized', hint: 'set X-Proxy-Token header or __t query param' }, req, 401);
    }

    /* ---- token was supplied in the query: remember it, clean the URL ---- */
    if (token && url.searchParams.has('__t')) {
      const clean = new URL(req.url);
      clean.searchParams.delete('__t');
      const h = new Headers({ location: clean.pathname + (clean.search || ''), 'cache-control': 'no-store' });
      h.append('set-cookie', tokenCookie(token));
      return new Response(null, { status: 302, headers: corsHeaders(req, h) });
    }

    /* ---- v5: the root is a NEUTRAL service page ------------------
     * The phone never navigates here for content anymore — and it
     * must never serve z.ai HTML, so a content classifier that
     * fetches the root sees a boring status page, not an AI chat
     * app. (The token gate above has already handled PROXY_TOKEN,
     * including the __t-query 302 cleanup, so this only runs for
     * token-satisfied or tokenless workers.) */
    if (url.pathname === '/') {
      return servicePage(req);
    }

    /* ---- session cookie clear ---- */
    if (url.pathname === '/__clear') {
      const h = new Headers({ location: '/', 'cache-control': 'no-store' });
      /* expire every cookie the browser sent, plus the token cookie */
      const ck = req.headers.get('cookie') || '';
      const seen = new Set(['__zai_t']);
      ck.split(';').forEach((kv) => {
        const n = kv.split('=')[0].trim();
        if (n) seen.add(n);
      });
      seen.forEach((n) => h.append('set-cookie', n + '=; Path=/; Max-Age=0; Secure; SameSite=None; Partitioned'));
      return new Response(null, { status: 302, headers: corsHeaders(req, h) });
    }

    /* ---- websocket upgrade ---- */
    if (req.headers.get('upgrade') === 'websocket') {
      return proxyWebsocket(req, url, event);
    }

    /* ---- route resolution ---- */
    let pfx = '';       // proxy prefix for this document ('' = transparent)
    let upstream = null; // absolute upstream URL
    let host = null;     // upstream host
    let tokMode = false; // this request came through /__t/<token>

    if (url.pathname.startsWith('/__t/')) {
      /* v4/v5 opaque token: the ONLY form content URLs take now */
      const tok = url.pathname.slice(5);
      const dec = decTok(tok);
      if (!dec || !/^https?:\/\//i.test(dec)) {
        return json({ error: 'bad token' }, req, 400);
      }
      const du = new URL(dec);
      if (!hostAllowed(du.host, event)) {
        return json({ error: 'host not allowed', allowed_suffixes: allowList(event) }, req, 403);
      }
      host = du.host;
      pfx = '';
      upstream = du.toString();
      tokMode = true;
    } else if (url.pathname.startsWith('/p/')) {
      const rest = url.pathname.slice(3); // "<host>/path..."
      const slash = rest.indexOf('/');
      host = slash < 0 ? rest : rest.slice(0, slash);
      const path = slash < 0 ? '/' : rest.slice(slash);
      if (!hostAllowed(host)) {
        return json({ error: 'host not allowed', host: host, allowed_suffixes: allowList(event) }, req, 403);
      }
      pfx = '/p/' + host;
      upstream = 'https://' + host + path + url.search;
    } else {
      /* v5: bare paths no longer mirror chat.z.ai — the transparent
       * catch-all is GONE. Nothing navigates to this worker; the only
       * content route is /__t/<token>. Answer a neutral 404 so the
       * origin never serves anything classifiable. */
      return json({ ok: false, service: 'zp', status: 404, note: 'nothing is served at this path' }, req, 404);
    }

    /* ---- query handling ----
     * Transparent/legacy requests may carry the proxy token (__t) in
     * the query — strip it before going upstream. Token requests carry
     * their whole query INSIDE the token; any extra params the browser
     * appended (e.g. EventSource adding __t) are merged in, minus __t. */
    const upUrl = new URL(upstream);
    if (tokMode) {
      for (const [k, v] of url.searchParams) {
        if (k === '__t') continue;
        if (!upUrl.searchParams.has(k)) upUrl.searchParams.set(k, v);
      }
    } else if (upUrl.searchParams.has('__t')) {
      upUrl.searchParams.delete('__t');
    }

    /* ---- build upstream request ---- */
    const h = new Headers();
    const skipReq = new Set(['host', 'origin', 'referer', 'cookie', 'connection', 'keep-alive', 'upgrade',
      'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'content-length', 'accept-encoding',
      'x-cookie', 'x-proxy-token', 'x-set-cookie']);
    /* v3: Cloudflare's edge injects its own connection headers
     * (cf-connecting-ip, cf-ipcountry, cf-ray, cf-visitor,
     * x-forwarded-for, cdn-loop, true-client-ip, ...) into every
     * request that reaches this worker. Forwarding them to
     * chat.z.ai — which runs behind Cloudflare itself — sends
     * forged edge headers into another zone's WAF. They are
     * dropped here, always. */
    const dropExact = new Set(['cdn-loop', 'true-client-ip', 'x-real-ip']);
    const dropPrefix = ['cf-', 'x-forwarded'];
    for (const [k, v] of req.headers) {
      const lk = k.toLowerCase();
      if (skipReq.has(lk)) continue;
      if (dropExact.has(lk)) continue;
      let drop = false;
      for (let i = 0; i < dropPrefix.length; i++) { if (lk.startsWith(dropPrefix[i])) { drop = true; break; } }
      if (drop) continue;
      h.set(k, v);
    }
    h.set('accept-encoding', 'gzip, deflate, br');
    h.set('cookie', mergeCookies(req.headers.get('cookie') || '', req.headers.get('x-cookie') || ''));
    h.set('origin', 'https://' + host);
    h.set('referer', 'https://' + host + '/');

    let body = undefined;
    let needDuplex = false;
    if (method !== 'GET' && method !== 'HEAD') {
      const cl = parseInt(req.headers.get('content-length') || '0', 10);
      if (cl > 0 && cl < 32 * 1024 * 1024) {
        body = await req.arrayBuffer(); // keeps Content-Length intact (important for OSS uploads)
        h.set('content-length', String(body.byteLength));
      } else {
        body = req.body; // stream big/unknown-size uploads
        needDuplex = true;
      }
    }

    let res;
    let retried = false;
    try {
      const fetchInit = { method: method, headers: h, redirect: 'manual' };
      if (body !== undefined) fetchInit.body = body;
      if (needDuplex) fetchInit.duplex = 'half';
      res = await fetch(upUrl.toString(), fetchInit);
      /* ---- v3: a 403/429 on a safe GET can be a WAF trip-wire fed
       * by leftover request headers — retry ONCE with a minimal,
       * clean header set before relaying the block page. ---- */
      if ((res.status === 403 || res.status === 429) && (method === 'GET' || method === 'HEAD')) {
        try {
          const res2 = await fetch(upUrl.toString(), { method: method, headers: minimalHeaders(req, host), redirect: 'manual' });
          retried = true; /* a retry attempt happened — tagged either way */
          if (res2.status !== res.status) {
            try { if (res.body && res.body.cancel) res.body.cancel(); } catch (e) { /* ignore */ }
            res = res2;
            retried = true;
          } else {
            try { if (res2.body && res2.body.cancel) res2.body.cancel(); } catch (e) { /* ignore */ }
          }
        } catch (e2) { /* keep the original response */ }
      }
    } catch (err) {
      return json({ error: 'upstream fetch failed', detail: String(err && err.message || err) }, req, 502);
    }

    /* ---- redirect handling: rewrite Location and let the browser follow inside the worker ---- */
    const loc = res.headers.get('location');
    if (loc && res.status >= 300 && res.status < 400 && res.status !== 304) {
      const mapped = mapLocation(loc, upUrl, event, tokMode);
      const rh = scrubHeaders(res.headers);
      reissueCookies(res, rh, event);
      rh.set('location', mapped);
      maybeSetTokenCookie(req, rh, event);
      return new Response(null, { status: res.status, headers: corsHeaders(req, rh) });
    }

    /* ---- normal responses ---- */
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    const outHeaders = scrubHeaders(res.headers);
    reissueCookies(res, outHeaders, event);
    maybeSetTokenCookie(req, outHeaders, event);
    outHeaders.set('x-final-url', res.url || upUrl.toString());
    if (retried) outHeaders.set('x-zp-retry', '1');
    const outCt = corsHeaders(req, outHeaders);

    if (ct.includes('text/html')) {
      const text = await res.text();
      const html = rewriteHtml(text, pfx, host, new URL(req.url).origin, token, allowList(event),
        tokMode ? upUrl.toString() : null);
      return new Response(html, { status: res.status, headers: outCt });
    }
    if (ct.includes('text/css')) {
      const text = await res.text();
      const css = rewriteCss(text, pfx, host, allowList(event), tokMode ? upUrl.toString() : null, new URL(req.url).origin);
      return new Response(css, { status: res.status, headers: outCt });
    }
    /* ---- v5: JavaScript location-assignment rewrite ----------------
     * Inside the sandbox frame the document lives at about:srcdoc; a
     * script that does location.href = X (or location.assign/replace)
     * would navigate the frame OUT of the sandbox — to a URL the org
     * filter blocks. Rewriting those tokens to __zaiLoc (the fake
     * location object the runtime patch installs BEFORE any site
     * script runs) turns every SPA redirect into a postMessage that
     * the pocket shell turns into a fresh sandboxed document. Reads
     * (location.href/pathname/origin...) are rewritten too, so SPA
     * routers hydrate against the REAL upstream URL instead of
     * about:srcdoc. Conservative patterns only — Superwork's v2.12
     * lesson: an aggressive wrap can emit a syntax error and kill an
     * entire bundle at parse time. */
    if (tokMode && /javascript|ecmascript|text\/jscript/i.test(ct)) {
      const text = await res.text();
      const js = rewriteJsLocation(text);
      if (js !== text) {
        const h2 = new Headers(outCt);
        h2.set('x-zp-jsrw', '1');
        return new Response(js, { status: res.status, headers: h2 });
      }
      return new Response(text, { status: res.status, headers: outCt });
    }

    return new Response(res.body, { status: res.status, headers: outCt });
  } catch (err) {
    return json({ error: 'proxy error', detail: String(err && err.message || err) }, req, 500);
  }
}

/* ============================================================ helpers */

function envOf(event) {
  return (event && event.env) || globalThis.__ZAI_ENV || {};
}
function allowList(event) {
  const extra = envOf(event).EXTRA_HOSTS || '';
  const arr = ALLOW.slice();
  String(extra).split(',').forEach((h) => {
    h = h.trim().toLowerCase();
    if (h && arr.indexOf(h) < 0) arr.push(h);
  });
  return arr;
}
function hostAllowed(host, event) {
  host = String(host || '').toLowerCase();
  const list = allowList(event);
  for (const a of list) {
    if (host === a || host.endsWith('.' + a)) return true;
  }
  return false;
}
async function checkToken(req, url, token) {
  if (req.headers.get('x-proxy-token') === token) return true;
  if (url.searchParams.get('__t') === token) return true;
  const ck = req.headers.get('cookie') || '';
  const m = ck.match(/(?:^|;\s*)__zai_t=([^;]+)/);
  if (m && decodeURIComponent(m[1]) === token) return true;
  return false;
}
function tokenCookie(token) {
  return '__zai_t=' + encodeURIComponent(token) + '; Path=/; Max-Age=31536000; Secure; SameSite=None; Partitioned';
}
function redirect(req, to) {
  const h = new Headers({ location: to, 'cache-control': 'no-store' });
  return new Response(null, { status: 302, headers: corsHeaders(req, h) });
}
function maybeSetTokenCookie(req, h, event) {
  const token = envOf(event).PROXY_TOKEN || '';
  if (!token) return;
  const ck = req.headers.get('cookie') || '';
  if (ck.indexOf('__zai_t=') >= 0) return;
  h.append('set-cookie', tokenCookie(token));
}

function mergeCookies(a, b) {
  const seen = new Map();
  const add = (str) => {
    if (!str) return;
    str.split(';').forEach((kv) => {
      kv = kv.trim();
      if (!kv) return;
      const name = kv.split('=')[0];
      if (!seen.has(name)) seen.set(name, kv);
    });
  };
  add(a); // browser-native cookies win
  add(b); // patch-supplied fallback cookies fill gaps
  return Array.from(seen.values()).join('; ');
}

/* response headers we must not forward */
const SCRUB = new Set(['content-security-policy', 'content-security-policy-report-only', 'x-frame-options',
  'strict-transport-security', 'cross-origin-opener-policy', 'cross-origin-embedder-policy',
  'cross-origin-resource-policy', 'content-encoding', 'content-length', 'transfer-encoding',
  'connection', 'keep-alive', 'upgrade', 'set-cookie', 'report-to', 'nel', 'vary']);

function scrubHeaders(headers) {
  const h = new Headers();
  for (const [k, v] of headers) {
    if (!SCRUB.has(k.toLowerCase())) h.set(k, v);
  }
  return h;
}

/* re-issue upstream cookies for this worker's domain (CHIPS-partitioned so they work in the app iframe) */
function reissueCookies(res, h, event) {
  try {
    let raw = [];
    if (typeof res.headers.getSetCookie === 'function') raw = res.headers.getSetCookie();
    else {
      const single = res.headers.get('set-cookie');
      if (single) raw = [single];
    }
    if (!raw.length) return;
    raw.forEach((sc) => {
      const parts = String(sc).split(';');
      const nv = parts[0].trim();
      if (!nv) return;
      let expires = null, maxAge = null, httpOnly = false;
      for (let i = 1; i < parts.length; i++) {
        const p = parts[i].trim();
        const k = p.split('=')[0].toLowerCase();
        if (k === 'expires') expires = p.slice(8).trim();
        else if (k === 'max-age') maxAge = p.slice(8).trim();
        else if (k === 'httponly') httpOnly = true;
      }
      let out = nv + '; Path=/; Secure; SameSite=None; Partitioned';
      if (expires) out += '; Expires=' + expires;
      if (maxAge !== null && maxAge !== undefined && maxAge !== '') out += '; Max-Age=' + maxAge;
      if (httpOnly) out += '; HttpOnly';
      h.append('set-cookie', out);
    });
    /* expose the raw cookies so the patch/shell can mirror them */
    h.set('x-set-cookie', encodeURIComponent(JSON.stringify(raw)));
  } catch (e) { /* ignore */ }
}

function corsHeaders(req, h) {
  h.set('access-control-allow-origin', '*');
  h.set('access-control-allow-methods', 'GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS');
  const reqH = req.headers.get('access-control-request-headers');
  h.set('access-control-allow-headers', reqH || '*');
  h.set('access-control-expose-headers', 'content-disposition, content-type, x-set-cookie, x-final-url, filename, x-zp-retry');
  h.set('access-control-max-age', '86400');
  return h;
}

function json(obj, req, status) {
  const h = new Headers({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  return new Response(JSON.stringify(obj), { status: status || 200, headers: corsHeaders(req, h) });
}

/* ---- v3: the minimal clean header set used by the 403/429 retry ---- */
function minimalHeaders(req, host) {
  const h = new Headers();
  const ua = req.headers.get('user-agent');
  if (ua) h.set('user-agent', ua);
  const al = req.headers.get('accept-language');
  if (al) h.set('accept-language', al);
  h.set('accept', req.headers.get('accept') || '*/*');
  h.set('accept-encoding', 'gzip, deflate, br');
  const ck = mergeCookies(req.headers.get('cookie') || '', req.headers.get('x-cookie') || '');
  if (ck) h.set('cookie', ck);
  h.set('origin', 'https://' + host);
  h.set('referer', 'https://' + host + '/');
  return h;
}

/* ---- v3: /__diag — live upstream probes ------------------------------
 *
 * Three GETs against the chat upstream, each shaped like a
 * different worker generation, so the page shows exactly WHICH
 * request style z.ai blocks (if any) from this worker's egress:
 *   1. "app"     — what v3 forwards for the app document
 *                  (browser-like, CF edge headers stripped)
 *   2. "minimal" — accept + user-agent + origin/referer only
 *   3. "forged"  — what v2 ACTUALLY forwarded: browser-like plus
 *                  the Cloudflare edge headers that ride along on
 *                  every request hitting the worker
 */
function esc(s) {
  return String(s == null ? '' : s).replace(/&/g, '&amp;').replace(/</g, '&lt;')
    .replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

async function diagProbe(event, kind) {
  const host = chatHost(event);
  const up = chatUpstream(event) + '/';
  const h = new Headers();
  h.set('accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8');
  h.set('accept-encoding', 'gzip, deflate, br');
  h.set('accept-language', 'en-US,en;q=0.9');
  h.set('user-agent', 'Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Mobile Safari/537.36');
  h.set('origin', 'https://' + host);
  h.set('referer', 'https://' + host + '/');
  if (kind === 'minimal') {
    h.delete('accept-language');
  }
  if (kind === 'forged') {
    h.set('cf-connecting-ip', '198.51.100.7');
    h.set('cf-ipcountry', 'US');
    h.set('cf-ray', 'diag-probe');
    h.set('x-forwarded-for', '198.51.100.7');
    h.set('cdn-loop', 'cloudflare');
  }
  try {
    const res = await fetch(up, { method: 'GET', headers: h, redirect: 'manual' });
    let snippet = '';
    try { snippet = (await res.text()).slice(0, 240); } catch (e) { snippet = '(body unreadable)'; }
    return {
      error: false,
      status: res.status,
      type: (res.headers.get('content-type') || '').split(';')[0] || '(none)',
      server: res.headers.get('server') || '(none)',
      ray: res.headers.get('cf-ray') || '(no cf-ray — upstream not on Cloudflare)',
      mitigated: res.headers.get('cf-mitigated') || '',
      location: res.headers.get('location') || '',
      snippet: snippet.trim().replace(/\s+/g, ' ')
    };
  } catch (err) {
    return { error: true, status: 0, detail: String((err && err.message) || err) };
  }
}

async function diagPage(req, event) {
  /* what the phone's own request arrived with (added by Cloudflare's
   * edge on the way in) — the v3 worker no longer forwards these */
  const incoming = [];
  for (const [k, v] of req.headers) {
    const lk = k.toLowerCase();
    if (lk.startsWith('cf-') || lk.startsWith('x-forwarded') || lk === 'cdn-loop' || lk === 'true-client-ip' || lk === 'x-real-ip') {
      incoming.push(k + ': ' + v);
    }
  }
  const p = await Promise.all([diagProbe(event, 'app'), diagProbe(event, 'minimal'), diagProbe(event, 'forged')]);
  const app = p[0], mini = p[1], forged = p[2];

  const verdictOf = (pr) => pr.error ? 'fetch failed' : (pr.status === 200 ? 'answered normally (200)' :
    (pr.status === 403 || pr.status === 429 ? 'BLOCKED (' + pr.status + ')' : 'HTTP ' + pr.status));

  let verdict, verdictColor;
  if (app.error || app.status !== 200) {
    if (!app.error && (app.status === 403 || app.status === 429)) {
      verdict = 'z.ai is BLOCKING this worker\u2019s requests (HTTP ' + app.status + '). That block page is what the app shows. Send this whole page to whoever helps you.';
      verdictColor = '#F87171';
    } else {
      verdict = 'The worker could not fetch the app page from ' + esc(chatHost(event)) + ' (' + esc(app.error ? app.detail : 'HTTP ' + app.status) + '). The app cannot work until this is fixed.';
      verdictColor = '#F87171';
    }
  } else if (!forged.error && (forged.status === 403 || forged.status === 429)) {
    verdict = 'z.ai answers normally, but blocks the OLD v2-style request (with forwarded Cloudflare headers). Your v3 fix is exactly right \u2014 keep it deployed.';
    verdictColor = '#FBBF24';
  } else {
    verdict = 'z.ai answers this worker normally. If the app still shows a block page, the block is NOT between this worker and z.ai \u2014 it is between your phone and this worker (network filter / browser). Try this page from a different network (Wi-Fi vs mobile data) to compare.';
    verdictColor = '#4ADE80';
  }

  const probeRow = (name, desc, pr) =>
    '<div class="probe"><div class="ph"><b>' + name + '</b><span class="code">' + esc(desc) + '</span></div>' +
    '<div class="line">status: <b class="' + (pr.error ? 'bad' : (pr.status === 200 ? 'ok' : (pr.status === 403 || pr.status === 429 ? 'bad' : 'warn'))) + '">' + esc(verdictOf(pr)) + '</b></div>' +
    (pr.error ? '<div class="line">error: ' + esc(pr.detail) + '</div>' :
      '<div class="line meta">type ' + esc(pr.type) + ' \u00b7 server ' + esc(pr.server) + ' \u00b7 cf-ray ' + esc(pr.ray) +
      (pr.mitigated ? ' \u00b7 cf-mitigated ' + esc(pr.mitigated) : '') +
      (pr.location ? ' \u00b7 location ' + esc(pr.location) : '') + '</div>' +
      '<div class="snip">' + esc(pr.snippet) + '</div>') +
    '</div>';

  const html = '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">' +
    '<title>z.ai pocket \u2014 worker diagnostics</title>' +
    '<style>' +
    ':root{--bg:#0B0D12;--panel:#14161F;--panel2:#1A1D28;--line:rgba(255,255,255,.08);--txt:#E7E9EE;--sub:#9AA1AD}' +
    '*{box-sizing:border-box}body{margin:0;padding:18px 14px 40px;background:var(--bg);color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,system-ui,"Segoe UI",Roboto,sans-serif;font-size:14px;line-height:1.55}' +
    'h1{font-size:18px;margin:0 0 2px}.tag{color:var(--sub);font-size:12.5px;margin-bottom:14px}' +
    '.verdict{padding:12px 14px;border-radius:12px;background:rgba(255,255,255,.05);border-left:3px solid ' + verdictColor + ';margin-bottom:14px;font-size:13.5px}' +
    '.card{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:13px 14px;margin-bottom:12px}' +
    '.card b{font-size:13px}.card .code,.snip{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;color:#B9B6FB;word-break:break-all}' +
    '.probe{background:var(--panel);border:1px solid var(--line);border-radius:14px;padding:13px 14px;margin-bottom:12px}' +
    '.ph{display:flex;justify-content:space-between;gap:10px;align-items:baseline;margin-bottom:6px}' +
    '.ph .code{color:var(--sub);font-size:10.5px}' +
    '.line{font-size:12.5px;color:#C4C9D4;margin:2px 0}.line b{font-family:ui-monospace,SFMono-Regular,Menlo,monospace}' +
    '.ok{color:#4ADE80}.bad{color:#F87171}.warn{color:#FBBF24}' +
    '.meta{color:var(--sub)}.snip{margin-top:7px;padding:9px 10px;border-radius:9px;background:var(--panel2);border:1px solid var(--line);max-height:110px;overflow:hidden}' +
    'ul{margin:6px 0 0;padding-left:18px}li{font-size:12px;color:var(--sub);margin:3px 0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;word-break:break-all}' +
    '.foot{color:var(--sub);font-size:11.5px;line-height:1.6}' +
    '</style></head><body>' +
    '<h1>z.ai pocket \u2014 worker diagnostics</h1>' +
    '<div class="tag">' + esc(VERSION) + ' \u00b7 ' + esc(new Date().toISOString()) + '</div>' +
    '<div class="verdict">' + esc(verdict) + '</div>' +
    probeRow('Probe 1 \u00b7 as the app (v3 style)', 'browser-like, CF headers stripped', app) +
    probeRow('Probe 2 \u00b7 minimal', 'accept + user-agent + origin only', mini) +
    probeRow('Probe 3 \u00b7 old v2 style', 'browser-like + forwarded CF headers', forged) +
    '<div class="card"><b>What your request arrived with</b>' +
    (incoming.length ? '<ul>' + incoming.map((l) => '<li>' + esc(l) + '</li>').join('') + '</ul>' :
      '<ul><li>(no Cloudflare edge headers seen \u2014 this request did not come through a Cloudflare edge)</li></ul>') +
    '<div class="foot">These headers were what v2 wrongly forwarded to z.ai. v3 strips them; Probe 3 shows what z.ai thinks of them.</div></div>' +
    '<div class="foot">This page made three live calls to ' + esc(chatUpstream(event)) + '/ from inside the worker. It works with or without the PROXY_TOKEN, in any cookie state.</div>' +
    '</body></html>';

  return new Response(html, { status: 200, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}

/* map a Location header value into proxy space */
function mapLocation(loc, upUrl, event, tokMode) {
  try {
    const abs = new URL(loc, upUrl);
    if (abs.protocol !== 'https:' && abs.protocol !== 'http:') return loc;
    if (!hostAllowed(abs.host, event)) return loc; // external redirect — pass through untouched
    if (tokMode) {
      /* this response came from a /__t/<token> request — there is no
       * path prefix and (v5) no transparent root anymore: EVERY
       * allowed target becomes a token, same-host or not, so the
       * fetching shell can follow it without hitting a neutral 404. */
      return tokPath(abs.toString());
    }
    if (abs.host === upUrl.host) {
      const pfx = prefixForHost(upUrl.host, event);
      return pfx + abs.pathname + abs.search;
    }
    return tokPath(abs.toString()); // v4: opaque token, host stays unreadable
  } catch (e) {
    return loc;
  }
}
function prefixForHost(host, event) {
  if (host === chatHost(event)) return ''; // transparent: the app lives at /
  return '/p/' + host;
}

/* ---------------- HTML rewriting ---------------- */
/* Map a URL-ish attribute value into proxy space.
 * tokDoc: set when this document was itself served through
 *         /__t/<token> — it has NO path prefix to re-attach, so
 *         every URL it references (absolute, root-relative,
 *         relative) must be absolutized against tokDoc and
 *         tokenized: that is what keeps the whole app sandboxed
 *         inside opaque worker paths.
 * v5: in tokDoc mode the token path is emitted ABSOLUTE (worker
 *         origin + /__t/…) because the document is painted into an
 *         about:srcdoc frame — a relative "/__t/…" cannot resolve
 *         against about:srcdoc's inherited file:// base, so every
 *         subresource (script, css, img) would silently fail. */
function mapAttr(v, pfx, host, allow, tokDoc, workerOrigin) {
  try {
    const s = String(v || '').trim();
    if (!s) return v;
    if (/^(data|blob|about|javascript|mailto|tel|sms|intent|ms-|chrome|file|#)/i.test(s)) return v;
    if (tokDoc) {
      const abs = new URL(s, tokDoc);
      if (abs.protocol !== 'https:' && abs.protocol !== 'http:') return v;
      const ok = allow.some((a) => abs.host === a || abs.host.endsWith('.' + a));
      if (!ok) return v;
      const tp = tokPath(abs.toString());
      return tp ? (workerOrigin ? workerOrigin.replace(/\/$/, '') + tp : tp) : v;
    }
    let m;
    if ((m = s.match(/^https?:\/\/([^\/?#]+)/i))) {
      const h = m[1].toLowerCase();
      const ok = allow.some((a) => h === a || h.endsWith('.' + a));
      if (!ok) return v;
      if (h === host) {
        const rest = s.slice(m[0].length) || '/';
        return pfx + rest;
      }
      return tokPath(s); // v4: opaque token, host stays unreadable
    }
    if ((m = s.match(/^\/\/([^\/?#]+)/))) {
      const h = m[1].toLowerCase();
      const ok = allow.some((a) => h === a || h.endsWith('.' + a));
      if (!ok) return v;
      if (h === host) {
        const rest = s.slice(m[0].length) || '/';
        return pfx + rest;
      }
      return tokPath('https:' + s); // protocol-relative → https token
    }
    if (s.charAt(0) === '/' && s.charAt(1) !== '/') return pfx + s;
    return v;
  } catch (e) {
    return v;
  }
}

const ATTR_NAMES = 'href|src|action|formaction|poster|data-src|data-href|data-url|data-background';

function rewriteHtml(text, pfx, host, workerOrigin, token, allow, tokDoc) {
  try {
    /* strip CSP meta tags and base targets */
    text = text.replace(/<meta[^>]+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi, '');
    text = text.replace(/<base\b([^>]*?)\s+target\s*=\s*["'][^"']*["']/gi, '<base$1');

    /* rewrite URL attributes */
    const attrRe = new RegExp('(\\s(?:' + ATTR_NAMES + ')\\s*=\\s*)("([^"]*)"|\'([^\']*)\')', 'gi');
    text = text.replace(attrRe, (whole, pre, quoted, dq, sq) => {
      const v = dq !== undefined ? dq : sq;
      const nv = mapAttr(v, pfx, host, allow, tokDoc, workerOrigin);
      if (nv === v) return whole;
      return pre + '"' + String(nv).replace(/"/g, '%22') + '"';
    });

    /* srcset lists */
    const ssRe = /(\ssrcset\s*=\s*)("([^"]*)"|'([^']*)')/gi;
    text = text.replace(ssRe, (whole, pre, quoted, dq, sq) => {
      const v = dq !== undefined ? dq : sq;
      const nv = v.split(',').map((cand) => {
        const t = cand.trim();
        if (!t) return '';
        const sp = t.indexOf(' ');
        const u = sp < 0 ? t : t.slice(0, sp);
        const rest = sp < 0 ? '' : t.slice(sp);
        const nu = mapAttr(u, pfx, host, allow, tokDoc, workerOrigin);
        return nu === u ? t : nu + rest;
      }).filter(Boolean).join(', ');
      if (nv === v) return whole;
      return pre + '"' + nv + '"';
    });

    /* url() inside style="..." attributes only (inline JS safety) */
    const styleRe = /(\sstyle\s*=\s*)("([^"]*)"|'([^']*)')/gi;
    text = text.replace(styleRe, (whole, pre, quoted, dq, sq) => {
      const v = dq !== undefined ? dq : sq;
      const nv = v.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (w, q, u) => {
        const nu = mapAttr(u, pfx, host, allow, tokDoc, workerOrigin);
        return nu === u ? w : "url('" + nu + "')";
      });
      if (nv === v) return whole;
      return pre + '"' + nv.replace(/"/g, '&quot;') + '"';
    });

    /* inject config + runtime patch as the first script */
    const cfg = { pfx: pfx, host: host, worker: workerOrigin, token: token || '', allow: allow,
      key: TOK_KEY, tok: !!tokDoc, doc: tokDoc || '', sd: !!tokDoc };
    const inject = '<scr' + 'ipt>window.__ZAI__=' + JSON.stringify(cfg) + ';' + PATCH_JS + '</scr' + 'ipt>';
    if (/<head[^>]*>/i.test(text)) text = text.replace(/<head[^>]*>/i, (m) => m + inject);
    else if (/<html[^>]*>/i.test(text)) text = text.replace(/<html[^>]*>/i, (m) => m + inject);
    else text = inject + text;
    return text;
  } catch (e) {
    return text;
  }
}

function rewriteCss(text, pfx, host, allow, tokDoc, workerOrigin) {
  try {
    text = text.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (w, q, u) => {
      const nu = mapAttr(u, pfx, host, allow, tokDoc, workerOrigin);
      return nu === u ? w : 'url("' + nu + '")';
    });
    text = text.replace(/@import\s*(['"])([^'"]+)\1/gi, (w, q, u) => {
      /* \s* — z.ai's CDN ships minified css like @import"https://…";
       * with NO space and NO parens. That exact form leaked the
       * upstream hostname straight to the browser once. */
      const nu = mapAttr(u, pfx, host, allow, tokDoc, workerOrigin);
      return nu === u ? w : '@import "' + nu + '"';
    });
    return text;
  } catch (e) {
    return text;
  }
}

/* ---------------- v5: JS location-assignment rewrite ----------------
 * Served scripts may navigate the sandbox frame with
 *   location.href = X · location.assign/replace(X)
 * and SPA routers read location.href / pathname / origin to hydrate.
 * Inside the sandbox the document sits at about:srcdoc, so reads are
 * nonsense and writes navigate OUT (straight into the org filter).
 * Every occurrence of those tokens becomes __zaiLoc.<prop> — the fake
 * location the runtime patch installs first: reads answer the REAL
 * upstream URL, writes postMessage the pocket shell (the href property
 * carries a setter, so `__zaiLoc.href = X` is valid even inside
 * ternaries). Patterns are deliberately conservative — the Superwork
 * v2.12 lesson: one bad wrap is a parse-time syntax error that kills a
 * whole bundle. `location = X` / `window.location = X` LVALUE forms are
 * left RAW (a real navigation the shell's escape recovery catches).
 * A prop name after `location.` keeps this from ever touching bare
 * `location` reads or unrelated identifiers. */
function rewriteJsLocation(text) {
  try {
    if (!/location\b/.test(text)) return text;
    let out = text;
    /* member forms, prefixed (window/document/self/top/parent/globalThis): */
    out = out.replace(/(?:window|document|self|top|parent|globalThis|global)\.location\.(href|assign|replace|reload|pathname|search|hash|origin|host|hostname|protocol|port|toString)\b/gi,
      (w, prop) => '__zaiLoc.' + prop);
    /* bare location.<prop> — the leading (?<![.\w$]) stops it from
     * matching x.location.href (nested-frame access) or mylocation.href: */
    out = out.replace(/(?<![.\w$])location\.(href|assign|replace|reload|pathname|search|hash|origin|host|hostname|protocol|port|toString)\b/gi,
      (w, prop) => '__zaiLoc.' + prop);
    return out;
  } catch (e) {
    return text;
  }
}

/* ---------------- v5: neutral service page (the root) ----------------
 * Everything a classifier can crawl at this origin must look like a
 * boring uptime page: no product names, no chat UI, no z.ai strings,
 * no AI vocabulary. The real app only ever lives behind opaque
 * /__t/<token> fetches. */
function servicePage(req) {
  const html = '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1">' +
    '<title>service</title>' +
    '<style>body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;background:#F2F3F5;color:#3A3D45;font:15px/1.5 -apple-system,BlinkMacSystemFont,system-ui,"Segoe UI",Roboto,sans-serif}' +
    '.c{text-align:center}.d{width:44px;height:44px;margin:0 auto 14px;border-radius:50%;background:#1F9D55;display:flex;align-items:center;justify-content:center}.d svg{width:24px;height:24px}' +
    'h1{margin:0;font-size:17px;font-weight:600;color:#101114}p{margin:6px 0 0;color:#82868F;font-size:13px}' +
    'code{font:12px/1 ui-monospace,SFMono-Regular,Menlo,monospace;background:#E3E5EA;border-radius:6px;padding:2px 6px;color:#3A3D45}</style></head>' +
    '<body><div class="c"><div class="d"><svg viewBox="0 0 64 64"><path d="M18 34l10 10 20-24" stroke="#fff" stroke-width="7" fill="none" stroke-linecap="round" stroke-linejoin="round"/></svg></div>' +
    '<h1>Service online</h1>' +
    '<p>Relay endpoint &middot; status at <code>/__status</code></p>' +
    '</div></body></html>';
  return new Response(html, { status: 200, headers: corsHeaders(req, new Headers({ 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' })) });
}

/* ---------------- websocket proxy ---------------- */
async function proxyWebsocket(req, url, event) {
  try {
    /* resolve upstream ws url — the whole worker mirrors chat.z.ai */
    let target;
    let tokMode = false;
    if (url.pathname.startsWith('/__t/')) {
      /* v4: opaque token (encodes the original ws/wss or http/https URL) */
      const dec = decTok(url.pathname.slice(5));
      if (!dec) return json({ error: 'bad token' }, req, 400);
      let t = dec;
      if (/^https?:\/\//i.test(t)) t = t.replace(/^http/i, 'ws');
      if (!/^wss?:\/\//i.test(t)) return json({ error: 'bad token' }, req, 400);
      const tu = new URL(t);
      if (!hostAllowed(tu.host, event)) return json({ error: 'host not allowed' }, req, 403);
      target = t;
      tokMode = true;
    } else if (url.pathname.startsWith('/p/')) {
      const rest = url.pathname.slice(3);
      const slash = rest.indexOf('/');
      const host = slash < 0 ? rest : rest.slice(0, slash);
      const path = slash < 0 ? '/' : rest.slice(slash);
      if (!hostAllowed(host, event)) return json({ error: 'host not allowed' }, req, 403);
      target = 'wss://' + host + path + url.search;
    } else {
      target = chatUpstream(event).replace(/^http/, 'ws') + url.pathname + url.search;
    }
    const t = new URL(target);
    if (tokMode) {
      /* merge browser-appended query params (minus __t) into the token's URL */
      for (const [k, v] of url.searchParams) {
        if (k === '__t') continue;
        if (!t.searchParams.has(k)) t.searchParams.set(k, v);
      }
    }
    if (t.searchParams.has('__t')) t.searchParams.delete('__t');

    const upHeaders = new Headers({ 'Upgrade': 'websocket' });
    const ck = mergeCookies(req.headers.get('cookie') || '', req.headers.get('x-cookie') || '');
    if (ck) upHeaders.set('cookie', ck);
    upHeaders.set('origin', 'https://' + t.host);

    const upRes = await fetch(t.toString(), { headers: upHeaders });
    const upWs = upRes.webSocket;
    if (!upWs) return json({ error: 'upstream refused websocket' }, req, 502);
    upWs.accept();

    const pair = new WebSocketPair();
    const client = pair[0];
    const server = pair[1];
    client.accept();

    upWs.addEventListener('message', (e) => { try { client.send(e.data); } catch (err) { /* ignore */ } });
    client.addEventListener('message', (e) => { try { upWs.send(e.data); } catch (err) { /* ignore */ } });
    upWs.addEventListener('close', (e) => { try { client.close(e.code || 1000, e.reason || ''); } catch (err) { /* ignore */ } });
    client.addEventListener('close', (e) => { try { upWs.close(e.code || 1000, e.reason || ''); } catch (err) { /* ignore */ } });
    upWs.addEventListener('error', () => { try { client.close(); } catch (err) { /* ignore */ } });

    return new Response(null, { status: 101, webSocket: client });
  } catch (err) {
    return json({ error: 'websocket proxy failed', detail: String(err && err.message || err) }, req, 500);
  }
}

/* ---------------- landing / token setup page ---------------- */
const FAVICON_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#171A23"/><path d="M18 20h28v7H33.5L46 44h-8.5L27 30.5V44h-9z" fill="#7C6CF0"/></svg>';

function landing(event, bad) {
  const html = '<!doctype html><html lang="en"><head><meta charset="utf-8">' +
    '<meta name="viewport" content="width=device-width, initial-scale=1, viewport-fit=cover">' +
    '<meta name="theme-color" content="#0B0D12">' +
    '<title>zp service — setup</title>' +
    '<link rel="icon" href="data:image/svg+xml,' + encodeURIComponent(FAVICON_SVG) + '">' +
    '<style>' +
    ':root{--bg:#0B0D12;--panel:#14161F;--panel2:#1A1D28;--line:rgba(255,255,255,.08);--txt:#E7E9EE;--sub:#9AA1AD;--acc:#6E6AF8;--bad:#F87171}' +
    '*{box-sizing:border-box;-webkit-tap-highlight-color:transparent}' +
    'body{margin:0;min-height:100vh;display:flex;align-items:center;justify-content:center;padding:24px;background:radial-gradient(1100px 500px at 50% -12%,rgba(110,106,248,.14),transparent 60%),var(--bg);color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,system-ui,"Segoe UI",Roboto,sans-serif;font-size:15px;line-height:1.5}' +
    '.card{width:100%;max-width:400px;background:var(--panel);border:1px solid var(--line);border-radius:22px;padding:28px 22px;box-shadow:0 24px 60px rgba(0,0,0,.5)}' +
    '.logoRow{display:flex;align-items:center;gap:12px;margin-bottom:18px}' +
    '.logo{width:46px;height:46px;border-radius:13px;background:linear-gradient(135deg,#6E6AF8,#4E4AC8);display:flex;align-items:center;justify-content:center;flex:none;box-shadow:0 8px 24px rgba(110,106,248,.35)}' +
    '.logo svg{width:26px;height:26px}' +
    'h1{margin:0;font-size:21px;letter-spacing:.2px}' +
    '.tag{color:var(--sub);font-size:13px;margin-top:2px}' +
    'label{display:block;font-size:12.5px;color:var(--sub);margin:14px 0 7px;font-weight:600;letter-spacing:.3px}' +
    '.inWrap{display:flex;align-items:center;background:var(--panel2);border:1px solid var(--line);border-radius:13px;padding:0 12px;transition:border-color .15s}' +
    '.inWrap:focus-within{border-color:var(--acc)}' +
    'input{flex:1;background:none;border:none;outline:none;padding:13px 0;font-size:15px;color:var(--txt);min-width:0}' +
    'input::placeholder{color:#5b6270}' +
    '.btn{display:flex;align-items:center;justify-content:center;width:100%;margin-top:16px;padding:14px;border:none;border-radius:14px;font:inherit;font-weight:650;font-size:15px;background:var(--acc);color:#fff;cursor:pointer}' +
    '.btn:active{transform:scale(.985)}' +
    '.err{margin-top:12px;padding:10px 12px;border-radius:10px;background:rgba(248,113,113,.1);border:1px solid rgba(248,113,113,.35);color:#FDA4AF;font-size:13px;line-height:1.5}' +
    '.hint{margin-top:14px;color:var(--sub);font-size:12.5px;line-height:1.6}' +
    '.hint b{color:var(--txt)}' +
    '</style></head><body><div class="card">' +
    '<div class="logoRow"><div class="logo"><svg viewBox="0 0 64 64"><path d="M18 20h28v7H33.5L46 44h-8.5L27 30.5V44h-9z" fill="#fff"/></svg></div>' +
    '<div><h1>zp service</h1><div class="tag">This endpoint is protected by an access token.</div></div></div>' +
    (bad ? '<div class="err">That token was not accepted — check it and try again.</div>' : '') +
    '<form method="GET" action="/">' +
    '<label for="t">PROXY TOKEN</label>' +
    '<div class="inWrap"><input id="t" name="__t" type="password" autocomplete="off" autocapitalize="off" spellcheck="false" placeholder="paste your PROXY_TOKEN" autofocus></div>' +
    '<button class="btn" type="submit">Continue&nbsp;&rarr;</button></form>' +
    '<div class="hint">The token lives in your worker\u2019s <b>Settings &rarr; Variables &rarr; PROXY_TOKEN</b> on dash.cloudflare.com. ' +
    'It is stored in a cookie on this device, so you only enter it once.</div>' +
    '</div></body></html>';
  return new Response(html, { status: bad ? 401 : 200, headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}
