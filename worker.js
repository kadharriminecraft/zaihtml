/* ============================================================
 * z.ai pocket — Cloudflare Worker reverse proxy
 * ------------------------------------------------------------
 * WHAT THIS DOES
 *   Makes https://chat.z.ai work from inside a single local HTML
 *   file ("zai-pocket.html"). Every request the real site makes
 *   (HTML, JS/CSS assets, API calls, SSE streams, uploads,
 *   downloads) is answered by THIS worker, which forwards it to
 *   the z.ai family of hosts. The browser never talks to z.ai.
 *
 * DEPLOY (you already have a worker):
 *   1. dash.cloudflare.com → Workers & Pages → your worker
 *   2. "Edit code" / Quick Edit → select all → paste this file
 *   3. Save & Deploy
 *   4. (recommended) Settings → Variables → add PROXY_TOKEN with
 *      a long random string, and put the same string into the
 *      app's settings. Optional: EXTRA_HOSTS="a.com,b.com" to
 *      allowlist additional first-party hosts.
 *
 * ROUTES
 *   /chat/*            -> https://chat.z.ai/*
 *   /p/<host>/*        -> https://<host>/*  (host must be allowlisted)
 *   /__status          -> health check JSON
 *   /__clear?names=..  -> expire session cookies (used by the app)
 *   /                  -> landing page
 *
 * SECURITY
 *   - Only z.ai / chatglm.cn / chatglm.site family hosts are
 *     proxied. This is NOT an open proxy.
 *   - With PROXY_TOKEN set, everything except the landing page,
 *     /__status and preflights requires the token.
 *   - Upstream cookies are re-issued for this worker's own domain
 *     (SameSite=None; Secure; Partitioned) so they work inside the
 *     app's iframe; the app also mirrors them as a fallback.
 * ============================================================ */

const VERSION = 'zai-pocket-proxy 1.0';

/* z.ai first-party family (suffix match — covers subdomains) */
const ALLOW = [
  'z.ai',               // chat.z.ai, zcode.z.ai, *.space-z.ai sandboxes, ...
  'chatglm.cn',         // z-cdn.chatglm.cn (frontend assets), z-cdn-media, cdn-proxy, sdata
  'chatglm.site',       // artifacts-cdn, adapter-prod, test envs
  'glm-chat.oss-cn-hongkong.aliyuncs.com' // file upload/download bucket
];

/* upstream origin for the /chat route (env CHAT_UPSTREAM overrides, e.g. for staging) */
function chatUpstream(event) { return envOf(event).CHAT_UPSTREAM || 'https://chat.z.ai'; }
function chatHost(event) {
  try { return new URL(chatUpstream(event)).host; } catch (e) { return 'chat.z.ai'; }
}

/* markers filled by the build script */
const PATCH_JS = "/* ============================================================\n * z.ai pocket \u2014 runtime patch\n * Injected by the proxy worker into every proxied HTML document\n * as the FIRST script inside <head>. It rewrites every network\n * call, navigation and popup so the SPA believes it lives on its\n * real origin while every byte actually flows through the worker.\n *\n * NOTE: this source is embedded inside a <script> tag in proxied\n * pages, so it must never contain the literal sequence \"</scr\" +\n * \"ipt>\" \u2014 keep it that way.\n * ============================================================ */\n(function () {\n  'use strict';\n  if (window.__ZAI_PATCHED__) return;\n  window.__ZAI_PATCHED__ = true;\n\n  var CFG = window.__ZAI__ || {};\n  var PFX = CFG.pfx || '';            // proxy prefix for this document, e.g. \"/chat\" or \"/p/z-cdn.chatglm.cn\"\n  var HOST = (CFG.host || '').toLowerCase(); // upstream host this document belongs to\n  var WORKER = CFG.worker || '';      // worker origin, e.g. https://name.workers.dev\n  var TOKEN = CFG.token || '';        // optional shared proxy token\n  var ALLOW = CFG.allow || [];        // allowlisted host suffixes\n\n  var jar = [];                       // fallback cookie jar (mirrored by the shell)\n  var lsMirror = {};                  // fallback localStorage mirror (for browsers that block it in iframes)\n  var upQueue = [];\n\n  /* ---------- messaging ---------- */\n  function up(msg) {\n    try {\n      msg.zai = 1;\n      if (window.parent && window.parent !== window) window.parent.postMessage(msg, '*');\n    } catch (e) { /* ignore */ }\n  }\n\n  /* ---------- host matching ---------- */\n  function allowedHost(h) {\n    h = (h || '').toLowerCase().replace(/\\.$/, '');\n    if (!h) return false;\n    for (var i = 0; i < ALLOW.length; i++) {\n      var a = String(ALLOW[i]).toLowerCase();\n      if (h === a || h.slice(-(a.length + 1)) === '.' + a) return true;\n    }\n    return false;\n  }\n\n  /* ---------- proxy-path bookkeeping ----------\n   * Guards against double-prefixing and recognises URLs that already\n   * point at the worker (same-origin) instead of the upstream host.\n   */\n  function originStr() {\n    try { return location.origin || (location.protocol + '//' + location.host); } catch (e) { return ''; }\n  }\n  function hasPfx(str) {\n    if (!PFX) return true;\n    if (str === PFX) return true;\n    return str.indexOf(PFX) === 0 && /^[\\/?#;]/.test(str.charAt(PFX.length));\n  }\n  function isCrossHostPath(str) { // \"/p/<allowlisted host>/\u2026\"\n    if (/^\\/p\\//.test(str)) {\n      var h = str.slice(3).split(/[\\/?#]/)[0].toLowerCase();\n      if (allowedHost(h)) return true;\n    }\n    return false;\n  }\n  function isProxyPath(p) {\n    if (!p) return false;\n    if (hasPfx(p)) return true;\n    if (isCrossHostPath(p)) return true;\n    if (/^\\/__(status|clear)([\\/?#]|$)/.test(p)) return true;\n    return false;\n  }\n\n  /* ---------- URL mapping ----------\n   * absolute / protocol-relative allowlisted URLs -> proxy paths\n   * same-origin (worker) absolute URLs -> normalised proxy paths\n   * root-absolute paths -> PFX + path  (they belong to this doc's upstream host)\n   * relative / data: / blob: / #...   -> untouched\n   */\n  function mapUrl(u) {\n    try {\n      if (u == null) return u;\n      if (typeof u === 'object' && u instanceof URL) {\n        var s = mapUrl(u.href);\n        return s;\n      }\n      if (typeof u !== 'string') return u;\n      var str = u.trim();\n      if (!str) return str;\n      if (/^(data|blob|about|javascript|mailto|tel|sms|intent|ms-|chrome|file|ws|wss):/i.test(str)) {\n        // wss/ws handled by the WebSocket wrapper below; here pass through\n        return str;\n      }\n      if (str.charAt(0) === '#') return str;\n      var m;\n      if ((m = str.match(/^https?:\\/\\/([^\\/?#]+)/i))) {\n        var host = m[1].toLowerCase();\n        var org = originStr();\n        if (org && (str === org || str.indexOf(org + '/') === 0)) {\n          // same-origin (worker) absolute URL \u2014 either already proxied\n          // (\"/chat/\u2026\", \"/p/host/\u2026\") or a bare worker-root path that\n          // still belongs to this document's upstream\n          var sp = str.slice(org.length) || '/';\n          if (isProxyPath(sp)) return sp;\n          return PFX + sp;\n        }\n        if (!allowedHost(host)) return str;                    // external: leave (usually analytics)\n        var rest = str.slice(m[0].length) || '/';\n        if (host === HOST) return PFX + rest;\n        return '/p/' + host + rest;\n      }\n      if ((m = str.match(/^\\/\\/([^\\/?#]+)/))) {\n        var h2 = m[1].toLowerCase();\n        if (!allowedHost(h2)) return str;\n        var rest2 = str.slice(m[0].length) || '/';\n        if (h2 === HOST) return PFX + rest2;\n        return '/p/' + h2 + rest2;\n      }\n      if (str.charAt(0) === '/' && str.charAt(1) !== '/') {\n        if (hasPfx(str)) return str;          // already carries this doc's proxy prefix\n        if (isCrossHostPath(str)) return str; // already a /p/<host>/ proxy path\n        return PFX + str;\n      }\n      return str; // relative \u2192 resolves against the proxied document URL\n    } catch (e) { return u; }\n  }\n\n  /* ---------- cookies ---------- */\n  function docCookies() {\n    var out = [];\n    try {\n      (document.cookie || '').split(';').forEach(function (kv) {\n        kv = kv.trim();\n        if (kv) out.push(kv);\n      });\n    } catch (e) { /* ignore */ }\n    return out;\n  }\n\n  function cookieHeader() {\n    var seen = {};\n    var parts = [];\n    docCookies().forEach(function (kv) {\n      var name = kv.split('=')[0];\n      if (!seen[name]) { seen[name] = 1; parts.push(kv); }\n    });\n    jar.forEach(function (c) {\n      if (c && c.name && !seen[c.name]) { seen[c.name] = 1; parts.push(c.name + '=' + c.value); }\n    });\n    return parts.join('; ');\n  }\n\n  function ingestSetCookie(hdrVal) {\n    try {\n      if (!hdrVal) return;\n      var arr = JSON.parse(decodeURIComponent(hdrVal));\n      if (!Array.isArray(arr)) return;\n      var map = {};\n      jar.forEach(function (c) { map[c.name] = c; });\n      arr.forEach(function (raw) {\n        var bits = String(raw).split(';');\n        var nv = bits[0];\n        var eq = nv.indexOf('=');\n        if (eq < 1) return;\n        var c = { name: nv.slice(0, eq).trim(), value: nv.slice(eq + 1).trim() };\n        for (var i = 1; i < bits.length; i++) {\n          var b = bits[i].trim();\n          var k = b.split('=')[0].toLowerCase();\n          if (k === 'max-age') {\n            var ma = parseInt(b.slice(8), 10);\n            if (ma === 0) { c.del = true; }\n            c.maxAge = ma;\n          }\n        }\n        if (c.del) delete map[c.name];\n        else map[c.name] = c;\n      });\n      jar = [];\n      Object.keys(map).forEach(function (k) { jar.push(map[k]); });\n      up({ type: 'cookies', cookies: jar });\n    } catch (e) { /* ignore */ }\n  }\n\n  function seedDocumentCookies() {\n    jar.forEach(function (c) {\n      try {\n        document.cookie = c.name + '=' + c.value + '; path=/; Max-Age=31536000; Secure; SameSite=None; Partitioned';\n      } catch (e) { /* ignore */ }\n    });\n  }\n\n  /* ---------- header injection ---------- */\n  function applyHeaders(h) {\n    try {\n      var ch = cookieHeader();\n      if (ch && !h.has('x-cookie')) h.set('x-cookie', ch);\n      if (TOKEN && !h.has('x-proxy-token')) h.set('x-proxy-token', TOKEN);\n    } catch (e) { /* ignore */ }\n    return h;\n  }\n\n  /* ---------- fetch ---------- */\n  var _fetch = window.fetch ? window.fetch.bind(window) : null;\n  if (_fetch) {\n    window.fetch = function (input, init) {\n      try {\n        if (input && typeof input === 'object' && typeof input.url === 'string' && input.constructor && input.constructor.name === 'Request') {\n          var mapped = mapUrl(input.url);\n          if (mapped !== input.url) {\n            try { input = new Request(mapped, input); } catch (e2) { /* keep original */ }\n          }\n        } else if (typeof input === 'string' || input instanceof URL) {\n          var u2 = mapUrl(String(input));\n          if (u2 !== String(input)) input = u2;\n        }\n        init = init || {};\n        var H;\n        try { H = (init.headers instanceof Headers) ? init.headers : new Headers(init.headers || {}); }\n        catch (e3) { H = new Headers(); }\n        init.headers = applyHeaders(H);\n        var p = _fetch(input, init);\n        p.then(function (r) {\n          try { ingestSetCookie(r.headers && r.headers.get('x-set-cookie')); } catch (e4) { /* ignore */ }\n        }, function () { /* network error \u2014 swallow */ });\n        return p;\n      } catch (e) {\n        return _fetch(input, init);\n      }\n    };\n  }\n\n  /* ---------- XMLHttpRequest ---------- */\n  try {\n    var _open = XMLHttpRequest.prototype.open;\n    XMLHttpRequest.prototype.open = function (method, url) {\n      try {\n        var mu = mapUrl(String(url));\n        if (mu !== String(url)) {\n          if (arguments.length > 2) {\n            arguments[1] = mu;\n            return _open.apply(this, arguments);\n          }\n          return _open.call(this, method, mu);\n        }\n      } catch (e) { /* ignore */ }\n      return _open.apply(this, arguments);\n    };\n    var _send = XMLHttpRequest.prototype.send;\n    XMLHttpRequest.prototype.send = function () {\n      try {\n        var ch = cookieHeader();\n        if (ch) this.setRequestHeader('x-cookie', ch);\n        if (TOKEN) this.setRequestHeader('x-proxy-token', TOKEN);\n      } catch (e) { /* ignore */ }\n      var xhr = this;\n      try {\n        xhr.addEventListener('loadend', function () {\n          try { ingestSetCookie(xhr.getResponseHeader && xhr.getResponseHeader('x-set-cookie')); } catch (e2) { /* ignore */ }\n        });\n      } catch (e3) { /* ignore */ }\n      return _send.apply(this, arguments);\n    };\n  } catch (e) { /* ignore */ }\n\n  /* ---------- EventSource ---------- */\n  try {\n    if (window.EventSource) {\n      var _ES = window.EventSource;\n      window.EventSource = function (url, cfg) {\n        try { url = mapUrl(String(url)); } catch (e) { /* ignore */ }\n        return new _ES(url, cfg);\n      };\n      window.EventSource.prototype = _ES.prototype;\n    }\n  } catch (e) { /* ignore */ }\n\n  /* ---------- WebSocket ---------- */\n  try {\n    if (window.WebSocket) {\n      var _WS = window.WebSocket;\n      window.WebSocket = function (url, protocols) {\n        try {\n          var s = String(url);\n          var m = s.match(/^(wss?):\\/\\/([^\\/?#]+)(\\/.*)?$/i);\n          if (m) {\n            var host = m[2].toLowerCase();\n            var scheme = m[1].toLowerCase() === 'ws' ? 'ws' : 'wss';\n            if (allowedHost(host)) {\n              var rest = m[3] || '/';\n              var path = (host === HOST ? PFX : '/p/' + host) + rest;\n              if (TOKEN && path.indexOf('__t=') < 0) {\n                path += (path.indexOf('?') < 0 ? '?' : '&') + '__t=' + encodeURIComponent(TOKEN);\n              }\n              url = (location.protocol === 'https:' ? 'wss' : scheme) + '://' + location.host + path;\n            }\n          }\n        } catch (e) { /* ignore */ }\n        return protocols === undefined ? new _WS(url) : new _WS(url, protocols);\n      };\n      window.WebSocket.prototype = _WS.prototype;\n      window.WebSocket.CONNECTING = _WS.CONNECTING;\n      window.WebSocket.OPEN = _WS.OPEN;\n      window.WebSocket.CLOSING = _WS.CLOSING;\n      window.WebSocket.CLOSED = _WS.CLOSED;\n    }\n  } catch (e) { /* ignore */ }\n\n  /* ---------- sendBeacon ---------- */\n  try {\n    if (navigator.sendBeacon) {\n      var _sb = navigator.sendBeacon.bind(navigator);\n      navigator.sendBeacon = function (url, data) {\n        try {\n          var mu = mapUrl(String(url));\n          if (mu !== String(url)) {\n            // beacons cannot carry custom headers; fall back to keepalive fetch\n            return _fetch(mu, { method: 'POST', body: data, keepalive: true, mode: 'no-cors' }) ? true : true;\n          }\n        } catch (e) { /* ignore */ }\n        return _sb(url, data);\n      };\n    }\n  } catch (e) { /* ignore */ }\n\n  /* ---------- navigation reporting ---------- */\n  function curUrl() { return location.pathname + location.search + location.hash; }\n  function reportNav() { up({ type: 'nav', url: curUrl(), title: document.title || '' }); }\n\n  try {\n    var _push = history.pushState;\n    var _replace = history.replaceState;\n    // SPA history entries must stay inside the proxy prefix: a bare\n    // \"/login\" pushed from \"/chat/\" would escape the sandbox on the next\n    // reload, and a cross-origin URL would throw SecurityError outright.\n    function fixHistUrl(u) {\n      try {\n        var s = String(u);\n        if (!s || s.charAt(0) === '#') return s;\n        var org = originStr();\n        if (org && (s === org || s.indexOf(org + '/') === 0)) {\n          var p = s.slice(org.length) || '/';\n          if (isProxyPath(p)) return p;\n          return PFX + p;\n        }\n        var mapped = mapUrl(s);\n        if (/^(https?:)?\\/\\//i.test(mapped)) return curUrl(); // cross-origin \u2192 would throw\n        return mapped;\n      } catch (e) { return u; }\n    }\n    history.pushState = function () {\n      try { if (arguments.length > 2 && arguments[2] != null) arguments[2] = fixHistUrl(arguments[2]); } catch (e2) { /* ignore */ }\n      var r = _push.apply(this, arguments); reportNav(); return r;\n    };\n    history.replaceState = function () {\n      try { if (arguments.length > 2 && arguments[2] != null) arguments[2] = fixHistUrl(arguments[2]); } catch (e2) { /* ignore */ }\n      var r = _replace.apply(this, arguments); reportNav(); return r;\n    };\n    window.addEventListener('popstate', reportNav);\n    window.addEventListener('hashchange', reportNav);\n    window.addEventListener('pageshow', reportNav);\n  } catch (e) { /* ignore */ }\n\n  /* ---------- Navigation API interception (Chrome/Edge) ----------\n   * catches location.href=..., form submits, link clicks \u2014 anything\n   * that would navigate this frame to an absolute or external URL.\n   */\n  try {\n    if (window.navigation && window.navigation.addEventListener) {\n      window.navigation.addEventListener('navigate', function (e) {\n        try {\n          if (!e.canIntercept || !e.destination || e.destination.sameDocument) return;\n          var dest = String(e.destination.url || '');\n          if (!dest) return;\n          var org = originStr();\n          if (org && (dest === org || dest.indexOf(org + '/') === 0)) {\n            // same-origin destination on the worker itself: either an\n            // already-proxied path (proceed natively \u2014 the old code used to\n            // eat these as \"external\") or a bare worker-root path that must\n            // regain this document's proxy prefix\n            var p = dest.slice(org.length) || '/';\n            if (isProxyPath(p)) return;\n            e.preventDefault();\n            location.href = PFX + p;\n            return;\n          }\n          var mapped = mapUrl(dest);\n          if (mapped !== dest) {\n            // z.ai-family absolute URL \u2192 swap for the proxied path\n            e.preventDefault();\n            location.href = mapped;\n            return;\n          }\n          if (/^https?:\\/\\//i.test(dest) || /^\\/\\//.test(dest)) {\n            // external site \u2014 the phone will block it anyway; tell the shell\n            e.preventDefault();\n            up({ type: 'ext', url: dest });\n          }\n          // relative destinations proceed natively\n        } catch (err) { /* ignore */ }\n      });\n    }\n  } catch (e) { /* ignore */ }\n\n  /* ---------- window.open ---------- */\n  function stubWindow() {\n    return {\n      closed: false,\n      close: function () { this.closed = true; },\n      focus: function () {}, blur: function () {},\n      postMessage: function () {},\n      location: { href: 'about:blank', replace: function () {}, assign: function () {} },\n      document: { write: function () {}, open: function () {}, close: function () {}, createElement: function () { return { setAttribute: function () {}, appendChild: function () {} }; } }\n    };\n  }\n  window.open = function (url) {\n    try {\n      var u = url == null ? '' : String(url);\n      if (!u || u === 'about:blank') return stubWindow();\n      var mapped = mapUrl(u);\n      if (mapped !== u) { location.href = mapped; return stubWindow(); }\n      if (/^(https?:)?\\/\\//i.test(u)) { up({ type: 'ext', url: u }); return stubWindow(); }\n      location.href = u;\n      return stubWindow();\n    } catch (e) { return stubWindow(); }\n  };\n\n  /* ---------- click / submit capture (fallback layer) ---------- */\n  document.addEventListener('click', function (e) {\n    try {\n      if (e.defaultPrevented || (e.button !== undefined && e.button !== 0)) return;\n      if (e.metaKey || e.ctrlKey || e.shiftKey || e.altKey) return;\n      var el = e.target;\n      var a = el && el.closest ? el.closest('a[href]') : null;\n      if (!a) return;\n      var href = a.getAttribute('href') || '';\n      if (!href || href.charAt(0) === '#' || /^(data|blob|javascript|mailto|tel):/i.test(href)) return;\n      var target = (a.target || '').toLowerCase();\n      var mapped = mapUrl(href);\n      if (mapped !== href) {\n        if (target === '_top' || target === '_parent' || target === '_blank') {\n          e.preventDefault();\n          location.href = mapped;\n        } else {\n          a.setAttribute('href', mapped); // let native navigation use the proxied href\n        }\n        return;\n      }\n      if (/^(https?:)?\\/\\//i.test(href)) {\n        e.preventDefault();\n        up({ type: 'ext', url: href });\n        return;\n      }\n      if (target === '_top' || target === '_parent') {\n        e.preventDefault();\n        location.href = href;\n      }\n    } catch (err) { /* ignore */ }\n  }, true);\n\n  document.addEventListener('submit', function (e) {\n    try {\n      var f = e.target;\n      if (!f || !f.getAttribute) return;\n      var action = f.getAttribute('action') || '';\n      if (action) {\n        var mapped = mapUrl(action);\n        if (mapped !== action) f.setAttribute('action', mapped);\n      }\n      var target = (f.target || '').toLowerCase();\n      if (target === '_top' || target === '_parent' || target === '_blank') {\n        e.preventDefault();\n        var dest = f.getAttribute('action') || curUrl();\n        if (/^(https?:)?\\/\\//i.test(dest) && mapUrl(dest) === dest) { up({ type: 'ext', url: dest }); return; }\n        location.href = dest;\n      }\n    } catch (err) { /* ignore */ }\n  }, true);\n\n  /* ---------- service worker: never register ----------\n   * a SW would bypass every patch we installed.\n   */\n  try {\n    if (navigator.serviceWorker && navigator.serviceWorker.register) {\n      navigator.serviceWorker.register = function () {\n        return Promise.resolve({ scope: '/', active: null, installing: null, waiting: null, unregister: function () { return Promise.resolve(true); }, addEventListener: function () {}, state: 'activated' });\n      };\n    }\n  } catch (e) { /* ignore */ }\n\n  /* ---------- analytics shims (their hosts are blocked anyway) ---------- */\n  window.dataLayer = window.dataLayer || [];\n  window.gtag = window.gtag || function () { window.dataLayer.push(arguments); };\n\n  /* ---------- localStorage fallback for browsers that block it in iframes ----------\n   * backed by the shell through postMessage so sessions survive reloads.\n   */\n  (function setupStorage() {\n    function usable(store) {\n      try {\n        var k = '__zai_probe__';\n        store.setItem(k, '1');\n        store.removeItem(k);\n        return true;\n      } catch (e) { return false; }\n    }\n    function makeShim(name) {\n      var mem = (name === 'localStorage') ? lsMirror : {};\n      return {\n        getItem: function (k) { return Object.prototype.hasOwnProperty.call(mem, k) ? mem[k] : null; },\n        setItem: function (k, v) { mem[k] = String(v); up({ type: 'ls', store: name, k: String(k), v: String(v) }); },\n        removeItem: function (k) { delete mem[k]; up({ type: 'ls', store: name, k: String(k), v: null }); },\n        clear: function () { mem = {}; up({ type: 'ls', store: name, k: '__clear__', v: null }); },\n        key: function (i) { return Object.keys(mem)[i] || null; }\n      };\n    }\n    ['localStorage', 'sessionStorage'].forEach(function (name) {\n      try {\n        if (!usable(window[name])) {\n          Object.defineProperty(window, name, { value: makeShim(name), configurable: true, writable: false });\n        }\n      } catch (e) { /* ignore */ }\n    });\n  })();\n\n  /* ---------- title watcher ---------- */\n  function watchTitle() {\n    try {\n      var t = document.querySelector('title');\n      if (t && window.MutationObserver) {\n        new MutationObserver(reportNav).observe(t, { childList: true, characterData: true, subtree: true });\n      }\n    } catch (e) { /* ignore */ }\n  }\n  if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', watchTitle);\n  else watchTitle();\n\n  /* ---------- error forwarding (diagnostics) ---------- */\n  var errCount = 0;\n  window.addEventListener('error', function (e) {\n    if (errCount++ < 10) up({ type: 'err', msg: String((e && e.message) || e).slice(0, 300) });\n  });\n\n  /* ---------- shell commands ---------- */\n  window.addEventListener('message', function (e) {\n    try {\n      var d = e.data;\n      if (!d || d.zai !== 1 || !d.cmd) return;\n      if (e.origin !== 'null' && WORKER && e.origin !== WORKER) return;\n      switch (d.cmd) {\n        case 'init':\n          jar = Array.isArray(d.jar) ? d.jar : [];\n          if (d.ls) {\n            Object.keys(d.ls).forEach(function (k) {\n              if (!(k in lsMirror)) lsMirror[k] = d.ls[k];\n            });\n          }\n          seedDocumentCookies();\n          reportNav();\n          break;\n        case 'back': history.back(); break;\n        case 'forward': history.forward(); break;\n        case 'reload': location.reload(); break;\n        case 'navigate':\n          if (d.url) location.href = mapUrl(String(d.url));\n          break;\n        case 'getstate': reportNav(); break;\n      }\n    } catch (err) { /* ignore */ }\n  });\n\n  /* ---------- boot ---------- */\n  up({ type: 'hello', url: curUrl(), title: document.title || '' });\n  reportNav();\n})();\n";

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
      return json({ ok: true, name: VERSION, time: new Date().toISOString(), token_required: !!token, token_ok: tokenOk }, req);
    }
    if (url.pathname === '/' || url.pathname === '/index.html') {
      return landing(event);
    }
    if (url.pathname === '/favicon.ico') {
      return new Response(FAVICON_SVG, { headers: { 'content-type': 'image/svg+xml', 'cache-control': 'public, max-age=86400' } });
    }

    /* ---- token gate ---- */
    const env = envOf(event);
    const token = env.PROXY_TOKEN || '';
    if (token && !(await checkToken(req, url, token))) {
      return json({ error: 'unauthorized', hint: 'set X-Proxy-Token header or __t query param' }, req, 401);
    }

    /* ---- session cookie clear ---- */
    if (url.pathname === '/__clear') {
      const names = (url.searchParams.get('names') || '').split(',').map((s) => s.trim()).filter(Boolean);
      const h = new Headers({ location: '/chat/', 'content-type': 'text/html' });
      names.forEach((n) => h.append('set-cookie', n + '=; Path=/; Max-Age=0; Secure; SameSite=None; Partitioned'));
      h.append('set-cookie', '__zai_t=; Path=/; Max-Age=0; Secure; SameSite=None; Partitioned');
      const out = corsHeaders(req, h);
      return new Response(null, { status: 302, headers: out });
    }

    /* ---- websocket upgrade ---- */
    if (req.headers.get('upgrade') === 'websocket') {
      return proxyWebsocket(req, url, event);
    }

    /* ---- route resolution ---- */
    let pfx = null;      // proxy prefix for this document, e.g. "/chat" or "/p/z-cdn.chatglm.cn"
    let upstream = null; // absolute upstream URL
    let host = null;     // upstream host

    if (url.pathname === '/chat' || url.pathname.startsWith('/chat/')) {
      host = chatHost(event);
      pfx = '/chat';
      upstream = chatUpstream(event) + url.pathname.slice('/chat'.length) + url.search;
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
      return json({ error: 'unknown route', hint: 'use /chat/ or /p/<host>/ — open the worker root / for help' }, req, 404);
    }

    /* ---- strip proxy token from query ---- */
    const upUrl = new URL(upstream);
    if (upUrl.searchParams.has('__t')) upUrl.searchParams.delete('__t');

    /* ---- build upstream request ---- */
    const h = new Headers();
    const skipReq = new Set(['host', 'origin', 'referer', 'cookie', 'connection', 'keep-alive', 'upgrade',
      'proxy-connection', 'te', 'trailer', 'transfer-encoding', 'content-length', 'accept-encoding',
      'x-cookie', 'x-proxy-token', 'x-set-cookie']);
    for (const [k, v] of req.headers) {
      if (!skipReq.has(k.toLowerCase())) h.set(k, v);
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
    try {
      const fetchInit = { method: method, headers: h, redirect: 'manual' };
      if (body !== undefined) fetchInit.body = body;
      if (needDuplex) fetchInit.duplex = 'half';
      res = await fetch(upUrl.toString(), fetchInit);
    } catch (err) {
      return json({ error: 'upstream fetch failed', detail: String(err && err.message || err) }, req, 502);
    }

    /* ---- redirect handling: rewrite Location and let the browser follow inside the worker ---- */
    const loc = res.headers.get('location');
    if (loc && res.status >= 300 && res.status < 400 && res.status !== 304) {
      const mapped = mapLocation(loc, upUrl, event);
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
    const outCt = corsHeaders(req, outHeaders);

    if (ct.includes('text/html')) {
      const text = await res.text();
      const html = rewriteHtml(text, pfx, host, new URL(req.url).origin, token, allowList(event));
      return new Response(html, { status: res.status, headers: outCt });
    }
    if (ct.includes('text/css')) {
      const text = await res.text();
      const css = rewriteCss(text, pfx, host, allowList(event));
      return new Response(css, { status: res.status, headers: outCt });
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
function maybeSetTokenCookie(req, h, event) {
  const token = envOf(event).PROXY_TOKEN || '';
  if (!token) return;
  const ck = req.headers.get('cookie') || '';
  if (ck.indexOf('__zai_t=') >= 0) return;
  h.append('set-cookie', '__zai_t=' + encodeURIComponent(token) + '; Path=/; Max-Age=31536000; Secure; SameSite=None; Partitioned');
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
  h.set('access-control-expose-headers', 'content-disposition, content-type, x-set-cookie, x-final-url, filename');
  h.set('access-control-max-age', '86400');
  return h;
}

function json(obj, req, status) {
  const h = new Headers({ 'content-type': 'application/json; charset=utf-8', 'cache-control': 'no-store' });
  return new Response(JSON.stringify(obj), { status: status || 200, headers: corsHeaders(req, h) });
}

/* map a Location header value into proxy space */
function mapLocation(loc, upUrl, event) {
  try {
    const abs = new URL(loc, upUrl);
    if (abs.protocol !== 'https:' && abs.protocol !== 'http:') return loc;
    if (!hostAllowed(abs.host, event)) return loc; // external redirect — pass through untouched
    if (abs.host === upUrl.host) {
      const pfx = prefixForHost(upUrl.host, event);
      return pfx + abs.pathname + abs.search;
    }
    return '/p/' + abs.host + abs.pathname + abs.search;
  } catch (e) {
    return loc;
  }
}
function prefixForHost(host, event) {
  if (host === chatHost(event)) return '/chat';
  return '/p/' + host;
}

/* ---------------- HTML rewriting ---------------- */
function mapAttr(v, pfx, host, allow) {
  try {
    const s = String(v || '').trim();
    if (!s) return v;
    if (/^(data|blob|about|javascript|mailto|tel|sms|intent|ms-|chrome|file|#)/i.test(s)) return v;
    let m;
    if ((m = s.match(/^https?:\/\/([^\/?#]+)/i))) {
      const h = m[1].toLowerCase();
      const ok = allow.some((a) => h === a || h.endsWith('.' + a));
      if (!ok) return v;
      const rest = s.slice(m[0].length) || '/';
      return (h === host ? pfx : '/p/' + h) + rest;
    }
    if ((m = s.match(/^\/\/([^\/?#]+)/))) {
      const h = m[1].toLowerCase();
      const ok = allow.some((a) => h === a || h.endsWith('.' + a));
      if (!ok) return v;
      const rest = s.slice(m[0].length) || '/';
      return (h === host ? pfx : '/p/' + h) + rest;
    }
    if (s.charAt(0) === '/' && s.charAt(1) !== '/') return pfx + s;
    return v;
  } catch (e) {
    return v;
  }
}

const ATTR_NAMES = 'href|src|action|formaction|poster|data-src|data-href|data-url|data-background';

function rewriteHtml(text, pfx, host, workerOrigin, token, allow) {
  try {
    /* strip CSP meta tags and base targets */
    text = text.replace(/<meta[^>]+http-equiv\s*=\s*["']?content-security-policy["']?[^>]*>/gi, '');
    text = text.replace(/<base\b([^>]*?)\s+target\s*=\s*["'][^"']*["']/gi, '<base$1');

    /* rewrite URL attributes */
    const attrRe = new RegExp('(\\s(?:' + ATTR_NAMES + ')\\s*=\\s*)("([^"]*)"|\'([^\']*)\')', 'gi');
    text = text.replace(attrRe, (whole, pre, quoted, dq, sq) => {
      const v = dq !== undefined ? dq : sq;
      const nv = mapAttr(v, pfx, host, allow);
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
        const nu = mapAttr(u, pfx, host, allow);
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
        const nu = mapAttr(u, pfx, host, allow);
        return nu === u ? w : "url('" + nu + "')";
      });
      if (nv === v) return whole;
      return pre + '"' + nv.replace(/"/g, '&quot;') + '"';
    });

    /* inject config + runtime patch as the first script */
    const cfg = { pfx: pfx, host: host, worker: workerOrigin, token: token || '', allow: allow };
    const inject = '<scr' + 'ipt>window.__ZAI__=' + JSON.stringify(cfg) + ';' + PATCH_JS + '</scr' + 'ipt>';
    if (/<head[^>]*>/i.test(text)) text = text.replace(/<head[^>]*>/i, (m) => m + inject);
    else if (/<html[^>]*>/i.test(text)) text = text.replace(/<html[^>]*>/i, (m) => m + inject);
    else text = inject + text;
    return text;
  } catch (e) {
    return text;
  }
}

function rewriteCss(text, pfx, host, allow) {
  try {
    text = text.replace(/url\(\s*(['"]?)([^'")]+)\1\s*\)/gi, (w, q, u) => {
      const nu = mapAttr(u, pfx, host, allow);
      return nu === u ? w : 'url("' + nu + '")';
    });
    text = text.replace(/@import\s+(['"])([^'"]+)\1/gi, (w, q, u) => {
      const nu = mapAttr(u, pfx, host, allow);
      return nu === u ? w : '@import "' + nu + '"';
    });
    return text;
  } catch (e) {
    return text;
  }
}

/* ---------------- websocket proxy ---------------- */
async function proxyWebsocket(req, url, event) {
  try {
    /* resolve upstream ws url */
    let target;
    if (url.pathname === '/chat' || url.pathname.startsWith('/chat/')) {
      target = chatUpstream(event).replace(/^http/, 'ws') + url.pathname.slice('/chat'.length) + url.search;
    } else if (url.pathname.startsWith('/p/')) {
      const rest = url.pathname.slice(3);
      const slash = rest.indexOf('/');
      const host = slash < 0 ? rest : rest.slice(0, slash);
      const path = slash < 0 ? '/' : rest.slice(slash);
      if (!hostAllowed(host, event)) return json({ error: 'host not allowed' }, req, 403);
      target = 'wss://' + host + path + url.search;
    } else {
      return json({ error: 'unknown route' }, req, 404);
    }
    const t = new URL(target);
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

/* ---------------- landing page ---------------- */
const FAVICON_SVG = '<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 64 64"><rect width="64" height="64" rx="14" fill="#171A23"/><path d="M18 20h28v7H33.5L46 44h-8.5L27 30.5V44h-9z" fill="#7C6CF0"/></svg>';

function landing(event) {
  const tokenRequired = !!(envOf(event).PROXY_TOKEN);
  const html = '<!doctype html><html><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">' +
    '<title>z.ai pocket proxy</title><link rel="icon" href="data:image/svg+xml,' + encodeURIComponent(FAVICON_SVG) + '">' +
    '<style>body{background:#0B0D12;color:#E7E9EE;font-family:system-ui,-apple-system,sans-serif;display:flex;min-height:100vh;align-items:center;justify-content:center;margin:0}' +
    '.c{max-width:420px;padding:40px 28px;text-align:center}h1{font-size:22px;margin:0 0 6px}p{color:#9aa1ad;font-size:14px;line-height:1.6;margin:8px 0}' +
    'a{display:inline-block;margin-top:18px;background:#6E6AF8;color:#fff;text-decoration:none;padding:13px 26px;border-radius:12px;font-weight:600}' +
    '.ok{color:#4ade80;font-size:13px;margin-top:14px}</style></head><body><div class="c">' +
    '<h1>z.ai pocket proxy</h1><p>' + VERSION + '</p>' +
    '<p>Online. Point the zai-pocket.html app at this URL, or jump straight in:</p>' +
    '<a href="/chat/">Open chat.z.ai</a>' +
    '<p class="ok">&#10003; worker reachable' + (tokenRequired ? ' &middot; token required' : ' &middot; no token set (add PROXY_TOKEN for safety)') + '</p>' +
    '</div></body></html>';
  return new Response(html, { headers: { 'content-type': 'text/html; charset=utf-8', 'cache-control': 'no-store' } });
}
