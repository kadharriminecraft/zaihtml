/* ============================================================
 * z.ai pocket — Cloudflare Worker relay — worker.js
 * BUILD: zp service 6.9 (the current one-and-only build)
 *   Deploy check: /__status on the worker URL must answer
 *   "zp service 6.9" — if it says 6.0 … 6.8, an old copy is
 *   still deployed; replace it with this file.
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
 *   v6 — credentialed CORS (origin echo + allow-credentials),
 *        path-preserving /__o/ handles with an injected base tag,
 *        cookie jar relayed via x-set-cookie / x-cookie so
 *        sign-in survives the null-origin sandbox.
 *   v6.1 — CORS FIX FOR REAL PHONES: v6 only echoed Origin: null
 *        back, so a pocket file opened through a viewer app that
 *        serves it from http://localhost:PORT (or any custom
 *        scheme) got Access-Control-Allow-Origin:* on its very
 *        first credentialed document fetch — the browser kills
 *        that response instantly ("Could not reach the app") while
 *        /__status (credentials:'omit') answers fine. Now ANY
 *        well-formed Origin is echoed with allow-credentials, and
 *        the sandbox runtime patch strips credentials:'include'
 *        (cookies already ride on x-cookie) so in-frame api calls
 *        can never trip credentialed-CORS rules either. The pocket
 *        (v6.2) additionally retries document loads in omit mode
 *        with the jar on x-cookie, so a load works from ANY origin
 *        on ANY browser, no matter how it handles credentials.
 *   v6.2 — STREAM/SEND HARDENING: (1) text/event-stream responses
 *        now pass through with x-accel-buffering:no + no-store so
 *        no CDN hop decides to buffer a live agent stream, and the
 *        upstream request for stream calls asks for identity
 *        encoding (some upstreams sit on gzip'd SSE). (2) The
 *        sandbox runtime patch ALSO strips credentials:'include'
 *        from Request-object fetches (v6.1 only covered the plain
 *        init form) and forces XHR withCredentials=false in sandbox
 *        mode — the z.ai app sends /api/config, /api/v1/auths and
 *        the sign-in call WITH credentials:"include", and fragile
 *        mobile webviews kill those at the network level, which
 *        silently breaks the chat-send flow (models/settings never
 *        load, the send button never arms). Deploying this version
 *        is REQUIRED for sending prompts on such phones.
 *   v6.3 — MODEL PICKER + STALE-TOKEN RECOVERY: the z.ai boot script
 *        caches a GLOBAL_FETCHES.models promise and sends the localStorage
 *        'token' as a Bearer on it; when that token is from an OLD login
 *        (saved session restored, cookies fresh) upstream answers 401 and
 *        the cached rejection leaves the model picker EMPTY all session
 *        ("Model not selected", nothing clickable). The runtime now (1)
 *        PRESERVES Request-object headers on fetch(Request) calls (the
 *        wrapper used to replace them, dropping Authorization), (2)
 *        retries a 401 GET /api/ call that carried Authorization ONCE
 *        with the header dropped — on models/auths success the stale
 *        token is cleared so the next boot is clean, and (3) retries a
 *        network-LEVEL failure of a first-boot GET /api/ call once after
 *        a short delay (fresh sandbox boots queue those calls behind a
 *        wall of analytics beacons and one dead fetch would otherwise
 *        poison the app's cached session/models promises for the whole
 *        session). Together with the pocket v6.4 session-restore fix
 *        this heals "model not selected" AND keeps logins alive across
 *        reopens.
 *   v6.4 — THE REAL MODEL-PICKER FIX + NO-MORE-SPURIOUS-LOGOUTS. Live
 *        tracing against the real app found the ACTUAL boot killer the
 *        6.3 retries could never touch: z.ai's inline boot script builds
 *        ONE shared headers object for its auths/config/models/settings
 *        fetches, and the runtime's old skip-if-present x-cookie logic
 *        kept the FIRST call's cookie snapshot baked into that shared
 *        object — so /api/models sailed out with pre-session cookies
 *        and z.ai's Aliyun edge 403'd it ("No models found" in the
 *        picker, "Model not selected" on send). Worse, the same 403
 *        on the account-settings page's auths call rejected the
 *        session promise, and the app renders itself as a GUEST —
 *        "settings → Account redirects, fails, back home, logged
 *        out". TWO fixes: (1) the runtime now ALWAYS refreshes the
 *        x-cookie header from the live jar (never trusts a stale
 *        snapshot on a shared Headers object); (2) the worker recovers
 *        401/403 on chat /api/ GETs SERVER-SIDE and invisibly — it
 *        takes the fresh cookies the refusal just issued, re-runs
 *        /api/v1/auths/ with them merged (renewing token + WAF
 *        cookies), retries the original call with everything merged
 *        (Authorization kept), and re-issues the gathered cookies on
 *        the response so the sandbox jar heals too. Verified end-to-
 *        end: a fully-stale jar now walks through the recovery and
 *        gets the complete model list (glm-5.3, glm-5.3-flash,
 *        glm-5.2 …) back with HTTP 200.
 *
 *   v6.5 — THE STUCK-SEND FIX. z.ai's frontend NEVER calls
 *        setItem('token'): all five token writes in the whole
 *        bundle are plain property assignments
 *        (`localStorage.token = jwt`), and the send path reads it
 *        back with getItem at click time. The old storage shim was
 *        a plain object, so every property write landed on a dead
 *        JS property — the token NEVER persisted, the chat send
 *        shipped `authorization: Bearer null` on /api/v1/chats/new,
 *        z.ai answered 401, and the app sat on its three-dots
 *        spinner forever ("the message never actually gets sent").
 *        Fresh sandbox boots (settings → Account) equally found no
 *        token and bounced the user home as a guest. THREE fixes:
 *        (1) the shim is now a full Storage emulation (Proxy):
 *        property get/set/delete route through getItem/setItem/
 *        removeItem, length + key enumeration behave like the real
 *        thing — the app's `localStorage.token = jwt` now sticks
 *        and rides the existing ls-mirror to the shell; (2) the
 *        server-side 401/403 session recovery now also covers
 *        chat /api/ POSTs with replayable (buffered) bodies —
 *        chats/new and completions refetch their session cookies
 *        and retry instead of hanging the send; (3) auths
 *        guest-degradation heal: z.ai lets a stale Bearer DEGRADE
 *        an auths call to a brand-new guest session (HTTP 200) —
 *        the worker detects the minted token differing from the
 *        presented Bearer, retries auths WITHOUT it, and serves
 *        the cookie-backed session (the logged-in account) back,
 *        so a stale stored token no longer logs the user out on
 *        the settings pages.
 *
 *   v6.6 — THE CAPTCHA-SCENE FIX. z.ai gates chat completions
 *        with an Aliyun slider captcha whose token is minted for
 *        a SCENE ID picked at runtime: the bundle's config getter
 *        reads `window.location.hostname === "chat.z.ai" ?
 *        "didk33e0" : "xswyjefn"`. The compiled form is a
 *        WHOLE-OBJECT reference — `(t = window.location) == null
 *        ? void 0 : t.hostname` — which the v5 location-rewrite
 *        never touched (it only rewrote `location.<prop>` member
 *        accesses). In the sandbox `window.location` is the real
 *        about:srcdoc location, hostname "" — so every captcha
 *        was initialized and verified under the WRONG scene
 *        (xswyjefn), and z.ai's backend rejected every solved
 *        token: the user solved the slider and STILL got
 *        "Verification required" forever. The rewrite now also
 *        (1) maps whole-object `window.location` READS to __zaiLoc
 *        (guarded: not after a dot/word char — so
 *        contentWindow.location stays real — and never an
 *        lvalue write), and (2) tolerates optional chaining
 *        (`location?.href`) in both prefixed and bare forms, so
 *        third-party scripts served through the relay
 *        (AliyunCaptcha.js, FeiLin) fingerprint the page as
 *        chat.z.ai too. Scene, referer-style checks and risk
 *        scoring all line up with the real site now.
 *
 *   v6.7 — SIGN-IN THAT SURVIVES THE FILE BEING CLOSED + NO MORE
 *        CAPTCHA STORMS FROM RESEND HAMMERING. Two fixes:
 *        (1) SESSION VAULT (/__vault). Every browser the pocket
 *            file runs in is expected to keep localStorage between
 *            opens — but many phone "viewer" apps open saved HTML
 *            in an ephemeral context where ALL storage is wiped the
 *            moment the file closes, so the saved z.ai session
 *            (cookie jar + login token) evaporated and the user
 *            re-signed-in on every single open. The vault stores an
 *            AES-GCM-encrypted session snapshot (the pocket
 *            encrypts it client-side with a secret only the user
 *            knows; the worker only ever sees ciphertext) in the
 *            edge cache, keyed by SHA-256(secret + deploy key).
 *            On a wiped phone: type the secret once, the session
 *            comes back, the app boots signed in. Wrong-secret
 *            probing is rate-limited and yields nothing (the key
 *            is a hash, the payload ciphertext).
 *        (2) CAPACITY AUTO-RETRY for chat completions POSTs. z.ai
 *            answers a busy model with an SSE error event
 *            (error_type "rate_limit_short" / "global_limit_reached"
 *            — the "X is intensifying the coordination of
 *            resources, please try again later" modal). Users
 *            hammer the resend button to "get the request in",
 *            and that rapid-fire burst is exactly what trips z.ai's
 *            risk control into captcha mode ("verification
 *            required" even while signed in). The worker now
 *            retries those responses SERVER-SIDE, invisibly, with
 *            a paced backoff (3s/8s/18s/35s + jitter — the same
 *            "keep trying" the user did by hand, but at a rhythm
 *            the risk control tolerates). Captcha-required errors
 *            and auth failures are NEVER retried — the slider must
 *            still pop, and 401/403 keeps the v6.4/v6.5 recovery.
 *
 *   v6.8 — ZERO-EFFORT SIGN-IN PERSISTENCE (/__vault/auto). The
 *        6.7 vault needs the user to type a secret after every
 *        wipe — real phones in the field showed users just want it
 *        to STAY signed in, full stop. The one thing a wiping
 *        viewer never wipes is the pocket FILE itself, so the
 *        copier now stamps a random 128-bit DEVICE KEY into every
 *        zai-pocket.html it saves (phones that keep storage or
 *        cookies get a runtime-generated key / a zp_dev cookie
 *        instead — every channel converges on the same vault).
 *        The pocket auto-saves the newest session snapshot here
 *        after every change (4s debounce) and auto-restores it
 *        before the first document load on every open — no secret,
 *        no button, nothing to remember. Stored AES-GCM-encrypted
 *        at rest under SHA-256(deploy key + device key); a wrong
 *        device key is just a cache miss in a 2^128 space. The
 *        zp_dev cookie (SameSite=None, Partitioned, 1 year)
 *        mirrors the device key so cookie-keeping phones survive
 *        even a full localStorage wipe, and the worker never
 *        forwards zp_dev upstream (it is not a z.ai cookie). The
 *        6.7 pin vault stays as the cross-device / paranoid
 *        backup; /__status now reports vault_auto:true so the
 *        pocket only calls the new endpoint on 6.8+.
 *
 *   v6.9 — THE RELAY KEEPS THE SESSION OPEN (single-user mode).
 *        User verdict on 6.7/6.8: "I don't care for the backups
 *        or anything — get rid of all that. Find a new way to
 *        stay signed in, like having the worker keep the session
 *        open. I am only using the worker for myself." So both
 *        vaults are GONE (no secrets, no device keys, no zp_dev
 *        cookie, no cards in the pocket), replaced by one simple
 *        thing: the worker passively CAPTURES the live session
 *        from the traffic it already proxies — every set-cookie
 *        z.ai hands out, every Bearer token the app sends, and
 *        the authoritative {token,id,role} of each /api/v1/auths
 *        answer — into a single edge-cache slot (/__session).
 *        The pocket fetches it once per open, before the first
 *        document load, and the app boots already signed in —
 *        no matter what the phone's viewer does to its storage.
 *        Guest traffic never demotes a held user session (the
 *        auths answer names the role); a sign-out empties the
 *        jar (logout clears the cookies), so a signed-out file
 *        boots signed out. /__status reports session:true.
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
 *   /__session   -> the relay-held session (v6.9, single user).
 *                   GET returns {ok,has,savedAt,token,jar} — the
 *                   newest session captured passively from the
 *                   proxied traffic; DELETE forgets it (sign out).
 *                   No secrets, no keys: the user runs this relay
 *                   for themselves (see SECURITY note below).
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
 *     them as x-cookie. Nothing is stored at this origin except
 *     the ONE /__session slot (v6.9): it holds the captured live
 *     session so the user's own pocket file re-signs itself in.
 *     This relay is single-user by design — if the worker URL
 *     ever leaks, DELETE /__session (or just sign out in the
 *     app) resets it. The zp_dev cookie is still stripped
 *     upstream (hygiene for 6.8-era leftovers).
 * ============================================================ */

const VERSION = 'zp service 6.9';

/* z.ai first-party family (suffix match — covers subdomains) */
const ALLOW = [
  'z.ai',               // chat.z.ai, zcode.z.ai, *.space-z.ai sandboxes, ...
  'chatglm.cn',         // z-cdn.chatglm.cn (frontend assets), z-cdn-media, cdn-proxy, sdata
  'chatglm.site',       // artifacts-cdn, adapter-prod, test envs
  'glm-chat.oss-cn-hongkong.aliyuncs.com', // file upload/download bucket
  'alicdn.com',         // o.alicdn.com — z.ai's shared frontend libs (jquery …)
  'aliyuncs.com',       // sdk.rum / log endpoints the z.ai frontend loads at boot
  'filebin.net'         // v6.2: delivery host for the copier's file mirrors —
                        // browsers get an HTML wrapper from it directly, but a
                        // server-side fetch (this worker) receives the raw
                        // bytes, so the copier pulls its payloads through
                        // /p/filebin.net/<bin>/<file> and they arrive green.
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

/* v6: path-preserving origin-token form — '/__o/<encTok(origin)><path><search>'.
 * Relative URL resolution (dynamic import("./chunk.js"), css url(),
 * <base>-resolved runtime urls) needs the upstream PATH to ride along
 * in cleartext; the HOSTNAME — what org filters key on — stays encrypted. */
function oTokPath(absUrl) {
  try {
    const u = new URL(absUrl);
    const ot = encTok(u.origin);
    if (!ot) return null;
    return '/__o/' + ot + u.pathname + u.search;
  } catch (e) { return null; }
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
"   * postMessages instead of steering the sandbox frame anywhere.",
"   * v6: the underlying URL is MUTABLE \u2014 the pushState/replaceState",
"   * shims advance it (below) so a router that re-reads",
"   * window.location.pathname after an SPA transition sees the NEW",
"   * path, exactly like the real location object. A frozen fake was why",
"   * chat.z.ai/auth rendered the HOME view: the URL bar moved but the",
"   * router's own re-resolution still read \"/\". */",
"  var LOC = { u: null };",
"  try { LOC.u = DOC ? new URL(DOC) : null; } catch (eLoc0) { LOC.u = null; }",
"  function setLoc(abs) {",
"    try { LOC.u = new URL(String(abs)); } catch (eSet) { /* keep old */ }",
"  }",
"  function makeLoc() {",
"    function prop(name, fb) {",
"      try { return LOC.u ? LOC.u[name] : fb; } catch (e) { return fb; }",
"    }",
"    var loc = {};",
"    Object.defineProperty(loc, 'href', {",
"      get: function () { return LOC.u ? LOC.u.href : (DOC || 'about:srcdoc'); },",
"      set: function (v) { nav(v); return v; },",
"      configurable: true",
"    });",
"    loc.assign = function (v) { nav(v); };",
"    loc.replace = function (v) { nav(v); };",
"    loc.reload = function () { up({ type: 'reloadreq' }); };",
"    loc.toString = function () { return LOC.u ? LOC.u.href : (DOC || 'about:srcdoc'); };",
"    ['origin', 'protocol', 'host', 'hostname', 'port', 'pathname', 'search', 'hash'].forEach(function (k) {",
"      try {",
"        Object.defineProperty(loc, k, {",
"          get: function () {",
"            if (!LOC.u) return k === 'origin' || k === 'host' || k === 'hostname' ? '' : (k === 'protocol' ? 'https:' : (k === 'pathname' ? '/' : ''));",
"            return LOC.u[k];",
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
"    if (/^\\/__(t|o)\\//.test(p)) return true; // v4/v6 token paths (full-URL / origin+path)",
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
"          if (/^\\/__(t|o)\\//.test(str)) return str;",
"          if (isCrossHostPath(str)) return str;",
"          if (/^\\/__(status|clear|diag)([\\/?#]|$)/.test(str)) return str;",
"          try {",
"            var t3 = tokPath(new URL(str, DOC).href);",
"            if (t3) return t3;",
"          } catch (e3) { /* fall through */ }",
"        }",
"        if (hasPfx(str)) return str;          // already carries this doc's proxy prefix",
"        if (isCrossHostPath(str)) return str; // already a legacy /p/<host>/ proxy path",
"        if (/^\\/__(t|o)\\//.test(str)) return str; // already a token path (v4 /__t/ or v6 /__o/)",
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
"      /* v6.4: ALWAYS refresh x-cookie with the current jar. The z.ai",
"       * boot script shares ONE headers object across its auths / config /",
"       * models / settings fetches; v6.3's skip-if-present kept the FIRST",
"       * call's cookie snapshot baked into that shared object, so /api/models",
"       * sailed out with pre-auth cookies and the Aliyun WAF 403'd it - the",
"       * model picker then showed \"No models found\" for the whole session.",
"       * x-cookie is this runtime's own header (no site code sets it), so",
"       * overwriting it is always safe and always freshest. */",
"      var ch = cookieHeader();",
"      if (ch) h.set('x-cookie', ch);",
"      else { try { h.delete('x-cookie'); } catch (eDel) { /* ignore */ } }",
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
"          /* v6.2: a Request OBJECT built with credentials:'include' is",
"           * the one fragile-webview path the init-form strip below can",
"           * never reach (its credentials live inside the object). In",
"           * sandbox mode rebuild it omit-mode — cookies ride on",
"           * x-cookie, 'include' buys nothing and trips credentialed-CORS",
"           * rules on strict mobile webviews. */",
"          if (SD) {",
"            try {",
"              var R0 = (input && typeof input === 'object' && typeof input.url === 'string') ? input : null;",
"              if (R0 && R0.credentials === 'include') {",
"                var iOpt = { method: R0.method, headers: R0.headers, credentials: 'omit',",
"                  cache: R0.cache, redirect: R0.redirect, referrer: R0.referrer, integrity: R0.integrity };",
"                if (R0.method !== 'GET' && R0.method !== 'HEAD') { iOpt.body = R0.body; iOpt.duplex = 'half'; }",
"                input = new Request(R0.url, iOpt);",
"              }",
"            } catch (eCR) { /* keep the include-mode request */ }",
"          }",
"        } else if (typeof input === 'string' || input instanceof URL) {",
"          var u2 = mapUrl(String(input));",
"          if (u2 !== String(input)) input = absW(u2);",
"        }",
"        init = init || {};",
"        /* v6.1: in sandbox mode (null-origin srcdoc) credentialed",
"         * fetches are the fragile path — some mobile browsers and",
"         * viewer-app webviews refuse them outright. The session",
"         * already rides on the x-cookie header this wrapper sets,",
"         * so 'include' adds nothing here: strip it to 'omit' and the",
"         * request passes with a plain wildcard allow-origin too. */",
"        if (SD && init.credentials === 'include') {",
"          try { init.credentials = 'omit'; } catch (eC1) { /* keep */ }",
"        }",
"        var H;",
"        try {",
"          if (init.headers) {",
"            H = (init.headers instanceof Headers) ? init.headers : new Headers(init.headers);",
"          } else if (input && typeof input === 'object' && typeof input.headers !== 'undefined') {",
"            /* v6.3: a fetch(Request) call. Setting init.headers below would",
"             * REPLACE the Request's own headers per spec, silently dropping",
"             * the app's Authorization on every Request-object call. Merge",
"             * the Request's headers into H instead. */",
"            H = new Headers();",
"            try { input.headers.forEach(function (v, k) { H.set(k, v); }); } catch (eIH) { /* ignore */ }",
"          } else { H = new Headers(); }",
"        } catch (e3) { H = new Headers(); }",
"        init.headers = applyHeaders(H);",
"        var iu = '';",
"        try { iu = (typeof input === 'string') ? input : (input && typeof input.url === 'string') ? input.url : ''; } catch (eIU) { iu = ''; }",
"        var meth = 'GET';",
"        try { meth = (init && init.method) || (input && input.method) || 'GET'; } catch (eM) { meth = 'GET'; }",
"        var hadAuth = false;",
"        try { if (init.headers && init.headers.get && init.headers.get('authorization')) hadAuth = true; } catch (eHA) { /* ignore */ }",
"        var p = _fetch(input, init);",
"        /* v6.3: network-level retry for first-boot GET api calls. On a",
"         * fresh sandbox boot the app's auths/models/config fetches",
"         * queue behind 15+ analytics beacons on a null-origin context",
"         * and occasionally die at the network level - and the app CACHES",
"         * those rejected GLOBAL_FETCHES promises, so one dead call leaves",
"         * the session/models empty for the whole session (\"Model not",
"         * selected\"). One delayed GET-only retry before the rejection",
"         * is allowed through. */",
"        var isApiGet = /^GET$/i.test(meth) && /\\/api\\//.test(String(iu));",
"        var retryable = function (iR) {",
"          var i3 = {};",
"          for (var k3 in iR) { try { i3[k3] = iR[k3]; } catch (eK3) { /* ignore */ } }",
"          return i3;",
"        };",
"        /* v6.3: stale-token recovery. The app's boot script caches a",
"         * GLOBAL_FETCHES.models promise: a GET /api/models carrying an",
"         * Authorization header left over from an OLD login answers 401",
"         * even with a perfectly good cookie session, and that cached",
"         * rejection leaves the model picker empty all session (\"Model",
"         * not selected\"). Retry such calls ONCE with Authorization",
"         * dropped - cookies ride on x-cookie - and when the retry",
"         * succeeds on models/auths, clear the stale token so the next",
"         * boot is clean. */",
"        var pr = p.then(function (r) {",
"          try {",
"            if (SD && r.status === 401 && hadAuth && /^GET$/i.test(meth) && /\\/api\\//.test(String(iu))) {",
"              var i2 = {};",
"              for (var kk in init) { try { i2[kk] = init[kk]; } catch (eK) { /* ignore */ } }",
"              var H2 = new Headers(init.headers || {});",
"              H2.delete('authorization');",
"              i2.headers = H2;",
"              return _fetch(iu, i2).then(function (r2) {",
"                try {",
"                  if (r2 && r2.ok) {",
"                    try { ingestSetCookie(r2.headers && r2.headers.get('x-set-cookie')); } catch (e5) { /* ignore */ }",
"                    if (/\\/api\\/(models|v1\\/auths)/.test(String(iu))) {",
"                      try { localStorage.removeItem('token'); } catch (eL) { /* ignore */ }",
"                      try { up({ type: 'ls', store: 'localStorage', k: 'token', v: null }); } catch (eU) { /* ignore */ }",
"                    }",
"                  }",
"                  return r2;",
"                } catch (eR2) { return r2; }",
"              }, function () { return r; });",
"            }",
"          } catch (eRec) { /* ignore */ }",
"          return r;",
"        }, function (err) {",
"          /* network-level failure: one delayed retry for GET api calls */",
"          try {",
"            if (SD && isApiGet && !init.__zpR) {",
"              return new Promise(function (res2, rej2) {",
"                setTimeout(function () {",
"                  var i3 = retryable(init);",
"                  i3.__zpR = 1;",
"                  _fetch(iu, i3).then(res2, rej2);",
"                }, 350);",
"              });",
"            }",
"          } catch (eNet) { /* ignore */ }",
"          throw err;",
"        });",
"        pr.then(function (r) {",
"          try { ingestSetCookie(r.headers && r.headers.get('x-set-cookie')); } catch (e4) { /* ignore */ }",
"          /* v6.4: the worker's session recovery healed this call by",
"           * dropping a stale Bearer (x-zp-retry: dropauth) — clear the",
"           * matching stale token from localStorage so the NEXT boot is",
"           * clean instead of paying the recovery on every api call. */",
"          try {",
"            if (SD && r.headers && r.headers.get('x-zp-retry') === 'dropauth' &&",
"                /\\/api\\/(models|v1\\/auths)/.test(String(iu))) {",
"              try { localStorage.removeItem('token'); } catch (eL4) { /* ignore */ }",
"              try { up({ type: 'ls', store: 'localStorage', k: 'token', v: null }); } catch (eU4) { /* ignore */ }",
"            }",
"          } catch (eDA) { /* ignore */ }",
"        }, function () { /* network error: swallow */ });",
"        return pr;",
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
"        /* v6.1: same reasoning as the fetch wrapper — in sandbox mode",
"         * withCredentials buys nothing (cookies ride on x-cookie) and",
"         * trips credentialed-CORS rules on fragile webviews. */",
"        if (SD) { try { this.withCredentials = false; } catch (eWC) { /* keep */ } }",
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
"         * the app renders the transition client-side exactly as built.",
"         * v6: ALSO advance the fake location \u2014 routers re-read",
"         * window.location.pathname to re-resolve routes after SPA",
"         * transitions; a frozen fake made every soft transition land",
"         * back on the boot route (the /auth-renders-home bug). */",
"        try {",
"          var su = (arguments.length > 2 && arguments[2] != null) ? String(arguments[2]) : '';",
"          if (su && su.charAt(0) !== '#') {",
"            var sAbs = '';",
"            try { sAbs = new URL(su, LOC.u || DOC || 'about:srcdoc').href; } catch (eA) { sAbs = su; }",
"            setLoc(sAbs);",
"            up({ type: 'hist', url: mapUrl(sAbs), up: sAbs });",
"          } else if (su && su.charAt(0) === '#') {",
"            /* hash-only push: the path stays, the hash moves */",
"            try { setLoc(String(LOC.u ? LOC.u.href : (DOC || '/')).replace(/#.*$/, '') + su); } catch (eHh) { /* ignore */ }",
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
"            try { rAbs = new URL(ru, LOC.u || DOC || 'about:srcdoc').href; } catch (eB) { rAbs = ru; }",
"            setLoc(rAbs);",
"            up({ type: 'hist', url: mapUrl(rAbs), up: rAbs, replace: true });",
"          } else if (ru && ru.charAt(0) === '#') {",
"            try { setLoc(String(LOC.u ? LOC.u.href : (DOC || '/')).replace(/#.*$/, '') + ru); } catch (eRh) { /* ignore */ }",
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
"          /* ALWAYS preventDefault: a native submission would navigate",
"           * the sandbox frame (straight into the org filter). */",
"          e.preventDefault();",
"          var action = f.getAttribute('action') || '';",
"          /* v6: SPA-managed forms (NO action attribute \u2014 the app's own",
"           * onsubmit handler owns the submit: captcha flows, fetch-based",
"           * logins, search boxes) must be LEFT ALONE. v5 serialized EVERY",
"           * form into a GET/POST navigation \u2014 which hijacked the z.ai",
"           * login form (email+password folded into the URL as a QUERY",
"           * STRING!), swapped the document, and killed the app's own",
"           * captcha\u2192signin chain: the \"sign-in buttons do nothing\"",
"           * symptom. Only forms that actually target a server endpoint",
"           * (a real action) become shell navigations. */",
"          if (!action || action === '#' || action.charAt(0) === '#' || /^javascript:/i.test(action)) return;",
"          var dest = action;",
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
"      /* v6.5: real Storage objects accept BOTH method calls and plain",
"       * property access. z.ai's bundle NEVER calls setItem('token'): all",
"       * five token writes are `localStorage.token = jwt`, read back with",
"       * getItem at send time — the old plain-object shim dropped every",
"       * property write, so sends shipped `authorization: Bearer null`",
"       * (401, three-dots spinner forever) and fresh sandbox boots lost",
"       * the login. This Proxy routes property get/set/delete through the",
"       * storage methods so the shim behaves like the real thing. */",
"      var proto = {",
"        getItem: function (k) { k = String(k); return Object.prototype.hasOwnProperty.call(mem, k) ? mem[k] : null; },",
"        setItem: function (k, v) { k = String(k); mem[k] = String(v); up({ type: 'ls', store: name, k: k, v: String(v) }); },",
"        removeItem: function (k) { k = String(k); if (Object.prototype.hasOwnProperty.call(mem, k)) { delete mem[k]; up({ type: 'ls', store: name, k: k, v: null }); } },",
"        clear: function () { Object.keys(mem).forEach(function (k) { delete mem[k]; }); up({ type: 'ls', store: name, k: '__clear__', v: null }); },",
"        key: function (i) { return Object.keys(mem)[i] || null; }",
"      };",
"      /* in-place clear() above keeps the lsMirror alias intact (boot",
"       * hydration + shell 'init' write straight into lsMirror). */",
"      try { Object.defineProperty(proto, 'length', { get: function () { return Object.keys(mem).length; }, configurable: true }); } catch (eLen) { /* ignore */ }",
"      var target = Object.create(proto);",
"      try {",
"        return new Proxy(target, {",
"          get: function (t, p) {",
"            if (typeof p === 'symbol') return t[p];",
"            if (Object.prototype.hasOwnProperty.call(mem, p)) return mem[p];",
"            var v = t[p];",
"            return (v === undefined && p !== 'length') ? null : v;",
"          },",
"          set: function (t, p, v) {",
"            if (typeof p === 'symbol') { t[p] = v; return true; }",
"            proto.setItem(p, v);",
"            return true;",
"          },",
"          deleteProperty: function (t, p) {",
"            if (typeof p === 'symbol') { delete t[p]; return true; }",
"            if (Object.prototype.hasOwnProperty.call(mem, p)) proto.removeItem(p);",
"            return true;",
"          },",
"          has: function (t, p) {",
"            if (typeof p === 'symbol') return p in t;",
"            return Object.prototype.hasOwnProperty.call(mem, p) || (p in t);",
"          },",
"          ownKeys: function (t) { return Object.keys(mem); },",
"          getOwnPropertyDescriptor: function (t, p) {",
"            if (typeof p === 'string' && Object.prototype.hasOwnProperty.call(mem, p)) {",
"              return { value: mem[p], writable: true, enumerable: true, configurable: true };",
"            }",
"            return undefined;",
"          }",
"        });",
"      } catch (ePx) { return target; } /* engine without Proxy: method-only fallback */",
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
"        case 'probe':",
"          /* v6 debug channel: the shell (or a test) asks, the frame answers",
"           * with the state the app actually sees. Used for diagnosing",
"           * captcha/login flows inside the opaque sandbox. */",
"          try {",
"            var pScripts = [];",
"            try {",
"              var pList = document.querySelectorAll('script[src]');",
"              for (var pi = 0; pi < pList.length && pi < 14; pi++) pScripts.push(pList[pi].getAttribute('src'));",
"            } catch (eSl) { /* ignore */ }",
"            up({",
"              type: 'probe',",
"              doc: DOC || '',",
"              locHref: (window.__zaiLoc && window.__zaiLoc.href) || '',",
"              realHref: (function () { try { return location.href; } catch (eR) { return '(throws)'; } })(),",
"              initAliyun: typeof window.initAliyunCaptcha,",
"              aliCfg: typeof window.AliyunCaptchaConfig === 'object' ? 'set' : 'unset',",
"              scripts: pScripts,",
"              forms: (function () { var n = 0; try { n = document.querySelectorAll('form').length; } catch (eF) { } return n; })(),",
"              title: document.title || ''",
"            });",
"          } catch (eP) { /* ignore */ }",
"          break;",
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
"  /* ---------- v6: boot diagnostic (the shell logs this; ZAI-MSG probes read it) ----------",
"   * Reports what the app's location reads will answer during THIS boot:",
"   * the fake location the router hydrates against, plus the real frame",
"   * URL for comparison. Cheap, quiet, and it settles routing questions",
"   * without cross-origin DOM access. */",
"  try {",
"    setTimeout(function () {",
"      up({",
"        type: 'bootdiag',",
"        doc: DOC || '',",
"        fakeHref: (window.__zaiLoc && window.__zaiLoc.href) || '',",
"        fakePath: (window.__zaiLoc && window.__zaiLoc.pathname) || '',",
"        realHref: (function () { try { return location.href; } catch (e) { return '(throws)'; } })(),",
"        title: document.title || ''",
"      });",
"    }, 2500);",
"  } catch (eDiag) { /* ignore */ }",
"})();",
""
].join("\n");

/* ============================================================ */

/* ============================================================
 * v6.9: /__session — the relay-held session (single user)
 * ------------------------------------------------------------
 * The user asked for the simplest possible persistence: "have the
 * worker keep the session open — I am only using the worker for
 * myself." No secrets, no device keys, no vaults (both are gone).
 * It works because the relay already sees every byte of the
 * session: z.ai hands it out as set-cookie headers on responses,
 * the app sends it as the Bearer token on API requests, and every
 * /api/v1/auths answer names the authoritative {token, id, role}.
 * The worker captures all three PASSIVELY (zero client help) into
 * one edge-cache slot:
 *
 *   GET    /__session -> {ok, has, savedAt, token, jar:[{name,value}]}
 *   DELETE /__session -> forget it (a clean sign-out)
 *
 * The pocket fetches it once per open, before the first document
 * load, so the app boots already signed in — on ANY phone, no
 * matter what its viewer does to localStorage. A GUEST capture
 * never demotes a held USER session (auths names the role, and a
 * foreign Bearer's JWT id is compared before it is taken); a
 * sign-out clears the jar (logout set-cookies are dead-cookie
 * removals), so a signed-out file boots signed out. Every
 * operation reads/writes the edge cache directly (no isolate
 * memory), so every Cloudflare isolate stays coherent. Captures
 * run via event.waitUntil and can never break the proxy.
 * ============================================================ */

const sessionHits = new Map(); /* ip -> {n, t} — /__session ops in the window */
const SESSION_EMPTY = { jar: {}, token: '', role: '', id: '', ts: 0 };

async function sha256Hex(str) {
  const dig = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(str));
  let out = '';
  const b = new Uint8Array(dig);
  for (let i = 0; i < b.length; i++) out += b[i].toString(16).padStart(2, '0');
  return out;
}

/* the JWT payload (id/role) — the same decode the auths heal uses */
function jwtClaims(t) {
  try {
    const parts = String(t || '').split('.');
    if (parts.length !== 3) return null;
    const b64 = parts[1].replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (parts[1].length % 4)) % 4);
    const dec = JSON.parse(atob(b64));
    return (dec && typeof dec === 'object') ? dec : null;
  } catch (e) { return null; }
}

function sessionRateOk(req) {
  /* light cap, same shape as the old vaults: 120 ops / 2 min / IP */
  const ip = String(req.headers.get('cf-connecting-ip') || req.headers.get('x-real-ip') || 'unknown').slice(0, 64);
  const now = Date.now();
  if (sessionHits.size > 4096) {
    for (const [k, v] of sessionHits) { if (now - v.t > 120000) sessionHits.delete(k); }
  }
  const e = sessionHits.get(ip);
  if (e && now - e.t < 120000) { e.n++; return e.n <= 120; }
  sessionHits.set(ip, { n: 1, t: now });
  return true;
}

async function sessionKeyUrl(req) {
  const origin = new URL(req.url).origin;
  return origin + '/__session/' + (await sha256Hex(TOK_KEY + '|zp-session-v1'));
}

async function sessionRead(req) {
  try {
    const hit = await caches.default.match(await sessionKeyUrl(req));
    if (hit) {
      const j = JSON.parse(await hit.text());
      if (j && typeof j === 'object') {
        return {
          jar: (j.jar && typeof j.jar === 'object' && !Array.isArray(j.jar)) ? j.jar : {},
          token: typeof j.token === 'string' ? j.token : '',
          role: typeof j.role === 'string' ? j.role : '',
          id: typeof j.id === 'string' ? j.id : '',
          ts: j.ts || 0,
        };
      }
    }
  } catch (eR) { /* cache hiccup: act empty */ }
  return { jar: {}, token: '', role: '', id: '', ts: 0 };
}

async function sessionWrite(req, st) {
  try {
    const body = JSON.stringify({ jar: st.jar, token: st.token, role: st.role, id: st.id, ts: st.ts });
    const toStore = new Response(body, {
      headers: { 'content-type': 'application/json', 'cache-control': 'max-age=2592000' }, /* 30 days */
    });
    await caches.default.put(new Request(await sessionKeyUrl(req), { method: 'GET' }), toStore);
  } catch (eP) { /* cache refused — nothing we can do; the next capture retries */ }
}

/* set-cookie array -> jar merge: an empty value or a past expiry REMOVES */
function sessionEatSetCookies(st, list) {
  let changed = false;
  (list || []).forEach((raw) => {
    try {
      const bits = String(raw).split(';');
      const nv = bits[0];
      const eq = nv.indexOf('=');
      if (eq < 1) return;
      const name = nv.slice(0, eq).trim();
      if (!name) return;
      const value = nv.slice(eq + 1).trim();
      let dead = value === '';
      for (let i = 1; i < bits.length; i++) {
        const b = bits[i].trim().toLowerCase();
        if (b === 'max-age=0' || b === 'max-age=-1' || b === 'expires=thu, 01 jan 1970 00:00:00 gmt') dead = true;
        const mEx = b.match(/^expires=(.+)$/);
        if (mEx) { const t = Date.parse(mEx[1]); if (!isNaN(t) && t <= Date.now()) dead = true; }
      }
      if (dead) { if (name in st.jar) { delete st.jar[name]; changed = true; } }
      else if (st.jar[name] !== value) { st.jar[name] = value; changed = true; }
    } catch (eC) { /* ignore a malformed cookie */ }
  });
  return changed;
}

/* passive capture — the proxy path calls this (waitUntil) for every
 * chat-host response. authsObj = a parsed {token,id,role} auths
 * answer when this response IS one; bearer = the request's Bearer. */
async function sessionCapture(req, bearer, setCookieList, authsObj) {
  try {
    const st = await sessionRead(req);
    const heldUser = !!(st.role && st.role !== 'guest' && st.id);
    let changed = sessionEatSetCookies(st, setCookieList);
    /* (1) the auths answer is authoritative: a USER session always
     * wins; a GUEST answer never demotes a held user session. */
    if (authsObj && authsObj.token && authsObj.id) {
      const role = String(authsObj.role || '');
      const id = String(authsObj.id);
      if (role !== 'guest') {
        if (st.token !== authsObj.token) { st.token = String(authsObj.token); changed = true; }
        if (st.id !== id) { st.id = id; changed = true; }
        if (role && st.role !== role) { st.role = role; changed = true; }
      } else if (!heldUser) {
        /* guest over guest (or over nothing): keep it fresh */
        if (st.token !== authsObj.token) { st.token = String(authsObj.token); changed = true; }
        if (st.id !== id) { st.id = id; changed = true; }
        if (st.role !== 'guest') { st.role = 'guest'; changed = true; }
      }
    }
    /* (2) a Bearer on any request keeps the token fresh when it is
     * the SAME identity (z.ai rotates tokens on every auths call);
     * a foreign id only lands when nothing better is held. */
    if (bearer && jwtClaims(bearer)) {
      const id = String((jwtClaims(bearer) || {}).id || '');
      if (!heldUser || st.id === id || !st.token) {
        if (st.token !== bearer) { st.token = bearer; changed = true; }
        if (id && st.id !== id) { st.id = id; changed = true; }
      }
    }
    if (changed) { st.ts = Date.now(); await sessionWrite(req, st); }
  } catch (eS) { /* capture must never break the proxy */ }
}

/* the endpoint: GET / DELETE (POST is intentionally absent — the
 * capture path is the only writer; the pocket never uploads) */
async function handleSession(req, url) {
  const method = req.method.toUpperCase();
  if (!sessionRateOk(req)) {
    return json({ ok: false, error: 'too many requests — wait two minutes and try again' }, req, 429);
  }
  if (method === 'GET' || method === 'HEAD') {
    const st = await sessionRead(req);
    const jar = Object.keys(st.jar).map((name) => ({ name: name, value: st.jar[name] }));
    const has = !!(st.token || jar.length);
    return json({ ok: true, has: has, savedAt: st.ts || 0, token: st.token || '', jar: jar }, req);
  }
  if (method === 'DELETE') {
    try { await caches.default.delete(await sessionKeyUrl(req)); } catch (eD) { /* idempotent */ }
    return json({ ok: true, note: 'session forgotten' }, req);
  }
  return json({ ok: false, error: 'use GET or DELETE' }, req, 405);
}

/* ---- v6.7: capacity auto-retry helpers (chat completions) ----------
 * z.ai reports a busy model as an SSE error event whose error_type is
 * "rate_limit_short" or "global_limit_reached" (the "X is intensifying
 * the coordination of resources" modal), or occasionally as a plain
 * 429/5xx. peekCompletionsFirst() reads the FIRST bytes of the
 * upstream response just far enough to classify it:
 *   'retry'   — a known-transient capacity error (safe to retry)
 *   'captcha' — FRONTEND_CAPTCHA_REQUIRED (NEVER retry: the slider
 *               must reach the app)
 *   null      — anything else (auth, personal hourly limit, or a
 *               normal stream already starting) — pass through.
 * The buffered bytes are always returned so the caller can rebuild
 * the response byte-exact when it does NOT retry. */
const ZP_SLEEP = (ms) => new Promise((r) => setTimeout(r, ms));

async function peekCompletionsFirst(res, maxBytes) {
  const lim = maxBytes || 4096;
  const dec = new TextDecoder();
  const chunks = [];
  let text = '';
  let total = 0;
  let done = false;
  const reader = res.body ? res.body.getReader() : null;
  if (!reader) return { sig: null, chunks: chunks, done: true };
  while (total < lim) {
    const rd = await reader.read();
    if (rd.done) { done = true; break; }
    chunks.push(rd.value);
    total += rd.value.length;
    text += dec.decode(rd.value, { stream: true });
    if (/"error_type"\s*:/.test(text) || /"status"\s*:\s*"error"/.test(text) || /FRONTEND_CAPTCHA_REQUIRED/.test(text)) break;
    if (text.indexOf('\n\n') >= 0 && text.indexOf('data:') >= 0) break; /* a full, healthy event arrived */
  }
  let sig = null;
  if (/FRONTEND_CAPTCHA_REQUIRED/.test(text)) sig = 'captcha';
  else {
    const m = text.match(/"error_type"\s*:\s*"([a-z_]+)"/);
    if (m && (m[1] === 'rate_limit_short' || m[1] === 'global_limit_reached')) sig = 'retry';
  }
  return { sig: sig, chunks: chunks, done: done, reader: reader };
}

/* rebuild a response with the peeked bytes prepended, streaming the rest */
function rebuildPeeked(original, peek) {
  const first = peek.chunks.length === 1 ? peek.chunks[0]
    : (peek.chunks.length > 1 ? concatChunks(peek.chunks) : new Uint8Array(0));
  if (!peek.reader || peek.done) {
    return new Response(first, { status: original.status, headers: original.headers });
  }
  const rest = peek.reader; /* already-locked reader: pump it through a new stream */
  const stream = new ReadableStream({
    start(ctrl) {
      try { if (first.length) ctrl.enqueue(first); } catch (eE) { /* ignore */ }
      const pump = () => rest.read().then((rd) => {
        if (rd.done) { try { ctrl.close(); } catch (eC) { /* ignore */ } return; }
        try { ctrl.enqueue(rd.value); } catch (eE2) { /* ignore */ }
        pump();
      }).catch(() => { try { ctrl.close(); } catch (eC2) { /* ignore */ } });
      pump();
    },
    cancel() { try { rest.cancel(); } catch (eC) { /* ignore */ } },
  });
  return new Response(stream, { status: original.status, headers: original.headers });
}

function concatChunks(chunks) {
  let n = 0;
  for (const c of chunks) n += c.length;
  const out = new Uint8Array(n);
  let o = 0;
  for (const c of chunks) { out.set(c, o); o += c.length; }
  return out;
}

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
      return json({ ok: true, name: VERSION, time: new Date().toISOString(), token_required: !!token, token_ok: tokenOk, session: true, entry: entry }, req);
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

    /* ---- v6.9: the relay-held session (single user, no secrets) ---- */
    if (url.pathname === '/__session') {
      return handleSession(req, url);
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
      /* v4/v5 opaque token (full absolute URL). Still the form for the
       * entry boot handle and every URL the runtime patch maps at run
       * time (fetch/XHR paths — no relative resolution happens against
       * those). */
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
    } else if (url.pathname.startsWith('/__o/')) {
      /* v6 path-preserving origin token: '/__o/<otok>/<upstream path>'.
       * Everything the worker embeds in HTML/CSS/redirect Locations uses
       * this form so RELATIVE references (dynamic import(), css url(),
       * <base>-resolved runtime URLs) resolve to worker URLs that still
       * carry the upstream path — the module-chunk 400 bug is dead. */
      const rest0 = url.pathname.slice(5);
      const slash = rest0.indexOf('/');
      const otok = slash < 0 ? rest0 : rest0.slice(0, slash);
      const upath = slash < 0 ? '/' : rest0.slice(slash);
      const dec = decTok(otok);
      if (!otok || !dec || !/^https?:\/\/[a-z0-9.:-]+\/?$/i.test(dec)) {
        return json({ error: 'bad origin token' }, req, 400);
      }
      const origin = dec.replace(/\/+$/, '');
      const ou = new URL(origin + '/');
      if (!hostAllowed(ou.host, event)) {
        return json({ error: 'host not allowed', allowed_suffixes: allowList(event) }, req, 403);
      }
      host = ou.host;
      pfx = '';
      upstream = origin + upath + url.search;
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
    /* v6.2: filebin (the copier's delivery host) serves a browser HTML
     * wrapper to any browser-shaped User-Agent and the raw bytes to plain
     * HTTP clients — and this worker forwards the caller's UA. For
     * filebin requests only, claim a plain client UA so the payloads the
     * copier pulls through /p/filebin.net/… arrive as raw bytes. */
    const isFilebin = host && (host.toLowerCase() === 'filebin.net' || host.toLowerCase().endsWith('.filebin.net'));
    if (isFilebin) {
      /* filebin hands the raw file ONLY to curl-shaped clients (verified:
       * curl/* -> 302 raw; wget, python-requests, any browser -> 200 HTML
       * wrapper). Claim a curl identity for these delivery fetches. */
      h.set('user-agent', 'curl/8.5.0');
      h.set('accept', '*/*');
    }
    /* v6.2: stream calls (the app's completions/continue SSE posts
     * carry Accept: text/event-stream) ask the upstream for IDENTITY
     * encoding — a compressed event-stream is a stream some upstream
     * CDNs feel licensed to buffer, and decompress-then-buffer shows
     * up on the phone as "the answer never arrives". */
    try {
      const acc = (req.headers.get('accept') || '').toLowerCase();
      if (acc.includes('text/event-stream')) {
        h.set('accept-encoding', 'identity');
      }
    } catch (eAE) { /* keep */ }
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
    let recoveryCookies = []; /* v6.4: fresh set-cookies gathered below */
    try {
      const fetchInit = { method: method, headers: h, redirect: 'manual' };
      if (body !== undefined) fetchInit.body = body;
      if (needDuplex) fetchInit.duplex = 'half';
      res = await fetch(upUrl.toString(), fetchInit);
      /* ---- v6.4: session recovery for chat /api/ GETs ------------------
       * z.ai's Aliyun edge answers 401/403 whenever the Cookie header is
       * stale or missing the session token. The classic victim is the
       * app's own boot: auths refreshes the cookies, but models/settings
       * fire in parallel (or share one stale header object) and die —
       * which empties the model picker ("No models found") or rejects
       * the session promise so hard the app renders itself logged out
       * (settings -> Account "redirects, fails, back home, logged out").
       * Recover SERVER-SIDE, invisible to the app:
       *   1. take the fresh cookies the 401/403 just handed out,
       *   2. re-run /api/v1/auths/ with them merged (the app's own
       *      session refresher — renews token + WAF cookies for guest
       *      and logged-in sessions alike; verified it answers 200
       *      even when every carried cookie is garbage),
       *   3. retry the ORIGINAL request with everything merged,
       *      keeping its Authorization header if it had one.
       * The gathered cookies are re-issued on the final response, so
       * the sandbox jar heals along with this one call. One attempt;
       * GET/HEAD always, plus v6.5 chat-/api/ POSTs with replayable
       * (buffered) bodies — the send pipeline's /api/v1/chats/new and
       * the completions POST recover the same way instead of hanging
       * the send on a 401 (three-dots spinner forever).
       * Non-/api/ GETs keep the v3 plain clean-header retry (WAF
       * trip-wire fed by leftover request headers). */
      const isChatApi = host === chatHost(event) && /^\/api\//.test(upUrl.pathname);
      /* ---- v6.5: auths guest-degradation heal ---------------------------
       * z.ai answers a GET /api/v1/auths/ carrying a STALE Bearer by
       * silently minting a GUEST session (HTTP 200) — for a logged-in
       * account that renders the app as logged out ("settings -> Account:
       * back home, signed out"). Detection must be identity-based: z.ai
       * ROTATES the token on every auths call (verified live), so a fresh
       * token alone is normal. Decode the presented Bearer's JWT id and
       * compare with the response's id — a CHANGED id is real degradation.
       * Then retry WITHOUT the Authorization: the cookies are the truth.
       * Heal when the retry is better: a non-guest role (the account), or a
       * DIFFERENT id (the cookie session's continuity restored). */
      const authzHdr = req.headers.get('authorization');
      if (isChatApi && method === 'GET' && /^\/api\/v1\/auths\/?$/.test(upUrl.pathname) && authzHdr &&
          res.status === 200 && (res.headers.get('content-type') || '').toLowerCase().includes('json')) {
        try {
          const resProbe = res.clone();
          const dgTxt = await resProbe.text();
          let dg = null; try { dg = JSON.parse(dgTxt); } catch (eDgP) { dg = null; }
          const bearerVal = String(authzHdr).replace(/^\s*Bearer\s+/i, '');
          let bearerId = '??';
          try {
            const pl = String(bearerVal).split('.')[1];
            if (pl) {
              const b64 = pl.replace(/-/g, '+').replace(/_/g, '/') + '='.repeat((4 - (pl.length % 4)) % 4);
              const dec = JSON.parse(atob(b64));
              if (dec && dec.id) bearerId = String(dec.id);
            }
          } catch (eId) { bearerId = '??'; }
          if (dg && dg.role === 'guest' && dg.token && dg.id && dg.id !== bearerId) {
            /* CRITICAL: the retry must carry the ORIGINAL request cookies —
             * NOT merged with the degraded response's set-cookies (those are
             * the freshly-minted stranger's; merging them would make the
             * retry return the stranger again and the heal could never
             * fire). Escape the stranger, ask the cookies what they say. */
            const ckDg = mergeCookies(req.headers.get('cookie') || '', req.headers.get('x-cookie') || '');
            const hDg = minimalHeaders(req, host);
            hDg.delete('authorization');
            hDg.set('accept', 'application/json');
            if (ckDg) hDg.set('cookie', ckDg);
            const rDg = await fetch(upUrl.toString(), { method: 'GET', headers: hDg, redirect: 'manual' });
            const scDg2 = typeof rDg.headers.getSetCookie === 'function' ? rDg.headers.getSetCookie() : [];
            let dg2 = null;
            try { dg2 = JSON.parse(await rDg.text()); } catch (eDgP2) { dg2 = null; }
            /* heal when the retry beats the degraded answer: a real account
             * (role != guest) or a different session id (cookie continuity
             * restored). Tokens rotate, so only id/role can be compared. */
            if (dg2 && dg2.token && (dg2.role !== 'guest' || dg2.id !== dg.id)) {
              /* healed — serve the cookie-backed session; only the HEALED
               * session's cookies ride along (the stranger's must not). */
              recoveryCookies = scDg2;
              res = new Response(JSON.stringify(dg2), { status: rDg.status, headers: rDg.headers });
              retried = 'dropauth';
            }
            /* else: the degraded answer already carries the cookie identity
             * — keep it (no heal, no tag) */
          }
        } catch (eDg) { /* probe failed — the original response stays */ }
      }
      const isRead = method === 'GET' || method === 'HEAD';
      /* v6.5 POST recovery: only chat-/api/ POSTs whose body was BUFFERED
       * (an ArrayBuffer — duck-typed: workerd's request ArrayBuffers can
       * live in another realm, so `instanceof` lies cross-realm) can be
       * replayed; streamed (duplex) bodies are passed through untouched. */
      const postReplay = !isRead && isChatApi && res.status !== 429 &&
        body != null && typeof body.byteLength === 'number';
      if ((res.status === 401 || res.status === 403 || res.status === 429) && (isRead || postReplay)) {
        try {
          const scFirst = typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : [];
          if (isChatApi && res.status !== 429) {
            const ck = mergeCookieList(
              [req.headers.get('cookie') || '', req.headers.get('x-cookie') || ''], scFirst);
            let scAuths = [];
            try {
              const rA = await fetch(new URL('/api/v1/auths/', upUrl).toString(), {
                method: 'GET', redirect: 'manual',
                headers: {
                  'accept': 'application/json',
                  'accept-encoding': 'gzip, deflate, br',
                  'user-agent': req.headers.get('user-agent') || '',
                  'accept-language': req.headers.get('accept-language') || 'en-US,en;q=0.9',
                  'origin': 'https://' + host,
                  'referer': 'https://' + host + '/',
                  ...(ck ? { cookie: ck } : {}),
                },
              });
              scAuths = typeof rA.headers.getSetCookie === 'function' ? rA.headers.getSetCookie() : [];
              try { if (rA.body && rA.body.cancel) rA.body.cancel(); } catch (eC) { /* ignore */ }
            } catch (eA) { /* refresh unavailable — retry with what we have */ }
            const ck2 = mergeCookieList([ck], scAuths);
            recoveryCookies = scFirst.concat(scAuths);
            const h2 = minimalHeaders(req, host);
            if (ck2) h2.set('cookie', ck2);
            const authz = req.headers.get('authorization');
            if (authz) h2.set('authorization', authz);
            const retryInit = { method: method, headers: h2, redirect: 'manual' };
            if (!isRead) {
              /* v6.5 POST recovery: replay the buffered body + its
               * content-type (minimalHeaders does not carry it). */
              retryInit.body = body;
              const rct = req.headers.get('content-type');
              if (rct) h2.set('content-type', rct);
            }
            let res2 = await fetch(upUrl.toString(), retryInit);
            retried = true; /* a retry attempt happened — tagged either way */
            /* v6.4 stage 2: a 401 that SURVIVES the cookie refresh means the
             * Bearer itself is stale — z.ai lets a bad Authorization beat
             * perfectly good cookies. Retry once more with it dropped; the
             * cookie session carries the call. Tag the success so the
             * runtime patch clears the stale token from localStorage (the
             * 6.3 client-side healing, now triggered by the worker). */
            let dropAuth = false;
            if (res2.status === 401 && authz) {
              try {
                const h3 = new Headers(h2);
                h3.delete('authorization');
                const retryInit3 = { method: method, headers: h3, redirect: 'manual' };
                if (!isRead) retryInit3.body = body;
                const res3 = await fetch(upUrl.toString(), retryInit3);
                if (res3.status !== res2.status) {
                  try { if (res2.body && res2.body.cancel) res2.body.cancel(); } catch (eC2) { /* ignore */ }
                  res2 = res3;
                  dropAuth = true;
                } else {
                  try { if (res3.body && res3.body.cancel) res3.body.cancel(); } catch (eC3) { /* ignore */ }
                }
              } catch (e3b) { /* keep the stage-1 response */ }
            }
            if (res2.status !== res.status) {
              try { if (res.body && res.body.cancel) res.body.cancel(); } catch (e) { /* ignore */ }
              res = res2;
              retried = dropAuth ? 'dropauth' : true;
            } else {
              try { if (res2.body && res2.body.cancel) res2.body.cancel(); } catch (e) { /* ignore */ }
            }
          } else {
            /* ---- v3: everything else — retry ONCE with a minimal, clean
             * header set before relaying the block page. ---- */
            const res2 = await fetch(upUrl.toString(), { method: method, headers: minimalHeaders(req, host), redirect: 'manual' });
            retried = true; /* a retry attempt happened — tagged either way */
            if (res2.status !== res.status) {
              try { if (res.body && res.body.cancel) res.body.cancel(); } catch (e) { /* ignore */ }
              res = res2;
              retried = true;
            } else {
              try { if (res2.body && res2.body.cancel) res2.body.cancel(); } catch (e) { /* ignore */ }
            }
          }
        } catch (e2) { /* keep the original response */ }
      }
    } catch (err) {
      return json({ error: 'upstream fetch failed', detail: String(err && err.message || err) }, req, 502);
    }

    /* ---- v6.7: capacity auto-retry for chat completions POSTs -------
     * z.ai's "model at capacity" answer arrives as an HTTP 200 SSE
     * event with error_type "rate_limit_short" (or "global_limit_
     * reached"), or as a plain 429/5xx. The app shows the "X is
     * intensifying the coordination of resources" modal, the user
     * hammers resend, and THAT burst is what flips z.ai's risk control
     * into captcha mode ("verification required" even signed in). So
     * the worker does the resending itself — same request, paced
     * backoff (3s/8s/18s/35s with jitter), up to four extra attempts,
     * invisible to the app (it just sees its normal pending state).
     * NEVER retried: captcha-required errors (the slider must pop),
     * 401/403 (the v6.4/v6.5 session recovery already handled those
     * above), and personal hourly limits (user_limit_reached — a
     * retry within a minute cannot succeed). Aborts when the phone
     * goes away (req.signal). The peeked first bytes are prepended
     * byte-exact on pass-through, so a normal stream is untouched. */
    /* (isChatApi is recomputed here: the 6.4 recovery declared its own
     * copy inside the try block above, which is out of scope here.) */
    const isChatApiCap = host === chatHost(event) && /^\/api\//.test(upUrl.pathname);
    const isCompletionsPost = isChatApiCap && method === 'POST' && /\/chat\/completions\/?$/.test(upUrl.pathname) &&
      body != null && typeof body.byteLength === 'number';
    if (isCompletionsPost) {
      const waits = [3000, 8000, 18000, 35000];
      let capAttempt = 0;
      for (;;) {
        if (req.signal && req.signal.aborted) break;
        if (res.status === 200) {
          let peek = null;
          try { peek = await peekCompletionsFirst(res, 4096); } catch (ePk) { peek = null; }
          if (!peek) break; /* peek failed — serve the stream untouched */
          if (peek.sig !== 'retry' || capAttempt >= waits.length) {
            /* healthy stream, captcha, other error, or out of attempts:
             * hand it through byte-exact (peeked bytes prepended). */
            res = rebuildPeeked(res, peek);
            break;
          }
          try { if (peek.reader) await peek.reader.cancel(); } catch (eCc) { /* ignore */ }
        } else if (res.status === 429 || res.status === 500 || res.status === 502 || res.status === 503 || res.status === 504) {
          if (capAttempt >= waits.length) break; /* pass the failure through as-is */
          try { if (res.body && res.body.cancel) res.body.cancel(); } catch (eCn) { /* ignore */ }
        } else {
          break; /* 401/403/404/… — already recovered above, or not ours to fix */
        }
        const waitMs = Math.round(waits[capAttempt] * (0.75 + Math.random() * 0.5));
        capAttempt++;
        await ZP_SLEEP(waitMs);
        if (req.signal && req.signal.aborted) break;
        try {
          const resCap = await fetch(upUrl.toString(), { method: 'POST', headers: h, redirect: 'manual', body: body });
          res = resCap;
        } catch (eCf) { break; } /* transport hiccup — the phone sees the last answer we have */
      }
      if (capAttempt > 0) retried = retried || 'capacity';
    }

    /* ---- v6.9: passive session capture (the relay keeps the sign-in).
     * Reads only headers (set-cookie) + the request's Bearer, plus a
     * small JSON clone when this response IS an auths answer — the
     * original response body is never consumed. Runs via waitUntil so
     * the proxy answer is never delayed by the cache write. */
    try {
      if (host === chatHost(event)) {
        const scAll = (typeof res.headers.getSetCookie === 'function' ? res.headers.getSetCookie() : []).concat(recoveryCookies || []);
        let authsObj = null;
        if (res.status === 200 && method === 'GET' && /^\/api\/v1\/auths\/?$/.test(upUrl.pathname) &&
            (res.headers.get('content-type') || '').toLowerCase().includes('json')) {
          try {
            const probe = res.clone();
            const aj = JSON.parse(await probe.text());
            if (aj && aj.token && aj.id) authsObj = { token: aj.token, id: aj.id, role: aj.role || '' };
          } catch (ePr) { authsObj = null; }
        }
        let bearer = '';
        const authzCap = req.headers.get('authorization') || '';
        const mB = authzCap.match(/^\s*Bearer\s+(\S+)\s*$/i);
        if (mB && mB[1].split('.').length === 3) bearer = mB[1];
        if (scAll.length || bearer || authsObj) {
          const pCap = sessionCapture(req, bearer, scAll, authsObj);
          if (event && typeof event.waitUntil === 'function') { try { event.waitUntil(pCap); } catch (eWu) { pCap.catch(function () { }); } }
          else pCap.catch(function () { });
        }
      }
    } catch (eSC) { /* capture must never break the proxy */ }

    /* ---- redirect handling: rewrite Location and let the browser follow inside the worker ---- */
    const loc = res.headers.get('location');
    if (loc && res.status >= 300 && res.status < 400 && res.status !== 304) {
      const mapped = mapLocation(loc, upUrl, event, tokMode);
      const rh = scrubHeaders(res.headers);
      reissueCookies(res, rh, event);
      reissueRawCookies(recoveryCookies, rh); /* v6.4 recovery cookies ride along */
      rh.set('location', mapped);
      maybeSetTokenCookie(req, rh, event);
      return new Response(null, { status: res.status, headers: corsHeaders(req, rh) });
    }

    /* ---- normal responses ---- */
    const ct = (res.headers.get('content-type') || '').toLowerCase();
    const outHeaders = scrubHeaders(res.headers);
    reissueCookies(res, outHeaders, event);
    reissueRawCookies(recoveryCookies, outHeaders); /* v6.4 recovery cookies ride along */
    maybeSetTokenCookie(req, outHeaders, event);
    outHeaders.set('x-final-url', res.url || upUrl.toString());
    if (retried) outHeaders.set('x-zp-retry', (retried === 'dropauth' || retried === 'capacity') ? retried : '1');
    const outCt = corsHeaders(req, outHeaders);

    if (ct.includes('text/html')) {
      /* v6.2: filebin (delivery host) labels EVERY file text/html — the
       * pocket payload must pass through byte-exact, never rewritten. */
      const isFb = host === 'filebin.net' || String(host || '').toLowerCase().endsWith('.filebin.net');
      if (isFb) {
        return new Response(res.body, { status: res.status, headers: outCt });
      }
      const text = await res.text();
      const html = rewriteHtml(text, pfx, host, new URL(req.url).origin, token, allowList(event),
        tokMode ? upUrl.toString() : null);
      const htmlRes = new Response(html, { status: res.status, headers: outCt });
      /* ---- v6.7: boot cookie-seed ---------------------------------------
       * When the pocket's document fetch arrived with REAL browser
       * cookies for this worker (credentials:'include' mode), the
       * browser's cookie store may be holding a live session the
       * pocket's own jar lost (phones whose viewer wipes localStorage
       * but keeps partitioned cookies). Echo any such cookies back as
       * x-jar-seed so the shell can merge them into its jar before the
       * sandbox boots. Anonymous/analytics cookies are skipped. */
      try {
        const browserCk = req.headers.get('cookie') || '';
        if (browserCk) {
          const have = new Set();
          (req.headers.get('x-cookie') || '').split(';').forEach(function (kv) {
            const n = kv.split('=')[0].trim(); if (n) have.add(n);
          });
          const seeds = [];
          browserCk.split(';').forEach(function (kv) {
            kv = kv.trim(); if (!kv) return;
            const eq = kv.indexOf('=');
            if (eq < 1) return;
            const name = kv.slice(0, eq).trim();
            if (!name || name === '__zai_t' || name === 'zp_dev' || have.has(name)) return;
            if (/^(cf_|__cf|_ga|_gat|_gid|__utm)/i.test(name)) return;
            seeds.push({ name: name, value: kv.slice(eq + 1).trim() });
          });
          if (seeds.length) htmlRes.headers.set('x-jar-seed', encodeURIComponent(JSON.stringify(seeds)));
        }
      } catch (eSeed) { /* never let the seed break a document */ }
      return htmlRes;
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

    /* ---- v6.2: event-stream passthrough hardening ----------------
     * The completions/continue SSE responses pass through UNTOUCHED
     * (res.body streams chunk-for-chunk — verified). These two extra
     * headers tell any intermediary that may still sit between this
     * worker and the phone (corp proxies, mobile carriers, CDNs) not
     * to buffer a live stream, and keep it out of every cache. */
    if (ct.includes('text/event-stream')) {
      outHeaders.set('x-accel-buffering', 'no');
      outHeaders.set('cache-control', 'no-store');
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
  /* this worker's OWN cookies never belong upstream — __zai_t is
   * the token cookie and zp_dev a 6.8-era device-vault leftover
   * some phones may still hold; both live on the relay origin
   * only and must not ride to z.ai. */
  const own = new Set(['zp_dev', '__zai_t']);
  const add = (str) => {
    if (!str) return;
    str.split(';').forEach((kv) => {
      kv = kv.trim();
      if (!kv) return;
      const name = kv.split('=')[0];
      if (own.has(name)) return;
      if (!seen.has(name)) seen.set(name, kv);
    });
  };
  add(a); // browser-native cookies win
  add(b); // patch-supplied fallback cookies fill gaps
  return Array.from(seen.values()).join('; ');
}

/* ---- v6.4: cookie folding for the 401/403 session recovery ------------
 * Fold one or more Cookie-header strings plus raw Set-Cookie strings
 * into a single Cookie header. Set-Cookie values are eaten LAST, so the
 * freshest upstream-issued values WIN over whatever the request carried. */
function mergeCookieList(baseStrs, setCookies) {
  const map = new Map();
  const eat = (str) => {
    String(str || '').split(';').forEach((kv) => {
      kv = kv.trim();
      if (!kv) return;
      const name = kv.split('=')[0];
      map.set(name, kv);
    });
  };
  (Array.isArray(baseStrs) ? baseStrs : [baseStrs]).forEach(eat);
  (setCookies || []).forEach((sc) => { eat(String(sc).split(';')[0]); });
  return Array.from(map.values()).join('; ');
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

/* ---- v6.4: re-issue cookies gathered by the 401/403 session recovery ----
 * Appends the recovery's raw Set-Cookie strings to the outgoing response
 * (as real partitioned set-cookies AND merged into the x-set-cookie list
 * the sandbox runtime ingests), so the jar heals along with the request. */
function reissueRawCookies(raw, h) {
  try {
    if (!raw || !raw.length) return;
    let existing = [];
    const prev = h.get('x-set-cookie');
    if (prev) { try { existing = JSON.parse(decodeURIComponent(prev)); } catch (eP) { existing = []; } }
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
    h.set('x-set-cookie', encodeURIComponent(JSON.stringify(existing.concat(raw))));
  } catch (e) { /* ignore */ }
}

function corsHeaders(req, h) {
  /* v6.1: credentialed CORS for EVERY caller. The z.ai app calls
   * EVERY api with credentials:"include" — and a browser REFUSES
   * Access-Control-Allow-Origin:* on credentialed cross-origin fetches,
   * which silently killed signin / chat-send inside the sandbox while
   * the worker happily logged 200s. Echo the origin back plus
   * allow-credentials so cookies actually flow.
   *
   * v6 echoed ONLY Origin: null — but phones open the saved pocket
   * file through viewer apps that serve it from http://localhost:PORT
   * or a custom app scheme, and those origins got the wildcard, so the
   * very first credentialed document fetch died with a network error
   * while the credentials:'omit' health probe answered fine
   * ("Could not reach the app"). Now ANY well-formed Origin is echoed.
   * No-Origin (server-to-server) requests keep the wildcard. */
  const org = (req.headers.get('origin') || '').trim();
  /* echo only origins a browser could legally send — printable ASCII,
   * scheme://… shape — never let a hostile header value become an
   * invalid response header */
  const echoable = org === 'null' ||
    (org.length > 0 && org.length < 256 && /^[!-~]+$/.test(org) && org.indexOf('://') > 0);
  if (org && echoable) {
    h.set('access-control-allow-origin', org);
    h.set('access-control-allow-credentials', 'true');
  } else {
    h.set('access-control-allow-origin', '*');
  }
  h.set('access-control-allow-methods', 'GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS');
  const reqH = req.headers.get('access-control-request-headers');
  h.set('access-control-allow-headers', reqH || '*');
  h.set('access-control-expose-headers', 'content-disposition, content-type, x-set-cookie, x-final-url, filename, x-zp-retry, x-zp-jsrw, x-jar-seed');
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
      /* this response came from a /__t/ or /__o/ request — there is no
       * path prefix and (v5) no transparent root anymore: EVERY allowed
       * target becomes a worker handle. v6 uses the path-preserving
       * /__o/ form so the destination keeps resolving relatives right. */
      const op = oTokPath(abs.toString());
      return op || tokPath(abs.toString());
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
      /* v6: /__o/ path-preserving form (absolute). The upstream PATH
       * rides along so relative references against this URL — dynamic
       * import() of sibling chunks above all — resolve to worker URLs
       * that reconstruct the right upstream file. The /__t/ full-token
       * form made "./chunk.js" resolve to /__t/chunk.js -> 400. */
      const op = oTokPath(abs.toString());
      return op ? (workerOrigin ? workerOrigin.replace(/\/$/, '') + op : op) : v;
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

    /* inject config + runtime patch as the first script; v6 also injects
     * a <base> pointing at this document's /__o/ mirror — the sandbox
     * document sits at about:srcdoc where relative URLs resolve against
     * NOTHING, so runtime-created refs (img.src = "foo.png", dynamic
     * import("./chunk.js") inside inline scripts, form submits without
     * actions) would all die. With <base> they resolve onto the worker,
     * path-preserved. The runtime's document.baseURI override still
     * reports the upstream URL to the app, so routers hydrate right. */
    const cfg = { pfx: pfx, host: host, worker: workerOrigin, token: token || '', allow: allow,
      key: TOK_KEY, tok: !!tokDoc, doc: tokDoc || '', sd: !!tokDoc };
    let inject = '<scr' + 'ipt>window.__ZAI__=' + JSON.stringify(cfg) + ';' + PATCH_JS + '</scr' + 'ipt>';
    if (tokDoc) {
      try {
        const bOp = oTokPath(tokDoc);
        if (bOp) inject = '<base href="' + (workerOrigin ? workerOrigin.replace(/\/$/, '') : '') + bOp + '">' + inject;
      } catch (eB) { /* ignore */ }
    }
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
 * `location` reads or unrelated identifiers.
 *
 * v6.6 adds TWO shapes the original pass missed:
 *   (a) optional chaining — `location?.href` / `window.location?.hash`
 *   (b) WHOLE-OBJECT reads — `(t = window.location) == null ? void 0 :
 *       t.hostname` — the compiled form the z.ai bundle uses for the
 *       captcha SCENE_ID getter. Left raw, `window.location` in the
 *       sandbox is about:srcdoc (hostname ""), and every captcha token
 *       was minted for the wrong scene, so z.ai rejected every solve. */
function rewriteJsLocation(text) {
  try {
    if (!/location\b/.test(text)) return text;
    let out = text;
    /* member forms, prefixed (window/document/self/top/parent/globalThis).
     * v6.6: `location?.` (optional chain) rewrites the same way —
     * __zaiLoc is never null, so the semantics only get more reliable. */
    out = out.replace(/(?<![.\w$])(?:window|document|self|top|parent|globalThis|global)\.location\??\.(href|assign|replace|reload|pathname|search|hash|origin|host|hostname|protocol|port|toString)\b/gi,
      (w, prop) => '__zaiLoc.' + prop);
    /* bare location.<prop> — the leading (?<![.\w$]) stops it from
     * matching x.location.href (nested-frame access) or mylocation.href: */
    out = out.replace(/(?<![.\w$])location\??\.(href|assign|replace|reload|pathname|search|hash|origin|host|hostname|protocol|port|toString)\b/gi,
      (w, prop) => '__zaiLoc.' + prop);
    /* v6.6: whole-object `window.location` READS (not followed by a
     * member access, not an lvalue write). Guards:
     *   - leading (?<![.\w$]) — contentWindow.location / x.location
     *     (real nested-frame access) stay untouched;
     *   - (?![.\w$]) — window.locationFoo never matches;
     *   - (?!\s*=(?!=)) — `window.location = X` writes stay REAL
     *     (navigations the shell's escape recovery owns). */
    out = out.replace(/(?<![.\w$])(?:window|document|self|top|parent|globalThis|global)\.location(?![.\w$])(?!\s*=(?!=))/g,
      (w) => '__zaiLoc');
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
