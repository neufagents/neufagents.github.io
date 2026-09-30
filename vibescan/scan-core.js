/*!
 * vibescan scan-core.js -- browser-side static detection engine (v0.2).
 *
 * Ported 1:1 from agents/vibescan/vibescan.py v0.2 (reference implementation).
 * Rule IDs are shared with the CLI ('secrets' / 'dotenv' / 'client_leaks' /
 * 'service_role' + the tree-level 'deps' check). When updating rules here,
 * update vibescan.py the same day (see browser/README.md, sync discipline).
 *
 * - DOM-free: runs in the browser (<script src="scan-core.js"> -> window.VibescanCore)
 *   and in node (CommonJS require). No network, no storage, no side effects.
 * - Input:  scanFiles([{path, content}, ...])  content = decoded UTF-8 text.
 *   The caller decides which files to include (binary / size filtering is the
 *   caller's job, mirroring the CLI's BINARY_EXT and MAX_FILE_BYTES behavior).
 * - Output: {findings, counts, verdict, scanned}
 *   finding = {check, sev, file, line, title, ev, raw}
 *     ev  = evidence string in the same masked form as the CLI report
 *     raw = the matched value / source line, for the UI to render its own
 *           first4/last4 mask. raw is local-only: never uploaded, never
 *           included in copied summaries. UI must mask before displaying.
 *
 * Privacy: all scanning happens in this file, in the caller's own runtime.
 * Nothing in here transmits data anywhere.
 */
(function (root, factory) {
  if (typeof module === 'object' && module.exports) { module.exports = factory(); }
  else { root.VibescanCore = factory(); }
}(typeof globalThis !== 'undefined' ? globalThis : this, function () {
  'use strict';

  var VERSION = '0.2';
  var SEV_ORDER = { HIGH: 0, MEDIUM: 1, LOW: 2, INFO: 3 };
  // Browser instant layer covers the four static families (S1-S4).
  // 'deps' is the tree-level lockfile check only (npm audit stays CLI/manual).
  var CHECKS = ['secrets', 'dotenv', 'client_leaks', 'service_role'];

  /* ------------------------------- regexes ------------------------------- */
  /* Keep in exact sync with vibescan.py v0.2. */

  // line-level ignore: a comment containing this marker skips the whole line
  var IGNORE_MARK = /vibescan:\s*ignore/i;

  var SECRET_PATTERNS = [
    ['openai-style API key', /\bsk-[A-Za-z0-9_-]{20,}\b/, 'HIGH'],
    ['stripe live key', /\b[sr]k_live_[0-9a-zA-Z]{10,}\b/, 'HIGH'],
    ['google API key', /\bAIza[0-9A-Za-z_-]{35}\b/, 'HIGH'],
    ['aws access key', /\bAKIA[0-9A-Z]{16}\b/, 'HIGH'],
    ['github token', /\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/, 'HIGH'],
    ['private key block', /-----BEGIN (?:RSA |EC |OPENSSH |PGP )?PRIVATE KEY-----/, 'HIGH'],
    ['slack token', /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/, 'HIGH']
  ];
  var GENERIC_SECRET = /\b(api[_-]?key|apikey|client_secret|secret|passwd|password|access[_-]?token|auth[_-]?token|service[_-]?role[_-]?key)\b\s*[:=]\s*["']([A-Za-z0-9_+=\/-]{16,})["']/i;
  var PLACEHOLDER = /(example|sample|dummy|placeholder|change[_-]?me|your[_-]|xxx+|todo|none|null|redacted|secret[_-]?here|\$\{|\{\{|<[^>]+>|\.\.\.)/i;
  var JWT_SRC = '\\b(eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]{8,})\\b';
  // public contexts for google keys (embed players etc.)
  var PUBLIC_GOOGLE_CTX = /(youtube|ytimg|gstatic|google\.com\/maps|maps\.google|googleapis\.com\/maps|recaptcha)/i;
  // known documentation example values (AWS docs sample key; not a real credential)
  var KNOWN_EXAMPLE_VALUES = ['AKIAIOSFODNN7EXAMPLE'];
  // client SDK contexts (Braze/Segment/Sentry... public by design -> downgrade, not ignore)
  var PUBLIC_SDK_CTX = /(braze|segment\.io|segment\.com|amplitude|posthog|sentry|algolia|mapbox|mixpanel|hotjar|intercom|drift\.com|crisp\.chat|datadog|plausible|googletagmanager|gtag\(|google-analytics|recaptcha|cloudflareinsights)/i;
  var DOTENV_BAD = /(^|\/)\.env($|\.[A-Za-z0-9_.-]+$)/i;
  var DOTENV_OK = /\.(example|sample|template|dist|md)$/i;
  var CLIENT_DIRS = /(^|\/)(src|app|apps|pages|components|public|static|client|frontend|web|ui)(\/|$)/i;
  var PUBLIC_ENV_SRC = '\\b(NEXT_PUBLIC_|VITE_|REACT_APP_|NUXT_ENV_|PUBLIC_)([A-Z0-9_]+)\\b';
  var PUBLIC_SENSITIVE = /(SECRET|SERVICE|PRIVATE|ADMIN|PASSWORD|PASSWD|TOKEN|SERVER|API_?KEY|ACCESS_?KEY|AUTH|CREDENTIAL)/;
  var PUBLIC_EXEMPT = /(ANON|PUBLIC_KEY|PUBLISHABLE|SITE|CLIENT|DOMAIN|URL|NAME|ID$)/;
  // server-side env reads (correct service_role usage; only risky if bundled client-side)
  var ENV_REF = /(process\.env|os\.environ|os\.getenv|import\.meta\.env|getenv\(|Environment\.GetEnvironmentVariable)/i;

  /* ------------------------------- helpers ------------------------------- */

  function splitLines(text) {
    text = String(text);
    if (text === '') return [];
    var lines = text.split(/\r\n|\r|\n/);
    if (lines.length && lines[lines.length - 1] === '') lines.pop();
    return lines;
  }

  function mask(s) { // CLI-style evidence mask
    s = String(s);
    return s.length > 8 ? s.slice(0, 6) + '...' : '***';
  }

  function snip(s, n) {
    n = n || 64;
    s = String(s).trim();
    return s.length > n ? s.slice(0, n) + '...' : s;
  }

  function lowEntropy(v) {
    var seen = {};
    var n = 0;
    for (var i = 0; i < v.length; i++) {
      if (!seen[v[i]]) { seen[v[i]] = 1; n++; }
    }
    return n <= 3;
  }

  function decodeB64Url(b64) {
    var s = String(b64).replace(/-/g, '+').replace(/_/g, '/');
    while (s.length % 4) s += '=';
    if (typeof Buffer !== 'undefined') return Buffer.from(s, 'base64').toString('utf8');
    return atob(s); // ASCII payloads only (JWT JSON claims); non-ASCII would mangle, acceptable
  }

  function publicEnvSearch(line) {
    return new RegExp(PUBLIC_ENV_SRC).test(line);
  }

  /* ------------------------------- checks -------------------------------- */

  function scanSecrets(path, text, findings) {
    var lines = splitLines(text);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (IGNORE_MARK.test(line)) continue;
      // +/- context window (3 lines before .. 2 after) for public-key context judgment
      var ctx = lines.slice(Math.max(0, (i + 1) - 4), (i + 1) + 2).join('\n');
      var lineHits = [];
      for (var pi = 0; pi < SECRET_PATTERNS.length; pi++) {
        var label = SECRET_PATTERNS[pi][0];
        var rx = SECRET_PATTERNS[pi][1];
        var sev = SECRET_PATTERNS[pi][2];
        var m = rx.exec(line);
        if (!m) continue;
        var val = m[0];
        if (KNOWN_EXAMPLE_VALUES.indexOf(val) !== -1 || val.toUpperCase().slice(-7) === 'EXAMPLE') {
          continue; // documentation example value
        }
        if (label === 'google API key' && PUBLIC_GOOGLE_CTX.test(ctx)) {
          findings.push({ check: 'secrets', sev: 'LOW', file: path, line: i + 1,
            title: 'Google API key (public context, e.g. embed player)', ev: mask(val), raw: val });
          lineHits.push(val);
          continue;
        }
        findings.push({ check: 'secrets', sev: sev, file: path, line: i + 1,
          title: label, ev: mask(val), raw: val });
        lineHits.push(val);
      }
      var gm = GENERIC_SECRET.exec(line);
      if (gm && !lineHits.some(function (h) { return h === gm[2] || h.indexOf(gm[2]) !== -1; }) &&
          !PLACEHOLDER.test(gm[2]) && !lowEntropy(gm[2]) &&
          KNOWN_EXAMPLE_VALUES.indexOf(gm[2]) === -1) {
        if (PUBLIC_SDK_CTX.test(ctx)) {
          findings.push({ check: 'secrets', sev: 'LOW', file: path, line: i + 1,
            title: 'credential-like assignment (' + gm[1] + '; client SDK key, public by design?)',
            ev: mask(gm[2]), raw: gm[2] });
        } else {
          findings.push({ check: 'secrets', sev: 'HIGH', file: path, line: i + 1,
            title: 'credential-like assignment (' + gm[1] + ')', ev: mask(gm[2]), raw: gm[2] });
        }
      }
      var jwtRe = new RegExp(JWT_SRC, 'g');
      var jm;
      while ((jm = jwtRe.exec(line)) !== null) {
        var role = '';
        try {
          var payload = jm[1].split('.')[1];
          payload += '='.repeat((4 - payload.length % 4) % 4);
          role = decodeB64Url(payload);
        } catch (e) { role = ''; }
        if (role.indexOf('service_role') !== -1) {
          findings.push({ check: 'secrets', sev: 'HIGH', file: path, line: i + 1,
            title: 'JWT contains service_role', ev: mask(jm[1]), raw: jm[1] });
        } else if (role.replace(/ /g, '').indexOf('"role":"anon"') !== -1 ||
                   role.indexOf('"role": "anon"') !== -1) {
          continue; // public anon key is normal
        } else {
          findings.push({ check: 'secrets', sev: 'LOW', file: path, line: i + 1,
            title: 'JWT literal (verify whether it is a public key)', ev: mask(jm[1]), raw: jm[1] });
        }
      }
    }
  }

  function scanDotenv(path, text, findings) {
    if (DOTENV_BAD.test(path) && !DOTENV_OK.test(path)) {
      findings.push({ check: 'dotenv', sev: 'HIGH', file: path, line: 0,
        title: '.env file committed to git', ev: path, raw: '' });
    }
  }

  function scanServiceRole(path, text, findings) {
    var lines = splitLines(text);
    var isDoc = path.toLowerCase().slice(-3) === '.md';
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (line.toLowerCase().indexOf('service_role') === -1) continue;
      if (IGNORE_MARK.test(line)) continue;
      if (/eyJ[A-Za-z0-9_-]{10,}/.test(line)) continue; // literal JWT -> secrets check owns it
      if (isDoc) continue; // docs discussing service_role are not exposure
      var sev, title;
      if (publicEnvSearch(line)) {
        sev = 'HIGH'; title = 'service_role in public-prefixed variable';
      } else if (ENV_REF.test(line)) {
        sev = 'LOW'; title = 'service_role via env (verify not bundled client-side)';
      } else if (CLIENT_DIRS.test(path)) {
        sev = 'HIGH'; title = 'service_role reference in client path';
      } else {
        continue; // plain mention in server code is not exposure
      }
      findings.push({ check: 'service_role', sev: sev, file: path, line: i + 1,
        title: title, ev: snip(line), raw: line });
    }
  }

  function scanClientLeaks(path, text, findings) {
    var lines = splitLines(text);
    for (var i = 0; i < lines.length; i++) {
      var line = lines[i];
      if (IGNORE_MARK.test(line)) continue;
      var it = line.matchAll(new RegExp(PUBLIC_ENV_SRC, 'g'));
      var step = it.next();
      while (!step.done) {
        var m = step.value;
        var name = m[2];
        if (PUBLIC_SENSITIVE.test(name) && !PUBLIC_EXEMPT.test(name)) {
          findings.push({ check: 'client_leaks', sev: 'HIGH', file: path, line: i + 1,
            title: 'public-prefixed var looks sensitive: ' + m[1] + name, ev: snip(line), raw: line });
        }
        step = it.next();
      }
    }
  }

  function treeChecks(files, findings) {
    var paths = files.map(function (f) { return f.path; });
    function has(p) { return paths.indexOf(p) !== -1; }
    if (!has('package.json')) {
      findings.push({ check: 'deps', sev: 'INFO', file: 'package.json', line: 0,
        title: 'no package.json (npm audit skipped)', ev: '', raw: '' });
      return;
    }
    var locks = ['package-lock.json', 'yarn.lock', 'pnpm-lock.yaml'].filter(has);
    if (!locks.length) {
      findings.push({ check: 'deps', sev: 'MEDIUM', file: 'package.json', line: 0,
        title: 'No lockfile - dependency tree not pinned; audit unavailable', ev: '', raw: '' });
      return;
    }
    // lockfile present: dependency audit (npm audit) is not feasible in the browser;
    // it stays a CLI / human-review step.
    findings.push({ check: 'deps', sev: 'INFO', file: 'package-lock', line: 0,
      title: 'npm audit not available in browser (covered in the human review)', ev: '', raw: '' });
  }

  /* ------------------------------- driver -------------------------------- */

  function cmpStr(a, b) { return a < b ? -1 : a > b ? 1 : 0; }

  function scanFiles(files) {
    var findings = [];
    var scanned = 0;
    for (var fi = 0; fi < files.length; fi++) {
      var f = files[fi];
      if (typeof f.content !== 'string') continue;
      scanned++;
      scanSecrets(f.path, f.content, findings);
      scanDotenv(f.path, f.content, findings);
      scanServiceRole(f.path, f.content, findings);
      scanClientLeaks(f.path, f.content, findings);
    }
    treeChecks(files, findings);

    // sort (severity -> check -> file -> line), then dedup -- same as CLI main()
    findings.sort(function (a, b) {
      return (SEV_ORDER[a.sev] - SEV_ORDER[b.sev]) || cmpStr(a.check, b.check) ||
             cmpStr(a.file, b.file) || (a.line - b.line);
    });
    var seen = {};
    var deduped = [];
    for (var i = 0; i < findings.length; i++) {
      var key = findings[i].check + '\u0000' + findings[i].file + '\u0000' +
                findings[i].line + '\u0000' + findings[i].title;
      if (seen[key]) continue;
      seen[key] = 1;
      deduped.push(findings[i]);
    }
    var counts = { HIGH: 0, MEDIUM: 0, LOW: 0, INFO: 0 };
    for (var j = 0; j < deduped.length; j++) counts[deduped[j].sev]++;
    var verdict = counts.HIGH ? 'NEEDS ATTENTION' : (counts.MEDIUM ? 'REVIEW' : 'PASS');
    return { findings: deduped, counts: counts, verdict: verdict, scanned: scanned };
  }

  return {
    version: VERSION,
    checks: CHECKS,
    scanFiles: scanFiles,
    _internals: { splitLines: splitLines, mask: mask, snip: snip, lowEntropy: lowEntropy }
  };
}));
