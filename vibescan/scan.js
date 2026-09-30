/* scan.js - UI glue for the instant scan page (N2 free scan, segment 2).
 * Engine: scan-core.js (window.VibescanCore). All scanning is local to the
 * browser: mode A talks only to api.github.com / raw.githubusercontent.com,
 * mode B never touches the network. No data is sent to NeufAgents servers.
 */
(function () {
  'use strict';

  var $ = function (id) { return document.getElementById(id); };
  var MAX_FILES_A = 40;
  var MAX_BYTES_PER_FILE_A = 300 * 1024;
  var MAX_FILES_B = 400;
  var MAX_TOTAL_BYTES_B = 10 * 1024 * 1024;

  /* -------------------- file selection policy (spec 4) -------------------- */
  var EXCLUDE = /(^|\/)(node_modules|\.git|vendor|\.venv|venv|__pycache__|\.next\/cache)(\/|$)/;
  var LOCKFILE = /(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|composer\.lock|Cargo\.lock|Gemfile\.lock|poetry\.lock)$/i;
  var BINARY_EXT = /\.(png|jpe?g|gif|webp|ico|avif|bmp|tiff?|svgz?|pdf|zip|gz|tgz|bz2|xz|7z|rar|jar|whl|exe|dll|so|dylib|bin|dat|mp[34]|m4a|wav|ogg|flac|mov|avi|mkv|woff2?|ttf|otf|eot|wasm|class|pyc|pyd|o|a|obj|psd|ai|sketch|db|sqlite|map)$/i;
  var CRED = /(^|\/)(\.env($|\.[A-Za-z0-9_.-]+$)|[^\/]*\.(pem|key|p12|pfx)$|credentials[^\/]*$|[^\/]*(^|[._-])config[^\/]*$|\.netrc$|id_rsa[^\/]*$)/i;
  var SRC = /\.(js|mjs|cjs|jsx|ts|tsx|py|rb|go|php|cs|java|kt|swift|rs|html|htm|vue|svelte|astro|sh|bash|zsh|ps1|yml|yaml|toml|json|properties|ini|conf|cfg|md|txt|env)$/i;
  var BUILD_DIR = /(^|\/)(dist|build|public|out|static|assets)\//i;

  function tier(path) {
    if (CRED.test(path)) return 0;
    if (SRC.test(path)) return 1;
    if (BUILD_DIR.test(path)) return 2;
    return 3;
  }

  function candidateList(entries) {
    return entries.filter(function (e) {
      var p = e.path;
      if (!p || p.indexOf('\u0000') >= 0) return false;
      if (EXCLUDE.test(p) || LOCKFILE.test(p) || BINARY_EXT.test(p)) return false;
      return true;
    }).sort(function (a, b) {
      var t = tier(a.path) - tier(b.path);
      return t !== 0 ? t : a.path.localeCompare(b.path);
    });
  }

  /* ----------------------------- helpers ---------------------------------- */
  function setProgress(msg) {
    var el = $('progress');
    el.style.display = msg ? 'block' : 'none';
    el.textContent = msg || '';
  }
  function showError(msg) {
    var el = $('error');
    el.style.display = 'block';
    el.textContent = msg;
  }
  function clearError() { $('error').style.display = 'none'; }
  function esc(s) {
    return String(s).replace(/[&<>"]/g, function (c) {
      return ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' })[c];
    });
  }
  function maskRaw(s) {
    s = String(s || '');
    if (s.length > 8) return s.slice(0, 4) + '\u2026' + s.slice(-4);
    return '***';
  }
  function setBusy(b) {
    $('run-btn').disabled = b;
    $('folder-btn').disabled = b;
  }
  async function mapLimit(items, limit, fn) {
    var out = new Array(items.length);
    var next = 0;
    async function worker() {
      while (next < items.length) {
        var i = next++;
        try { out[i] = await fn(items[i], i); } catch (e) { out[i] = null; }
      }
    }
    var pool = [];
    for (var k = 0; k < Math.min(limit, items.length); k++) pool.push(worker());
    await Promise.all(pool);
    return out;
  }

  /* ------------------------- mode A: GitHub repo -------------------------- */
  function parseRepo(input) {
    var u = String(input || '').trim().replace(/\.git$/i, '');
    var m = u.match(/github\.com\/([^\/\s#?]+)\/([^\/\s#?]+)(?:\/tree\/([^\/\s#?]+))?/i);
    if (m) return { owner: m[1], repo: m[2], branch: m[3] || null };
    m = u.match(/^([A-Za-z0-9_.-]+)\/([A-Za-z0-9_.-]+)$/);
    if (m) return { owner: m[1], repo: m[2], branch: null };
    return null;
  }

  async function scanRemote(rawInput) {
    var p = parseRepo(rawInput);
    if (!p) {
      throw new Error('That does not look like a GitHub repo link. Try the full URL, e.g. https://github.com/you/your-app');
    }
    setProgress('Looking up the repo\u2026');
    var metaResp = await fetch('https://api.github.com/repos/' + p.owner + '/' + p.repo);
    if (metaResp.status === 404) {
      throw new Error('Repo not found. If it is private, use the free sample review instead - we request read-only access and never write.');
    }
    if (metaResp.status === 403 || metaResp.status === 429) {
      throw new Error('GitHub is rate-limiting this browser (60 requests/hour). Try again in a few minutes, or use the free sample review.');
    }
    if (!metaResp.ok) throw new Error('Could not reach GitHub (HTTP ' + metaResp.status + '). Try again in a moment.');
    var meta = await metaResp.json();
    var branch = p.branch || meta.default_branch || 'main';

    setProgress('Listing files\u2026');
    var treeResp = await fetch('https://api.github.com/repos/' + p.owner + '/' + p.repo + '/git/trees/' + encodeURIComponent(branch) + '?recursive=1');
    if (!treeResp.ok) throw new Error('Could not list the repo files (HTTP ' + treeResp.status + '). If the repo is huge, use the free sample review.');
    var tree = await treeResp.json();
    var blobs = (tree.tree || []).filter(function (t) { return t.type === 'blob'; })
      .map(function (t) { return { path: t.path, size: t.size || 0 }; });
    if (!blobs.length) throw new Error('The repo tree came back empty. Try the free sample review instead.');

    var picked = candidateList(blobs)
      .filter(function (b) { return b.size && b.size <= MAX_BYTES_PER_FILE_A; })
      .slice(0, MAX_FILES_A);

    setProgress('Fetching ' + picked.length + ' files\u2026');
    var base = 'https://raw.githubusercontent.com/' + p.owner + '/' + p.repo + '/' + encodeURIComponent(branch) + '/';
    var fetched = await mapLimit(picked, 4, async function (b, i) {
      setProgress('Fetching files\u2026 ' + (i + 1) + ' / ' + picked.length);
      var r = await fetch(base + b.path.split('/').map(encodeURIComponent).join('/'));
      if (!r.ok) return null;
      var text = await r.text();
      if (text.indexOf('\u0000') >= 0) return null;
      return { path: b.path, content: text };
    });
    var files = fetched.filter(Boolean);
    if (!files.length) throw new Error('Could not fetch any text files from that repo. Try the free sample review.');
    return files;
  }

  /* ------------------------ mode B: local folder -------------------------- */
  function scanLocal(fileList) {
    return new Promise(function (resolve, reject) {
      var entries = [];
      for (var i = 0; i < fileList.length; i++) {
        var f = fileList[i];
        var path = (f.webkitRelativePath || f.name || '').replace(/^[^\/]*\//, '');
        if (path) entries.push({ path: path, file: f, size: f.size || 0 });
      }
      var picked = candidateList(entries)
        .filter(function (e) { return e.size <= 2 * 1024 * 1024; })
        .slice(0, MAX_FILES_B);
      var files = [];
      var queue = [];
      var total = 0;
      for (var q = 0; q < picked.length; q++) {
        if (total + picked[q].size > MAX_TOTAL_BYTES_B) break;
        total += picked[q].size;
        queue.push(picked[q]);
      }
      (async function () {
        for (var j = 0; j < queue.length; j += 12) {
          var chunk = queue.slice(j, j + 12);
          var texts = await Promise.all(chunk.map(function (e) { return e.file.text().catch(function () { return null; }); }));
          for (var k = 0; k < chunk.length; k++) {
            var t = texts[k];
            if (t == null || t.indexOf('\u0000') >= 0) continue;
            files.push({ path: chunk[k].path, content: t });
          }
          setProgress('Reading files\u2026 ' + Math.min(j + 12, queue.length) + ' / ' + queue.length);
        }
        resolve(files);
      })().catch(reject);
    });
  }

  /* ------------------------------ render ---------------------------------- */
  var HINTS = {
    secrets: 'Rotate this key at the provider now, remove it from source, and read it from environment variables instead.',
    dotenv: 'Remove this file from the repo; keep real values in your hosting platform\u2019s environment settings.',
    client_leaks: 'Anything bundled client-side is public. Move this to a server-side variable or use a publishable key.',
    service_role: 'This key bypasses row-level security. Rotate it now and keep it strictly server-side.'
  };
  var CHECK_TITLES = {
    secrets: 'Hardcoded secret',
    dotenv: 'Committed .env file',
    client_leaks: 'Client-side secret name',
    service_role: 'service_role key exposure'
  };
  var SEVS = ['HIGH', 'MEDIUM', 'LOW', 'INFO'];

  function findingHTML(f) {
    var title = f.title || CHECK_TITLES[f.check] || f.check;
    return '<div class="finding">' +
      '<div><span class="sev ' + esc(f.sev) + '">' + esc(f.sev) + '</span><span class="f-title">' + esc(title) + '</span></div>' +
      '<div class="f-loc">' + esc(f.file) + (f.line ? ':' + esc(String(f.line)) : '') + '</div>' +
      '<div class="f-ev">' + esc(maskRaw(f.raw)) + '</div>' +
      '<div class="f-hint">' + esc(HINTS[f.check] || 'Review and remove.') + '</div>' +
      '</div>';
  }

  function summaryText(files, findings) {
    var lines = ['vibescan instant preview - ' + files.length + ' files scanned, ' + findings.length + ' finding(s).',
      'Note: static preview only. Absence of findings is not proof of security.', ''];
    findings.forEach(function (f) {
      lines.push('[' + f.sev + '] ' + (f.title || CHECK_TITLES[f.check] || f.check) + ' - ' + f.file + (f.line ? ':' + f.line : '') + ' (' + (f.ev || '') + ')');
    });
    return lines.join('\n');
  }

  function render(files, findings) {
    var box = $('results');
    var head;
    if (findings.length) {
      head = '<div class="summary">' + findings.length + ' high-confidence finding' + (findings.length > 1 ? 's' : '') +
        ' in ' + files.length + ' files scanned. Treat them as real until proven otherwise.</div>';
    } else {
      head = '<div class="summary">No high-confidence leaks in ' + files.length + ' files. Good - the part we cannot see from here matters more.</div>';
    }
    var groups = '';
    SEVS.forEach(function (sev) {
      var g = findings.filter(function (f) { return f.sev === sev; });
      if (!g.length) return;
      groups += '<h2>' + sev + ' (' + g.length + ')</h2>' + g.map(findingHTML).join('');
    });
    var dispos = findings.length ? (
      '<div class="steps"><strong>If any of these are real, do this in order:</strong><br>' +
      '1) Rotate the key at the provider, right now - assume it is compromised.<br>' +
      '2) Remove it from the code and read it from environment variables instead.<br>' +
      '3) It stays in git history even after you delete it - rotate, or purge history. ' +
      'We do this in the rescue engagements.</div>'
    ) : '';
    var ctas = '<p style="margin-top:18px">' +
      '<a class="cta" href="/vibescan/?from=scan#scan">Request the free sample review (human pass, 24-48h)</a>' +
      '<a class="cta alt" href="/vibescan/#pricing">See the full 10-class audit ($500)</a></p>' +
      '<p><button class="ghost" id="copy-btn">Copy summary (masked)</button></p>';
    box.innerHTML = head + groups + dispos + ctas +
      '<p class="muted">Static preview only - it does not read git history and does not check the six classes listed below.</p>';
    box.style.display = 'block';
    var cb = $('copy-btn');
    if (cb) cb.addEventListener('click', function () {
      var txt = summaryText(files, findings);
      var done = function () { cb.textContent = 'Copied.'; setTimeout(function () { cb.textContent = 'Copy summary (masked)'; }, 1600); };
      if (navigator.clipboard && navigator.clipboard.writeText) {
        navigator.clipboard.writeText(txt).then(done, function () { window.prompt('Copy:', txt); });
      } else { window.prompt('Copy:', txt); }
    });
    box.scrollIntoView({ behavior: 'smooth', block: 'start' });
  }

  /* ------------------------------- wiring --------------------------------- */
  async function run(filesPromise, label) {
    if (!window.VibescanCore || !window.VibescanCore.scanFiles) {
      showError('Scanner engine did not load. Refresh the page and try again.');
      return;
    }
    clearError();
    $('results').style.display = 'none';
    setBusy(true);
    try {
      var files = await filesPromise;
      setProgress('Scanning ' + files.length + ' files\u2026');
      var result = window.VibescanCore.scanFiles(files);
      var findings = (result && result.findings) || [];
      render(files, findings);
      setProgress('');
    } catch (e) {
      setProgress('');
      showError((e && e.message) || 'Something went wrong. Try again, or use the free sample review.');
    } finally {
      setBusy(false);
    }
  }

  $('run-btn').addEventListener('click', function () {
    var v = $('repo').value.trim();
    if (!v) { showError('Paste a repo link first, e.g. https://github.com/you/your-app'); return; }
    run(scanRemote(v), v);
  });
  $('repo').addEventListener('keydown', function (ev) {
    if (ev.key === 'Enter') { $('run-btn').click(); }
  });
  $('folder-btn').addEventListener('click', function () { $('folder-input').click(); });
  $('folder-input').addEventListener('change', function () {
    var fl = $('folder-input').files;
    if (!fl || !fl.length) return;
    run(scanLocal(fl), 'local folder');
  });
})();
