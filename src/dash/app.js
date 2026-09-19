'use strict';

// Dashboard client. No framework, no bundler: this file is read straight off
// disk by dash.js on every request, so what's here is exactly what runs.

(function () {
  var TOKEN = window.DASH_TOKEN;
  var BASE = '/_dash';

  function api(path, opts) {
    opts = opts || {};
    var headers = Object.assign({ 'X-Dash-Token': TOKEN }, opts.headers || {});
    if (opts.body && !headers['Content-Type']) headers['Content-Type'] = 'application/json';
    return fetch(BASE + path, Object.assign({}, opts, { headers: headers })).then(function (r) {
      return r.text().then(function (text) {
        var data = null;
        try { data = text ? JSON.parse(text) : null; } catch (e) { /* non-JSON body */ }
        return { ok: r.ok, status: r.status, data: data, text: text };
      });
    });
  }

  // ------------------------------------------------------------- tab router

  var TABS = ['overview', 'logs', 'rules', 'egress', 'residue'];

  function currentTab() {
    var h = (location.hash || '#overview').slice(1);
    return TABS.indexOf(h) === -1 ? 'overview' : h;
  }

  function showTab(name) {
    for (var i = 0; i < TABS.length; i++) {
      var t = TABS[i];
      var panel = document.getElementById('panel-' + t);
      if (panel) panel.hidden = t !== name;
      var link = document.querySelector('.tabs a[data-tab="' + t + '"]');
      if (link) link.classList.toggle('active', t === name);
    }
    if (name === 'logs') loadLogs();
    if (name === 'egress') renderEgressTab(lastSnapshot);
    if (name === 'residue') renderResidueTab(lastSnapshot);
  }

  window.addEventListener('hashchange', function () { showTab(currentTab()); });

  // -------------------------------------------------------------- overview

  var lastSnapshot = null;

  function fmtUptime(ms) {
    if (typeof ms !== 'number') return String(ms);
    var s = Math.floor(ms / 1000);
    var h = Math.floor(s / 3600);
    var m = Math.floor((s % 3600) / 60);
    var sec = s % 60;
    return (h ? h + 'h ' : '') + (h || m ? m + 'm ' : '') + sec + 's';
  }

  // The verdict is computed here, independently, from the raw snapshot --
  // never trusted as a field the server hands over pre-judged. Anything this
  // logic cannot confirm renders as NOT PROTECTED or DEGRADED, never
  // PROTECTED: an optimistic guess here is worse than no verdict at all.
  function computeVerdict(snap) {
    if (!snap || !snap.redaction) return { level: 'unknown', label: 'checking…' };
    var red = snap.redaction;
    var eg = snap.egress || {};
    var hasRules = (red.literals || 0) + (red.patterns || 0) > 0;

    if (!hasRules) return { level: 'exposed', label: 'NOT PROTECTED — no redaction rules loaded' };

    var egressConfigured = Array.isArray(eg.configured) ? eg.configured.length > 0 : false;
    var neverConfigured = !egressConfigured && eg.masking === undefined && eg.active === undefined;

    if (eg.fellBackDirect > 0) {
      return { level: 'exposed', label: 'NOT PROTECTED — at least one request went out unmasked (' + eg.fellBackDirect + ')' };
    }
    if (eg.masking === false) {
      return { level: 'exposed', label: 'NOT PROTECTED — egress is not masking your address' };
    }
    if (egressConfigured && eg.tunnelling === false && !eg.externallyMasked) {
      return { level: 'exposed', label: 'NOT PROTECTED — tunnel is idle and nothing else is masking you' };
    }
    if (egressConfigured && eg.masking !== true && !eg.externallyMasked) {
      // Configured but not yet confirmed one way or the other.
      return { level: 'degraded', label: 'DEGRADED — redaction active, egress masking unverified' };
    }
    if (neverConfigured) {
      // No egress at all: an intentional, known configuration -- redaction
      // is doing real work, but your address is not being hidden.
      return { level: 'degraded', label: 'DEGRADED — redaction active, no egress masking configured' };
    }
    return { level: 'protected', label: 'PROTECTED' };
  }

  function renderVerdict(snap) {
    var v = computeVerdict(snap);
    var el = document.getElementById('verdict');
    el.className = 'verdict verdict-' + v.level;
    el.textContent = v.label;
  }

  function renderOverview(snap) {
    lastSnapshot = snap;
    renderVerdict(snap);
    var p = snap.proxy || {};
    var r = snap.redaction || {};
    var eg = snap.egress || {};
    var res = snap.residue;

    set('pid', p.pid);
    set('port', p.port);
    set('uptime', fmtUptime(p.uptimeMs));
    set('literals', r.literals);
    set('patterns', r.patterns);
    set('aliases', r.aliases);
    set('rewrites', r.rewrites);
    set('timezone', r.timezone === undefined ? '—' : (r.timezone ? 'on' : 'off'));

    var state = eg.masking === true ? 'masked' : eg.masking === false ? 'NOT masked' : (eg.note || 'unverified');
    set('egress-state', state);
    set('egress-country', eg.apparentCountry || '—');
    set('egress-reason', eg.decisionReason || '—');
    set('egress-fails', (eg.failures || 0) + ' / ' + (eg.fellBackDirect || 0));

    if (res) {
      set('scrub-when', new Date(res.ts).toLocaleString());
      set('scrub-files', res.filesRewritten);
      set('scrub-verify', res.verifyFailures);
    } else {
      set('scrub-when', 'never run');
      set('scrub-files', '—');
      set('scrub-verify', '—');
    }
  }

  function set(field, value) {
    var el = document.querySelector('[data-f="' + field + '"]');
    if (el) el.textContent = value === undefined || value === null ? '—' : String(value);
  }

  function loadStatusOnce() {
    api('/api/status?t=' + encodeURIComponent(TOKEN)).then(function (r) {
      if (r.data) renderOverview(r.data);
    });
  }

  function startEvents() {
    try {
      var es = new EventSource(BASE + '/api/events?t=' + encodeURIComponent(TOKEN));
      es.onmessage = function (ev) {
        try {
          renderOverview(JSON.parse(ev.data));
        } catch (e) { /* ignore a malformed frame */ }
      };
      es.onerror = function () { /* EventSource retries on its own */ };
    } catch (e) {
      loadStatusOnce();
    }
  }

  // ------------------------------------------------------------------ logs

  function loadLogs() {
    var level = document.getElementById('log-level').value;
    var q = document.getElementById('log-search').value;
    var limit = document.getElementById('log-limit').value;
    var qs = '?limit=' + encodeURIComponent(limit) + '&level=' + encodeURIComponent(level) +
      (q ? '&q=' + encodeURIComponent(q) : '');
    api('/api/logs' + qs).then(function (r) {
      if (!r.data) return;
      renderLogs(r.data);
    });
  }

  function renderLogs(data) {
    var container = document.getElementById('log-lines');
    container.innerHTML = '';
    var frag = document.createDocumentFragment();
    (data.lines || []).forEach(function (l) {
      var row = document.createElement('div');
      row.className = 'log-line level-' + (l.level || 'info');
      var ts = document.createElement('span');
      ts.className = 'log-ts';
      ts.textContent = l.ts || '--:--:--';
      var text = document.createElement('span');
      text.className = 'log-text';
      text.textContent = l.text;
      row.appendChild(ts);
      row.appendChild(text);
      frag.appendChild(row);
    });
    container.appendChild(frag);
    document.getElementById('log-total').textContent = (data.total || 0) + ' matching line(s)';
  }

  var followTimer = null;
  function setupLogsTab() {
    document.getElementById('log-level').addEventListener('change', loadLogs);
    document.getElementById('log-limit').addEventListener('change', loadLogs);
    document.getElementById('log-search').addEventListener('input', debounce(loadLogs, 250));
    document.getElementById('log-refresh').addEventListener('click', loadLogs);
    document.getElementById('log-follow').addEventListener('change', function (e) {
      if (e.target.checked) startFollow(); else stopFollow();
    });
    startFollow();
  }
  function startFollow() {
    stopFollow();
    followTimer = setInterval(function () {
      if (currentTab() === 'logs' && document.getElementById('log-follow').checked) loadLogs();
    }, 4000);
  }
  function stopFollow() {
    if (followTimer) clearInterval(followTimer);
    followTimer = null;
  }
  function debounce(fn, ms) {
    var t = null;
    return function () {
      clearTimeout(t);
      var args = arguments;
      t = setTimeout(function () { fn.apply(null, args); }, ms);
    };
  }

  // ------------------------------------------------------------- PII rules

  var rulesRaw = null;

  function setupRulesTab() {
    document.getElementById('rules-load').addEventListener('click', function () {
      api('/api/config/raw').then(function (r) {
        if (!r.ok) {
          showRulesErrors(['could not load config: ' + r.status]);
          return;
        }
        rulesRaw = r.data;
        renderRulesEditor(rulesRaw);
        document.getElementById('rules-save').disabled = false;
        document.getElementById('rules-status').textContent = 'loaded';
      });
    });
    document.getElementById('rules-save').addEventListener('click', saveRules);
  }

  function showRulesErrors(errors) {
    var box = document.getElementById('rules-errors');
    if (!errors || !errors.length) {
      box.hidden = true;
      box.textContent = '';
      return;
    }
    box.hidden = false;
    box.textContent = errors.join('\n');
  }

  function el(tag, attrs, children) {
    var e = document.createElement(tag);
    for (var k in attrs || {}) {
      if (k === 'text') e.textContent = attrs[k];
      else e.setAttribute(k, attrs[k]);
    }
    (children || []).forEach(function (c) { e.appendChild(c); });
    return e;
  }

  function revealableInput(value, className) {
    var wrap = document.createElement('span');
    wrap.className = 'rules-row';
    var input = el('input', { type: 'password', value: value == null ? '' : value, class: className || '' });
    var btn = el('button', { type: 'button', class: 'reveal', text: 'show' });
    btn.addEventListener('click', function () {
      var hidden = input.type === 'password';
      input.type = hidden ? 'text' : 'password';
      btn.textContent = hidden ? 'hide' : 'show';
    });
    wrap.appendChild(input);
    wrap.appendChild(btn);
    return { wrap: wrap, input: input };
  }

  function renderRulesEditor(rules) {
    var root = document.getElementById('rules-editor');
    root.innerHTML = '';

    // literals
    var literalsGroup = el('div', { class: 'rules-group' }, [el('h3', { text: 'Literals' })]);
    var literalRows = [];
    (rules.literals || []).forEach(function (lit) {
      addLiteralRow(literalsGroup, literalRows, lit);
    });
    var addLitBtn = el('button', { type: 'button', text: '+ literal' });
    addLitBtn.addEventListener('click', function () { addLiteralRow(literalsGroup, literalRows, ''); });
    literalsGroup.appendChild(addLitBtn);
    root.appendChild(literalsGroup);

    // patterns
    var patternsGroup = el('div', { class: 'rules-group' }, [el('h3', { text: 'Patterns' })]);
    var patternRows = [];
    (rules.patterns || []).forEach(function (p) { addPatternRow(patternsGroup, patternRows, p); });
    var addPatBtn = el('button', { type: 'button', text: '+ pattern' });
    addPatBtn.addEventListener('click', function () { addPatternRow(patternsGroup, patternRows, { name: '', regex: '', flags: 'g' }); });
    patternsGroup.appendChild(addPatBtn);
    root.appendChild(patternsGroup);

    // aliases
    var aliasesGroup = el('div', { class: 'rules-group' }, [el('h3', { text: 'Aliases' })]);
    var aliasRows = [];
    (rules.aliases || []).forEach(function (a) { addAliasRow(aliasesGroup, aliasRows, a); });
    var addAliasBtn = el('button', { type: 'button', text: '+ alias' });
    addAliasBtn.addEventListener('click', function () { addAliasRow(aliasesGroup, aliasRows, { real: '', alias: '' }); });
    aliasesGroup.appendChild(addAliasBtn);
    root.appendChild(aliasesGroup);

    // normalize
    var norm = rules.normalize || {};
    var normGroup = el('div', { class: 'rules-group' }, [el('h3', { text: 'Normalize' })]);
    var tzRow = el('label', { class: 'rules-row' });
    var tzCheck = el('input', { type: 'checkbox' });
    tzCheck.checked = Boolean(norm.timezone);
    tzRow.appendChild(tzCheck);
    tzRow.appendChild(document.createTextNode(' normalize timezone'));
    normGroup.appendChild(tzRow);
    var rewriteRows = [];
    (norm.rewrites || []).forEach(function (rw) { addRewriteRow(normGroup, rewriteRows, rw); });
    var addRwBtn = el('button', { type: 'button', text: '+ rewrite' });
    addRwBtn.addEventListener('click', function () { addRewriteRow(normGroup, rewriteRows, { name: '', regex: '', flags: 'g', replace: '' }); });
    normGroup.appendChild(addRwBtn);
    root.appendChild(normGroup);

    root._collect = function () {
      var literals = literalRows.filter(function (r) { return !r.removed; }).map(function (r) { return r.input.value; });
      var patterns = patternRows.filter(function (r) { return !r.removed; }).map(function (r) {
        return { name: r.name.value, regex: r.regex.value, flags: r.flags.value || 'g' };
      });
      var aliases = aliasRows.filter(function (r) { return !r.removed; }).map(function (r) {
        return { real: r.real.input.value, alias: r.alias.value };
      });
      var rewrites = rewriteRows.filter(function (r) { return !r.removed; }).map(function (r) {
        return { name: r.name.value, regex: r.regex.value, flags: r.flags.value || 'g', replace: r.replace.value };
      });
      return {
        literals: literals,
        patterns: patterns,
        aliases: aliases,
        normalize: { timezone: tzCheck.checked, rewrites: rewrites },
      };
    };
  }

  function addLiteralRow(group, rows, value) {
    var r = revealableInput(typeof value === 'string' ? value : (value && value.value) || '');
    var removeBtn = el('button', { type: 'button', class: 'remove', text: '✕' });
    var rowState = { input: r.input, removed: false };
    removeBtn.addEventListener('click', function () { rowState.removed = true; r.wrap.remove(); });
    r.wrap.appendChild(removeBtn);
    group.insertBefore(r.wrap, group.lastChild);
    rows.push(rowState);
  }

  function addPatternRow(group, rows, p) {
    var wrap = el('div', { class: 'rules-row' });
    var name = el('input', { type: 'text', value: p.name || '', placeholder: 'name' });
    var regex = el('input', { type: 'text', value: p.regex || '', placeholder: 'regex' });
    var flags = el('input', { type: 'text', value: p.flags || 'g', placeholder: 'flags', style: 'max-width:60px' });
    var removeBtn = el('button', { type: 'button', class: 'remove', text: '✕' });
    var rowState = { name: name, regex: regex, flags: flags, removed: false };
    removeBtn.addEventListener('click', function () { rowState.removed = true; wrap.remove(); });
    [name, regex, flags, removeBtn].forEach(function (c) { wrap.appendChild(c); });
    group.insertBefore(wrap, group.lastChild);
    rows.push(rowState);
  }

  function addAliasRow(group, rows, a) {
    var wrap = el('div', { class: 'rules-row' });
    var realR = revealableInput(a.real || '');
    var alias = el('input', { type: 'text', value: a.alias || '', placeholder: 'alias' });
    var removeBtn = el('button', { type: 'button', class: 'remove', text: '✕' });
    var rowState = { real: realR, alias: alias, removed: false };
    removeBtn.addEventListener('click', function () { rowState.removed = true; wrap.remove(); });
    wrap.appendChild(realR.wrap);
    wrap.appendChild(alias);
    wrap.appendChild(removeBtn);
    group.insertBefore(wrap, group.lastChild);
    rows.push(rowState);
  }

  function addRewriteRow(group, rows, rw) {
    var wrap = el('div', { class: 'rules-row' });
    var name = el('input', { type: 'text', value: rw.name || '', placeholder: 'name' });
    var regex = el('input', { type: 'text', value: rw.regex || '', placeholder: 'regex' });
    var flags = el('input', { type: 'text', value: rw.flags || 'g', placeholder: 'flags', style: 'max-width:60px' });
    var replace = el('input', { type: 'text', value: rw.replace || '', placeholder: 'replace' });
    var removeBtn = el('button', { type: 'button', class: 'remove', text: '✕' });
    var rowState = { name: name, regex: regex, flags: flags, replace: replace, removed: false };
    removeBtn.addEventListener('click', function () { rowState.removed = true; wrap.remove(); });
    [name, regex, flags, replace, removeBtn].forEach(function (c) { wrap.appendChild(c); });
    group.insertBefore(wrap, group.lastChild);
    rows.push(rowState);
  }

  function saveRules() {
    if (!rulesRaw) return;
    var root = document.getElementById('rules-editor');
    var edited = root._collect();

    // Cheap client-side pre-checks only (regex syntax, obvious conflicts).
    // The authoritative checks -- catastrophic-backtracking probes and alias
    // risk scoring -- can only run server-side, so the real gate is always
    // the POST below; this just avoids a round trip for typos.
    var preErrors = [];
    edited.patterns.forEach(function (p) {
      try { new RegExp(p.regex, p.flags); } catch (e) { preErrors.push('pattern "' + p.name + '": ' + e.message); }
    });
    edited.aliases.forEach(function (a) {
      if (a.real === a.alias) preErrors.push('alias "' + a.alias + '": real and alias must differ');
    });
    if (preErrors.length) {
      showRulesErrors(preErrors);
      return;
    }

    var merged = Object.assign({}, rulesRaw, edited);
    api('/api/config', { method: 'POST', body: JSON.stringify(merged) }).then(function (r) {
      if (!r.ok) {
        showRulesErrors((r.data && r.data.errors) || ['save failed (' + r.status + ')']);
        return;
      }
      showRulesErrors([]);
      rulesRaw = merged;
      var warnings = (r.data && r.data.warnings) || [];
      document.getElementById('rules-status').textContent =
        'saved. backup: ' + (r.data && r.data.backup) + (warnings.length ? ' | warnings: ' + warnings.join('; ') : '');
    });
  }

  // -------------------------------------------------------------- egress

  function setupEgressTab() {
    document.getElementById('egress-on').addEventListener('click', function () { egressAction('on'); });
    document.getElementById('egress-off').addEventListener('click', function () { egressAction('off'); });
    document.getElementById('egress-check').addEventListener('click', function () { egressAction('check'); });
  }

  function egressAction(action) {
    api('/api/egress/' + action, { method: 'POST' }).then(function (r) {
      document.getElementById('egress-result').textContent = JSON.stringify(r.data, null, 2);
      loadStatusOnce();
    });
  }

  function renderEgressTab(snap) {
    var box = document.getElementById('egress-cards');
    box.innerHTML = '';
    var eg = (snap && snap.egress) || {};
    var card = el('div', { class: 'card' }, [el('h3', { text: 'Current egress state' })]);
    var dl = el('dl');
    [
      ['Configured providers', (eg.configured || []).length],
      ['Active', eg.active || '—'],
      ['Masking', eg.masking === true ? 'yes' : eg.masking === false ? 'no' : 'unverified'],
      ['Decision reason', eg.decisionReason || '—'],
      ['Exit country', eg.apparentCountry || '—'],
      ['Failures', eg.failures || 0],
      ['Fell back direct', eg.fellBackDirect || 0],
    ].forEach(function (pair) {
      dl.appendChild(el('div', {}, [el('dt', { text: pair[0] }), el('dd', { text: String(pair[1]) })]));
    });
    card.appendChild(dl);
    box.appendChild(card);
  }

  // -------------------------------------------------------------- residue

  function setupResidueTab() {
    document.getElementById('residue-scan').addEventListener('click', function () {
      var btn = document.getElementById('residue-scan');
      btn.disabled = true;
      api('/api/residue/scan', { method: 'POST' }).then(function (r) {
        btn.disabled = false;
        document.getElementById('residue-result').textContent = JSON.stringify(r.data, null, 2);
        loadJobs();
      });
    });
    document.getElementById('residue-refresh').addEventListener('click', loadJobs);
    document.getElementById('retention-run').addEventListener('click', function () {
      var btn = document.getElementById('retention-run');
      var out = document.getElementById('retention-result');
      btn.disabled = true;
      api('/api/retention/run', { method: 'POST' }).then(function (r) {
        btn.disabled = false;
        out.hidden = false;
        var acts = r.data && r.data.actions;
        out.textContent = acts && acts.length
          ? JSON.stringify(acts, null, 2)
          : 'Nothing needed removing: everything is already within policy.';
        loadRetention();
        loadRetentionHistory();
        loadSignals();
      });
    });
    loadJobs();
    loadRetention();
    loadRetentionHistory();
  }

  // ------------------------------------------------- residue job history

  function loadJobs() {
    api('/api/residue/jobs?limit=50').then(function (r) {
      renderResidueSummary(r.data && r.data.summary);
      var box = document.getElementById('residue-jobs');
      box.innerHTML = '';
      var jobs = (r.data && r.data.jobs) || [];
      if (!jobs.length) {
        box.appendChild(el('p', { class: 'hint', text:
          'No passes recorded yet. The scrub runs hourly when "residue": { "scrub": true } is set, and once at the end of each Claude Code session.' }));
        return;
      }
      var tbl = el('table', { class: 'jobs' });
      var head = el('tr', {}, ['When', 'Trigger', 'Result', 'Scanned', 'Rewritten', 'Verify fails', 'Took', ''].map(function (h) {
        return el('th', { text: h });
      }));
      tbl.appendChild(head);
      jobs.forEach(function (j) {
        // A failed pass is the one thing in this table that must not be
        // possible to skim past: it means real values are still on disk.
        var bad = j.ok === false || (j.verifyFailures || 0) > 0;
        var row = el('tr', { class: bad ? 'job-bad' : '' });
        row.appendChild(el('td', { text: new Date(j.ts).toLocaleString() }));
        row.appendChild(el('td', { text: j.trigger || '?' }));
        row.appendChild(el('td', { text: bad ? 'FAILED' : 'ok' }));
        row.appendChild(el('td', { text: j.filesScanned == null ? '–' : String(j.filesScanned) }));
        row.appendChild(el('td', { text: String(j.filesRewritten == null ? '–' : j.filesRewritten) }));
        row.appendChild(el('td', { text: String(j.verifyFailures == null ? '–' : j.verifyFailures) }));
        row.appendChild(el('td', { text: j.durationMs == null ? '–' : (j.durationMs / 1000).toFixed(1) + 's' }));
        var cell = el('td');
        if (j.hasLog) {
          var btn = el('button', { type: 'button', text: 'view log' });
          btn.addEventListener('click', function () { showJobLog(j.id); });
          cell.appendChild(btn);
        } else {
          cell.appendChild(el('span', { class: 'hint', text: 'no log' }));
        }
        // "327 rewritten" is not auditable on its own; this answers WHICH.
        if (j.filesRewritten > 0) {
          var mbtn = el('button', { type: 'button', text: 'which files' });
          mbtn.addEventListener('click', function () { showManifest(j.id); });
          cell.appendChild(mbtn);
        }
        row.appendChild(cell);
        tbl.appendChild(row);
      });
      box.appendChild(tbl);
    });
  }

  function showManifest(id) {
    var pre = document.getElementById('residue-joblog');
    pre.hidden = false;
    pre.textContent = 'loading...';
    api('/api/residue/manifest?id=' + encodeURIComponent(id)).then(function (r) {
      var d = r.data;
      if (!d || d.error) {
        pre.textContent = (d && d.error) || 'no manifest';
        return;
      }
      var out = [];
      out.push('FILES REWRITTEN BY THIS PASS');
      out.push('run ' + d.ts + '   applied=' + d.applied);
      out.push('examined ' + d.filesExamined + ', changed ' + d.filesChanged);
      // Stated plainly: with no backup, this manifest IS the audit trail.
      out.push('backups kept: ' + (d.backupsKept ? d.backupRoot : 'NO — the originals are gone, so this list is the only record'));
      out.push('');
      var t = d.totalsByCategory || {};
      var keys = Object.keys(t).sort(function (a, b) { return t[b] - t[a]; });
      if (keys.length) {
        out.push('values removed, by category:');
        keys.forEach(function (k) { out.push('  ' + String(t[k]).padStart(6) + '  ' + k); });
        out.push('');
      }
      out.push('files (most affected first):');
      (d.files || []).forEach(function (f) {
        var cats = f.categories
          ? Object.keys(f.categories).map(function (k) { return k + '=' + f.categories[k]; }).join(' ')
          : '';
        out.push('  ' + String(f.linesChanged).padStart(5) + ' line(s)  ' + f.file + (cats ? '   [' + cats + ']' : ''));
      });
      pre.textContent = out.join('\n');
    });
  }

  function showJobLog(id) {
    var pre = document.getElementById('residue-joblog');
    pre.hidden = false;
    pre.textContent = 'loading...';
    api('/api/residue/job?id=' + encodeURIComponent(id)).then(function (r) {
      pre.textContent = (r.data && r.data.log) || (r.data && r.data.error) || 'no log';
    });
  }

  // ------------------------------------------------------------ retention

  function loadRetention() {
    api('/api/retention').then(function (r) {
      var box = document.getElementById('retention-table');
      box.innerHTML = '';
      var d = r.data;
      if (!d) return;
      if (d.enabled === false) {
        box.appendChild(el('p', { class: 'warn', text:
          'Retention is DISABLED. These files will grow without limit, and each one records what was on this machine and when.' }));
      }
      var tbl = el('table', { class: 'jobs' });
      tbl.appendChild(el('tr', {}, ['What', 'File', 'Size', 'Records', 'Policy'].map(function (h) {
        return el('th', { text: h });
      })));
      (d.items || []).forEach(function (i) {
        var row = el('tr');
        row.appendChild(el('td', { text: i.label }));
        row.appendChild(el('td', { text: i.file }));
        row.appendChild(el('td', { text: i.bytes == null ? '–' : fmtBytes(i.bytes) }));
        row.appendChild(el('td', { text: i.records == null ? '–' : String(i.records) }));
        row.appendChild(el('td', { text: i.rule }));
        tbl.appendChild(row);
      });
      box.appendChild(tbl);
      if (d.backups) {
        box.appendChild(el('p', { class: 'hint', text: 'Backups: ' + d.backups.rule + ' — ' + d.backups.warning }));
      }
    });
  }

  // ------------------------------------------------------------- signals

  // Rendered on Overview because a finding nobody scrolls to is a finding
  // nobody has. Each one states what happened, why it matters, and what to
  // do -- a signal without an action is an anxiety generator.
  function loadSignals() {
    api('/api/insights').then(function (r) {
      var box = document.getElementById('signals');
      if (!box) return;
      box.innerHTML = '';
      var sig = (r.data && r.data.signals) || [];
      if (!sig.length) {
        box.appendChild(el('p', { class: 'hint', text: 'No signals: the scrub is running, retention is current, and nothing anomalous has been recorded.' }));
        return;
      }
      sig.forEach(function (s) {
        var card = el('div', { class: 'signal signal-' + s.severity });
        card.appendChild(el('div', { class: 'signal-title', text: s.title }));
        card.appendChild(el('div', { class: 'signal-detail', text: s.detail }));
        if (s.action) card.appendChild(el('div', { class: 'signal-action', text: s.action }));
        box.appendChild(card);
      });
    });
  }

  function loadRetentionHistory() {
    api('/api/retention/history?limit=30').then(function (r) {
      var box = document.getElementById('retention-history');
      if (!box) return;
      box.innerHTML = '';
      var runs = (r.data && r.data.runs) || [];
      if (!runs.length) {
        box.appendChild(el('p', { class: 'hint', text: 'No passes recorded yet. Housekeeping runs a minute after the proxy starts, then hourly.' }));
        return;
      }
      var tbl = el('table', { class: 'jobs' });
      tbl.appendChild(el('tr', {}, ['When', 'Trigger', 'Actions', 'Records removed', 'Files removed', 'Freed'].map(function (h) {
        return el('th', { text: h });
      })));
      runs.forEach(function (x) {
        var row = el('tr');
        row.appendChild(el('td', { text: new Date(x.ts).toLocaleString() }));
        row.appendChild(el('td', { text: x.trigger || 'scheduled' }));
        row.appendChild(el('td', { text: x.actionCount ? String(x.actionCount) : 'nothing to do' }));
        row.appendChild(el('td', { text: String(x.removedRecords || 0) }));
        row.appendChild(el('td', { text: String(x.removedFiles || 0) }));
        row.appendChild(el('td', { text: fmtBytes(x.freedBytes || 0) }));
        tbl.appendChild(row);
      });
      box.appendChild(tbl);
    });
  }

  function fmtBytes(n) {
    if (n < 1024) return n + ' B';
    if (n < 1024 * 1024) return (n / 1024).toFixed(1) + ' KB';
    return (n / 1024 / 1024).toFixed(1) + ' MB';
  }

  // Driven by the DURABLE job summary, not the proxy's in-memory lastScrub.
  // Those disagreed: lastScrub is lost whenever the proxy restarts -- which
  // happens at logon, on a crash, and every time the watchdog revives it --
  // so this card read "never run" directly above a history table listing
  // completed runs. Of the two, the one that survives a restart is the one
  // telling the truth.
  function renderResidueSummary(sum) {
    var box = document.getElementById('residue-cards');
    box.innerHTML = '';
    var card = el('div', { class: 'card' }, [el('h3', { text: 'Transcript scrub job' })]);
    var dl = el('dl');
    var rows;
    if (!sum || sum.neverRun) {
      rows = [['Status', 'never run']];
    } else {
      rows = [
        ['Last run', new Date(sum.lastRun).toLocaleString()],
        ['Last result', sum.lastFailed ? 'FAILED' : 'ok'],
        ['Runs recorded', sum.runs],
        ['Failures', sum.failures],
        ['Files rewritten (total)', sum.filesRewritten],
      ];
      // A job whose most recent pass failed is the case that matters: it
      // looks configured and healthy from every other angle while leaving
      // real values on disk.
      if (sum.lastFailed && sum.lastOk) rows.push(['Last success', new Date(sum.lastOk).toLocaleString()]);
    }
    rows.forEach(function (pair) {
      dl.appendChild(el('div', {}, [el('dt', { text: pair[0] }), el('dd', { text: String(pair[1]) })]));
    });
    card.appendChild(dl);
    box.appendChild(card);
  }

  function renderResidueTab() {
    // The card is filled by loadJobs() from the durable summary; this keeps
    // the tab-switch path from blanking it.
    loadJobs();
  }

  // ------------------------------------------------------------------ init

  document.addEventListener('DOMContentLoaded', function () {
    showTab(currentTab());
    loadStatusOnce();
    startEvents();
    setupLogsTab();
    setupRulesTab();
    setupEgressTab();
    setupResidueTab();
    loadSignals();
    // Signals are derived from files on disk, not from the SSE snapshot, so
    // they need their own refresh. Five minutes: often enough that a failed
    // overnight scrub is visible by morning, rare enough that an open tab is
    // not re-reading job history continuously.
    var t = setInterval(loadSignals, 5 * 60 * 1000);
    window.addEventListener('beforeunload', function () { clearInterval(t); });
  });
})();
