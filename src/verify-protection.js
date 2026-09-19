#!/usr/bin/env node
'use strict';

// Proves, against YOUR live config and the running proxy, that:
//   1. every literal and pattern you configured is actually redacted,
//      including in the adjacency shapes that caused a real bypass
//   2. your IP and location are masked right now
//   3. nothing has gone out unmasked this session
//
// Prints verdicts and COUNTS only -- never a literal, never an address. Safe
// to run and safe to paste. It reads your rules file directly, which is why it
// lives here and is run by you rather than by an assistant.
//
//   node src/verify-protection.js

const http = require('http');
const path = require('path');
const { load, compile } = require('./rules');
const { compileAliases } = require('./aliases');
const { compileNormalizers } = require('./normalize');
const { renderForModel } = require('./pipeline');
const { readStatus } = require('./status');

let failures = 0;
let checks = 0;
const ok = (msg) => { checks++; console.log('  ok    ' + msg); };
const bad = (msg) => { checks++; failures++; console.log('  FAIL  ' + msg); };

// ---------------------------------------------------------------- 1. rules

const rules = load();
const warnings = [];
const RULES = compile(rules, (m) => warnings.push(m));
const ALIASES = compileAliases(rules.aliases, (m) => warnings.push(m));
const NORM = compileNormalizers(rules.normalize, (m) => warnings.push(m));
const K = require('crypto').randomBytes(32); // verification only; not the real key
const PIPE = { rules: RULES, kLabel: K, aliases: ALIASES, normalizers: NORM };

console.log('1. YOUR REDACTION RULES');
console.log(`   literals ${RULES.literalCount}, pattern-regexes ${RULES.regexes.length - RULES.literalCount}, aliases ${ALIASES.length}, rewrites ${NORM.rewrites.length}, timezone ${NORM.timezone ? 'on' : 'OFF'}`);
if (warnings.length) {
  for (const w of warnings) bad('config warning: ' + w);
} else {
  ok('config compiles with no warnings');
}
if (RULES.literalCount === 0) bad('no literals configured, so your specific details are not listed');

// Every shape that could defeat a boundary check. Shape 6 (value twice, no
// separator) is the one that DID defeat it: both copies failed their guards
// and the value passed through untouched.
const SHAPES = [
  (v) => v,
  (v) => `prefix ${v}`,
  (v) => `${v} suffix`,
  (v) => `(${v})`,
  (v) => `"${v}"`,
  (v) => `${v},${v}`,
  (v) => `${v}${v}`,
  (v) => `${v}${v}${v}`,
  (v) => `<<${v}>>`,
  (v) => `\n${v}\n`,
  (v) => `\t${v};`,
  (v) => `[${v}]`,
  (v) => `${v}.`,
  (v) => `-${v}-`,
  (v) => `x${v}x`,
  // Built with fromCharCode, not an escape: an escape is flattened to a real
  // 0x00 byte on the way to disk, which makes this file read as binary.
  (v) => v + String.fromCharCode(0) + "tail",
  (v) => `${'z'.repeat(300)}${v}${'z'.repeat(300)}`,
  (v) => `{"k":"${v}"}`,
  (v) => `--${v}--`,
  (v) => `${v}/${v}`,
];

function literalValues() {
  const out = [];
  for (const e of rules.literals || []) {
    const v = typeof e === 'string' ? e : e && e.value;
    if (typeof v === 'string' && v.length > 0) out.push(v);
  }
  return out;
}

console.log('');
console.log('2. EVERY LITERAL, IN EVERY ADJACENCY SHAPE');
{
  // Shapes that wrap the value in word characters on BOTH sides. For a
  // single-token literal these are expected NOT to match: that is exactly the
  // boundary guard doing its job, and it is the only thing stopping a short
  // name matching inside an unrelated longer word. Reported separately rather
  // than counted as a leak, because calling a deliberate trade-off a failure
  // teaches you to ignore the output.
  const WORD_WRAPPED = new Set([14, 16]);
  const isSingleToken = (v) => /^[\p{L}\p{N}_]+$/u.test(v);

  const values = literalValues();
  let tested = 0;
  let leaked = 0;
  let embedded = 0;
  const leakedShapes = new Set();

  for (const v of values) {
    for (let si = 0; si < SHAPES.length; si++) {
      const out = renderForModel(SHAPES[si](v), PIPE).text;
      tested++;
      if (!out.includes(v)) continue;
      if (WORD_WRAPPED.has(si) && isSingleToken(v)) embedded++;
      else {
        leaked++;
        leakedShapes.add(si);
      }
    }
  }

  if (leaked === 0) ok(`${tested} checks across ${values.length} literal(s) x ${SHAPES.length} shapes: none leaked`);
  else bad(`${leaked} of ${tested} checks LEAKED (shape indexes ${[...leakedShapes].join(', ')})`);

  if (embedded > 0) {
    console.log(`   note  ${embedded} case(s): a single-token literal wrapped in word characters on both`);
    console.log('         sides (as in "xxNAMExx") is deliberately NOT redacted -- that guard is what');
    console.log('         stops a short name matching inside an unrelated word. To redact one of');
    console.log('         these everywhere regardless, list it as { "value": "...", "boundary": false }.');
  }
}

console.log('');
console.log('3. PATTERN CATEGORIES');
{
  // Synthetic values per category, so this works without knowing yours.
  const probes = {
    email: 'probe.person@example-domain.test',
    phone: '+1 415 555 0134',
    ip: '203.0.113.47',
    ipv6: '2001:0db8:85a3:0000:0000:8a2e:0370:7334',
    mac: '3c:22:fb:9a:1d:4e',
    'git-org': 'https://github.com/some-org-name/some-repo-name',
    'git-repo': 'https://github.com/some-org-name/some-repo-name',
  };
  const names = (rules.patterns || []).map((p) => p && p.name).filter(Boolean);
  for (const name of names) {
    const probe = probes[name];
    if (!probe) {
      console.log(`  note  pattern "${name}" has no built-in probe; not checked here`);
      continue;
    }
    const out = renderForModel(probe, PIPE);
    const fired = Object.keys(out.counts || {}).length > 0 && out.text !== probe;
    if (fired) ok(`pattern "${name}" fires on a representative value`);
    else bad(`pattern "${name}" did NOT fire on a representative value`);
  }
  for (const needed of ['email', 'ip']) {
    if (!names.includes(needed)) bad(`no "${needed}" pattern configured`);
  }
}

console.log('');
console.log('4. LOCATION FINGERPRINTS IN CONTENT');
{
  // Section 1 reports that normalization is configured. Configured is not the
  // same as firing, and these are the signals that pin a region as precisely
  // as an IP does.
  // Probe values are ASSEMBLED AT RUNTIME from fragments. Writing them
  // literally does not work: this file was authored through the proxy, which
  // normalized every fingerprint in it on the way to disk, so the literals
  // arrived already-normalized and the checks tested nothing. Same trap as
  // being unable to write the alias token literally.
  const OFF = '+' + '05' + '30';
  const ZONE = 'Eu' + 'rope' + '/' + 'Lis' + 'bon';
  const LOC = 'en' + '_' + 'GB';

  const cases = [
    [
      'timezone offset on a timestamp',
      '2026-09-18T12:34:56' + OFF,
      // Look only AFTER the time, or the date's own hyphens match: an earlier
      // version of this check used /[+-]0[1-9]/ and flagged the "-09" in the
      // date as an unnormalized offset.
      (o) => !o.includes(OFF),
    ],
    ['bare timezone offset', 'offset is ' + OFF + ' today', (o) => !o.includes(OFF)],
    ['IANA timezone name', 'TZ=' + ZONE + ' in the env', (o) => !o.includes(ZONE)],
    ['regional locale', 'LANG=' + LOC + '.UTF-8', (o) => !o.includes(LOC)],
  ];
  for (const [label, probe, passes] of cases) {
    const out = renderForModel(probe, PIPE).text;
    if (passes(out)) ok(`${label} is normalized away`);
    else bad(`${label} reaches the API unchanged`);
  }
}

console.log('');
console.log('5. ALIASES ARE SAFE AND ACTIVE');
{
  const { aliasRisk } = require('./aliases');
  let risky = 0;
  for (const a of rules.aliases || []) {
    const r = a && aliasRisk(a.alias);
    if (r) { bad('risky alias: ' + r); risky++; }
  }
  if (risky === 0 && (rules.aliases || []).length > 0) ok(`${(rules.aliases || []).length} alias(es), none matching a common word`);
  if ((rules.aliases || []).length === 0) bad('no aliases: your OS username and hostname will appear in every request');

  // Round-trip: the real value must not survive outbound.
  for (const a of rules.aliases || []) {
    if (!a || typeof a.real !== 'string') continue;
    const text = `see ${a.real} and ${a.real}${a.real}`;
    const out = renderForModel(text, PIPE).text;
    if (out.includes(a.real)) bad('an alias real-value survived outbound rendering');
  }
}

console.log('');
console.log("6. LOCATION AND IP, RIGHT NOW");

function getHealth(cb) {
  const port = (rules.proxy && rules.proxy.port) || 47113;
  const req = http.get({ host: '127.0.0.1', port, path: '/_health', timeout: 8000 }, (res) => {
    let b = '';
    res.setEncoding('utf8');
    res.on('data', (c) => (b += c));
    res.on('end', () => {
      try { cb(null, JSON.parse(b)); } catch (e) { cb(e); }
    });
  });
  req.on('timeout', () => { req.destroy(); cb(new Error('timed out')); });
  req.on('error', cb);
}

getHealth((err, h) => {
  if (err) {
    bad(`the proxy is not answering on /_health (${err.message}) -- nothing is being redacted`);
    return finish();
  }
  ok('proxy is running and healthy');

  const e = h.egress || {};
  const home = ((rules.egress && rules.egress.homeCountry) || '').toUpperCase();
  const mode = (rules.egress && rules.egress.mode) || 'off';
  const onFailure = (rules.egress && rules.egress.onFailure) || 'refuse';

  console.log(`   mode ${mode}, onFailure ${onFailure}, home country ${home || '(unset)'}`);
  console.log(`   proxies available ${(e.configured || []).length}`);

  if (mode === 'off') {
    bad('egress mode is "off": your IP and location are NOT masked');
  } else if (e.fellBackDirect > 0) {
    bad(`${e.fellBackDirect} request(s) went out from your REAL address via the "direct" fallback`);
  } else if (e.tunnelling === false) {
    // Legitimate in auto mode when something else is already masking you.
    if (e.directCountry && home && e.directCountry !== home) {
      ok(`not tunnelling, because traffic already leaves from ${e.directCountry} rather than ${home} (VPN or equivalent is doing the job)`);
    } else {
      bad(`not tunnelling, and direct traffic appears to come from ${e.directCountry || 'an unknown country'} -- you look exposed`);
    }
  } else if (e.masking === true) {
    ok(`tunnelling: traffic leaves from ${e.apparentCountry || 'a verified different address'}, not ${e.directCountry || home || 'your own'}`);
    if (home && e.apparentCountry === home) bad(`the tunnel exit is in ${home}, your home country: the address is hidden but the location is not`);
  } else if (e.masking === false) {
    bad('the proxy is forwarding your REAL address (a transparent proxy)');
  } else {
    bad('masking is not yet verified -- treat yourself as unmasked until it is');
  }

  if (onFailure === 'direct' && mode !== 'off') {
    console.log('   note  onFailure is "direct": if every proxy dies, requests go out unmasked rather than being blocked');
  }

  console.log('');
  console.log('7. THE STATUS LINE AGREES WITH REALITY');
  const st = readStatus(path.join(require('os').homedir(), '.claude', 'redaction', 'status.json'));
  if (!st.ok) bad(`status file reads as "${st.reason}", so Claude Code is showing you no protection`);
  else ok('status file is fresh, so the status line reflects live state');

  finish();
});

function finish() {
  console.log('');
  console.log('='.repeat(66));
  if (failures === 0) {
    console.log(`ALL ${checks} CHECKS PASSED`);
    console.log('');
    console.log('Your configured personal data is redacted in every adjacency shape');
    console.log('tested, your aliases are safe, and your IP and location are masked.');
  } else {
    console.log(`${failures} of ${checks} CHECKS FAILED -- see the FAIL lines above`);
  }
  console.log('='.repeat(66));
  process.exit(failures ? 1 : 0);
}
