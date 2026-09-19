#!/usr/bin/env node
'use strict';

// Entry point. Wires real keys, rules and config, then listens on loopback.

const fs = require('fs');
const path = require('path');
const os = require('os');
const { loadMaster, subkey, restrictAcl } = require('./keys');
const { load, compile, RULES_PATH } = require('./rules');
const { compileAliases, aliasRisk } = require('./aliases');
const { compileNormalizers } = require('./normalize');
const { makeDeviceRewriter } = require('./device');
const { makeContext } = require('./walk');
const { createLogger } = require('./audit');
const { createCache } = require('./cache');
const { createResolver } = require('./resolver');
const { createServer } = require('./server');
const { parseEgressList, createEgressAgent, createHealth, verifyMasking, prewarm, decideTunnel, DECISION_TTL_MS } = require('./egress');
const { compileHeaderPolicy } = require('./headers');
const { createPool } = require('./pool');
const { createProviders } = require('./providers');
const residueLog = require('./residue-log');
const retention = require('./retention');
const { createStatusWriter } = require('./status');
const { createNotifier } = require('./notify');
const { createDashboard } = require('./dash');
const { spawn } = require('child_process');

// Redaction state lives outside the repo so it can never be committed and no task
// working in the repo can stumble on it.
const LOG_PATH = path.join(os.homedir(), '.claude', 'redaction', 'redact-proxy.log');

// Path overrides exist so the startup test can wire the REAL proxy against
// fixture configs. Without them start.js was the one file no test could touch,
// because exercising it meant reading the user's live rules and key -- and it
// was also the only file with a config-dependent crash: a const referenced
// before its declaration inside a ternary, invisible until that branch ran.
//
// CCR_STARTUP_ONLY wires everything and skips the network side effects (pool
// refresh, masking probe, pre-warm), so the test stays hermetic while still
// executing every line of wiring.
function start() {
  const rulesPath = process.env.CCR_RULES_PATH || undefined;
  const logPath = process.env.CCR_LOG_PATH || LOG_PATH;
  const startupOnly = process.env.CCR_STARTUP_ONLY === '1';
  const logger = createLogger(logPath);

  // Fail closed on key problems: never fall back to unkeyed hashing.
  const master = loadMaster(process.env.CCR_KEY_PATH || undefined);
  const kLabel = subkey(master, 'label');
  const kMemo = subkey(master, 'memo');

  const rules = load(rulesPath);
  const compiled = compile(rules, (m) => logger.warn(m));
  const aliases = compileAliases(rules.aliases, (m) => logger.warn(m));
  // `remoteTools` supersedes `aliasReverseExclude`: the list now governs both
  // alias reversal AND PII label resolution, because the distinction that
  // matters is local-vs-remote, not one transform vs the other. The old key is
  // still honoured so existing configs keep working.
  const remoteTools = rules.remoteTools || rules.aliasReverseExclude || [];
  const port = (rules.proxy && rules.proxy.port) || 47113;

  // Desktop notifications: the only channel that can speak to the user
  // mid-session (see notify.js for why statusLine, SessionStart and the
  // 502 body all fall short). Forced off under CCR_STARTUP_ONLY so the
  // startup permutation tests never spawn a real OS notification process --
  // the same reasoning that already skips pool refresh, masking probe and
  // pre-warm in that mode.
  const notifyCfg = rules.notify || {};
  const notifier = createNotifier({
    enabled: !startupOnly && notifyCfg.enabled !== false,
    minIntervalMs: typeof notifyCfg.minIntervalMs === 'number' ? notifyCfg.minIntervalMs : 5 * 60 * 1000,
    warn: (m) => logger.warn(m),
  });

  if (compiled.literalCount === 0) {
    logger.warn(
      'redact-rules.json has no effective literals; only category patterns will apply'
    );
  }
  // Zero rules of ANY kind (literal or pattern) means the proxy is running
  // but redacting nothing -- the one condition worth a critical toast at
  // startup, since a warning in a log nobody watches live is not enough.
  if (compiled.regexes.length === 0) {
    notifier.alert(
      'critical',
      'No redaction rules loaded',
      'The proxy started with zero literals and zero patterns configured; nothing will be redacted.'
    );
  }
  // Fatal, not a warning. A risky alias silently rewrites source files on
  // write, and the damage is invisible until someone reads the file later.
  // Refusing to start forces a safe alias instead of quietly choosing
  // between corrupting files and leaking the real value.
  for (const a of rules.aliases || []) {
    const risk = a && aliasRisk(a.alias);
    if (risk) {
      throw new Error(
        `unsafe alias in redact-rules.json: ${risk}. ` +
          'Inbound un-aliasing replaces the alias with the real value everywhere it appears, ' +
          'so a common word will be substituted into code and comments you never intended.'
      );
    }
  }
  if (aliases.length === 0) {
    logger.warn('no aliases configured; the OS username will appear in every request');
  }

  const normalizers = compileNormalizers(rules.normalize, (m) => logger.warn(m));

  const kDevice = subkey(master, 'device');
  const deviceRewriter = makeDeviceRewriter({
    mode: (rules.deviceId && rules.deviceId.mode) || 'off',
    kDevice,
  });

  const kCache = subkey(master, 'cache');
  const cache = createCache({ key: kCache });
  const ctx = makeContext({ kLabel, kMemo, rules: compiled, aliases, cache, normalizers, deviceRewriter });
  const resolveStats = {};
  if (deviceRewriter) logger.warn('device_id rewriting is ENABLED; if the API starts rejecting requests, set deviceId.mode back to "off"');
  const resolver = createResolver({
    rules: compiled,
    kLabel,
    cache,
    stats: resolveStats,
    warn: (m) => logger.warn(m),
    remoteTools,
    // One config object, shared by reference with the outbound walk, so the
    // resolver can never reverse a different pipeline than the one that
    // rendered what the model saw.
    render: ctx.render,
  });
  // ---- egress: mask the source IP, fail closed if it cannot ----
  let egressList = [];
  try {
    egressList = parseEgressList(rules.egress);
  } catch (e) {
    // A malformed egress config must not silently degrade to a direct
    // connection, which is what ignoring the error would do.
    logger.warn(`egress config rejected (${e.message}); refusing to start without the tunnel the config asked for`);
    throw e;
  }
  // Created whenever egress COULD carry traffic, which includes pool-only
  // config where nothing is listed up front. Gating this on `egressList`
  // alone meant the agent existed while its health record did not, so the
  // masking check crashed and the status line reported nothing -- the exact
  // configuration for "rely on fetched proxies, keep the VPN manual".
  const egressEnabled = egressList.length > 0 || Boolean((rules.egress && rules.egress.pool || {}).enabled);
  const egressHealth = egressEnabled ? createHealth({ egressList }) : null;
  // Default "refuse": a dead proxy must not silently become an unmasked
  // connection. "direct" is the deliberate escape hatch for being locked out.
  const onFailure = (rules.egress && rules.egress.onFailure) || 'refuse';
  if (!['refuse', 'direct'].includes(onFailure)) {
    throw new Error(`egress.onFailure must be "refuse" or "direct", got ${JSON.stringify(onFailure)}`);
  }
  // mode: "on" always tunnels, "off" never does, "auto" tunnels only when we
  // look exposed -- decided by comparing the apparent country of a direct
  // connection against homeCountry. If traffic already appears to come from
  // somewhere else, a VPN (or anything equivalent) is doing the job and
  // adding a free proxy on top only adds a hop and a third party.
  const egMode = (rules.egress && rules.egress.mode) || (egressList.length ? 'on' : 'off');
  const homeCountry = ((rules.egress && rules.egress.homeCountry) || '').toUpperCase() || null;
  if (egMode === 'auto' && !homeCountry) {
    throw new Error('egress.mode "auto" needs egress.homeCountry (e.g. "PT") to tell exposed from masked');
  }
  // Starts true so the very first request is tunnelled: until the probe comes
  // back we do not know whether we are masked, and assuming we are is the
  // assumption that leaks.
  const egState = {
    tunnel: egMode !== 'off',
    reason: egMode === 'auto' ? 'awaiting first country probe' : `mode=${egMode}`,
    // When the country behind the decision was observed. null means never.
    decidedAt: null,
  };

  const ipCheck = (rules.egress && rules.egress.ipCheckUrl) || 'https://api.ipify.org';
  // The pool supplies proxies fetched from public lists, verified to actually
  // mask before use. Configured `urls` always come first: something the user
  // chose deliberately outranks anything scraped off the internet.
  const poolCfg = (rules.egress && rules.egress.pool) || {};
  const pool = poolCfg.enabled
    ? createPool({
        excludeCountries: poolCfg.excludeCountries || [],
        want: poolCfg.want || 5,
        testUrl: ipCheck,
        // Individual probe failures are expected, not events: free lists run
        // about a 7% hit rate, so most probes fail by design. Forwarding each
        // one would bury the pool's actual outcome and, since warnings feed
        // the status line, fill it with noise while nothing was wrong. The
        // verified count below is the outcome that matters.
        warn: (m) => {
          if (!/^probe failed:/.test(m)) logger.warn(`pool: ${m}`);
        },
      })
    : null;
  let poolList = [];
  // Endpoints already running on this machine: an SSH dynamic forward,
  // Cloudflare WARP, Tor, or anything else speaking SOCKS5 or CONNECT on a
  // known port. Detection completes a real protocol handshake, so an open
  // port that merely accepts a connection is never offered as a proxy.
  let detectedList = [];

  // Order IS precedence: configured first, because a deliberate choice
  // outranks anything discovered; then locally detected; then the opt-in
  // pool last, as the least dependable source by nature.
  const getEgressList = () => egressList.concat(detectedList, poolList);

  const providers = egressEnabled
    ? createProviders({
        testUrl: ipCheck,
        warn: (m) => logger.warn('providers: ' + m),
        extra: (rules.egress && rules.egress.providers) || {},
      })
    : null;

  // Fire-and-forget. Detection must never delay listening: a proxy that is
  // slow to start looks exactly like a proxy that is broken.
  function detectProviders() {
    if (!providers) return;
    providers.detect((err, found) => {
      if (err) {
        logger.warn('provider detection failed (' + err.message + '); continuing with configured and pooled proxies only');
        return;
      }
      detectedList = (found || []).map((p) => p.egress).filter(Boolean);
      if (detectedList.length) {
        logger.warn('providers: detected ' + detectedList.length + ' local endpoint(s): ' + (found || []).map((p) => p.id).join(', '));
      } else {
        logger.warn('providers: none detected locally; see docs/providers.md for free options that are actually dependable');
      }
      if (egressHealth) egressHealth.setConfigured(getEgressList().map((e) => e.label));
      publishStatus();
    });
  }

  const egressAgent = (egressList.length || pool)
    ? createEgressAgent({
        egressList: getEgressList,
        warn: (m) => logger.warn(m),
        health: egressHealth,
        allowDirect: onFailure === 'direct',
        // Re-evaluated per connection so an expired observation fails SAFE. Trusting
        // the stored verdict is what let a VPN drop go unnoticed for 7 minutes.
        // Self-healing: a proxy that cannot carry a connection is dropped
        // from the pool at once, and an exhausted pool triggers a refresh.
        // Otherwise a dead entry is retried on every single request until
        // its cache TTL expires.
        onProxyFailure: (label) => {
          if (!pool) return;
          pool.demote(label);
          poolList = poolList.filter((p) => p.label !== label);
          if (egressHealth) {
            egressHealth.setConfigured(egressList.map((e) => e.label).concat(poolList.map((p) => p.label)));
          }
          if (poolList.length === 0 && egressList.length === 0 && !poolRefreshing) {
            refreshPool('pool exhausted by live failures');
          }
        },
        shouldTunnel: () => {
          if (egMode !== 'auto') return egState.tunnel;
          const d = decideTunnel({
            mode: egMode,
            homeCountry,
            directCountry: egressHealth && egressHealth.state.directCountry,
            decidedAt: egState.decidedAt,
          });
          return d.tunnel;
        },
      })
    : null;

  // Guards against a stampede: many concurrent requests can each discover
  // the last proxy is dead at the same moment.
  let poolRefreshing = false;
  function refreshPool(why) {
    if (!pool || poolRefreshing) return;
    poolRefreshing = true;
    logger.warn(`pool: refreshing (${why})`);
    pool.get((err, list) => {
      if (err) {
        poolRefreshing = false;
        logger.warn(`pool: refresh failed (${err.message}); keeping ${poolList.length} cached`);
        return;
      }
      poolRefreshing = false;
      poolList = list || [];
      logger.warn(`pool: ${poolList.length} verified proxies available`);
      if (egressHealth) {
        // Keep `configured` truthful as the pool changes, so readers can tell
        // "egress active with 3 proxies" from "egress active with none" --
        // the second is the state that needs the VPN turned back on.
        egressHealth.setConfigured(egressList.map((e) => e.label).concat(poolList.map((p) => p.label)));
        if (poolList.length === 0 && egressList.length === 0) {
          egressHealth.note({ ok: false, error: 'no proxies verified; requests will be refused until one is' });
        }
      }
      publishStatus();
      // New proxies mean no warm socket to any of them yet.
      if (egState.tunnel && poolList.length) {
        prewarm({ agent: egressAgent, warn: (m) => logger.warn(m) }, (ok) => {
          if (ok) logger.warn('egress pre-warmed: a tunnel to the API is open and pooled');
        });
      }
    });
  }
  if (egressAgent && onFailure === 'direct') {
    logger.warn(
      'egress.onFailure is "direct": if every proxy fails, requests go out from your real IP rather than being blocked'
    );
  }
  const ipCheckEnabled = !(rules.egress && rules.egress.ipCheck === false);

  const headerPolicy = compileHeaderPolicy(rules.headers || {});

  // Named and shared, not inlined into createServer's options: the
  // dashboard's Egress tab (POST /_dash/api/egress/on|off|check) delegates
  // to these exact same closures, so a toggle flipped from the browser and
  // one flipped from curl go through one code path instead of two that could
  // drift apart.
  //
  // Fresh live probe, not a cached read: direct vs tunnelled, compared now.
  const doEgressCheck = egressAgent
    ? (done) => {
        const probe = createHealth({ egressList: getEgressList() });
        verifyMasking(
          { health: probe, agent: egressAgent, url: ipCheck, checkDirect: true, warn: () => {} },
          () => {
            const s = probe.snapshot();
            const home = homeCountry;
            done({
              masked: s.masking === true,
              tunnelling: egState.tunnel,
              decision: egState.reason,
              yourCountry: s.directCountry || null,
              exitCountry: s.apparentCountry || null,
              exitAddress: s.exitIp || null,
              homeCountry: home,
              exitIsHomeCountry: Boolean(home && s.apparentCountry === home),
              proxiesAvailable: getEgressList().length,
              wentOutDirect: egressHealth ? egressHealth.state.fellBackDirect : 0,
              onFailure,
              checkedAt: new Date().toISOString(),
              note:
                s.masking === true
                  ? "Traffic leaves from exitCountry, not yourCountry. Verified by asking an echo service, not by reading a stored value."
                  : s.masking === false
                    ? "The echo service saw the SAME address as a direct connection: you are NOT masked."
                    : "Could not confirm. Treat yourself as unmasked until it says otherwise.",
            });
          }
        );
      }
    : null;

  const doEgressToggle = egressAgent
    ? (on) => {
        egState.tunnel = on;
        egState.reason = `toggled ${on ? 'on' : 'off'} at runtime`;
        if (egressHealth) egressHealth.setTunnelDecision(on, egState.reason);
        publishStatus();
      }
    : null;

  // Last structured record of the scheduled residue scrub, for the
  // dashboard's Residue tab. null until the first pass completes (or forever,
  // if scrubbing isn't configured) -- the dashboard must show "never run",
  // never invent a result.
  let lastScrub = null;

  // The dashboard: served by THIS server, on THIS port, no new process. Built
  // before createServer so the same instance can be threaded into it below.
  const dashboard = createDashboard({
    rulesPath: rulesPath || RULES_PATH,
    logPath,
    getSnapshot: () => ({
      proxy: { pid: process.pid, port, uptimeMs: Math.round(process.uptime() * 1000) },
      redaction: {
        literals: compiled.literalCount,
        patterns: compiled.patternCount,
        aliases: aliases.length,
        rewrites: normalizers.rewrites.length,
        timezone: normalizers.timezone,
      },
      egress: egressHealth
        ? Object.assign(egressHealth.snapshot(), { pool: pool ? poolList.length : null })
        : { configured: [], active: null, ok: null, masking: null, note: 'egress not configured' },
      residue: lastScrub,
    }),
    egressActions: egressAgent ? { toggle: doEgressToggle, check: doEgressCheck } : {},
  });

  const server = createServer({
    ctx, aliases, logger, resolver, remoteTools, egressAgent, egressHealth, headerPolicy, port,
    dash: dashboard,
    egressCheck: doEgressCheck,
    egressToggle: doEgressToggle,
  });

  // Persist the cache periodically and on exit; losing it costs only the
  // Bash-label fallback, never correctness.
  const flush = setInterval(() => cache.save(), 60000);
  if (flush.unref) flush.unref();
  for (const sig of ['SIGINT', 'SIGTERM']) {
    process.on(sig, () => { cache.save(); process.exit(0); });
  }

  // Publishes state for the status line. The heartbeat is what makes "the
  // proxy died" detectable: the reader treats a stale file as unprotected, so
  // the absence of these writes is itself the signal.
  const status = createStatusWriter();

  // Mid-session notification state, tracked here (not inside notify.js)
  // because only start.js knows what "a change" means for each condition --
  // notify.js just rate-limits identical messages. Each flag below fires a
  // toast exactly once per transition into the bad state, then resets when
  // the state clears (except the sticky direct-fallback counter, which by
  // design never goes back down, so its flag never resets either).
  let sawMaskingConfirmed = false;
  let maskingLostNotified = false;
  let directFallbackNotified = false;
  let poolEmptyNotified = false;

  const publishStatus = () => {
    const redaction = {
      literals: compiled.literalCount,
      patterns: compiled.patternCount,
      aliases: aliases.length,
    };
    const egress = egressHealth
      ? Object.assign(egressHealth.snapshot(), { pool: pool ? poolList.length : null })
      : { configured: [] };

    // masking was confirmed and is now NOT masked -> critical, once per loss.
    if (egress.masking === true) {
      sawMaskingConfirmed = true;
      maskingLostNotified = false;
    } else if (egress.masking === false) {
      if (sawMaskingConfirmed && !maskingLostNotified) {
        notifier.alert(
          'critical',
          'IP masking lost',
          'Masking was confirmed earlier this session and is no longer active; traffic may be leaving from your real address.'
        );
        maskingLostNotified = true;
      }
    }

    // a request went out direct via onFailure:"direct" -> critical, once,
    // the moment the sticky counter first becomes non-zero.
    if (egress.fellBackDirect > 0 && !directFallbackNotified) {
      notifier.alert(
        'critical',
        'Request sent unmasked',
        `The egress fallback sent at least one request from your real address (onFailure="direct"); count=${egress.fellBackDirect}.`
      );
      directFallbackNotified = true;
    }

    // the egress pool became empty while egress is meant to be active -> warn.
    if (egressEnabled) {
      const available = Array.isArray(egress.configured) ? egress.configured.length : 0;
      if (available === 0) {
        if (!poolEmptyNotified) {
          notifier.alert(
            'warn',
            'Egress pool empty',
            'No egress proxies are currently available; requests may be refused or sent unmasked depending on configuration.'
          );
          poolEmptyNotified = true;
        }
      } else {
        poolEmptyNotified = false;
      }
    }

    return status.publish({ port, redaction, egress });
  };
  const heartbeat = setInterval(publishStatus, 30 * 1000);
  if (heartbeat.unref) heartbeat.unref();

  // Retention, enforced by the proxy because it is the only component that is
  // always running. Hourly, and once shortly after startup so a machine that
  // is rarely left on still gets housekeeping.
  //
  // Wrapped in try/catch and never awaited: retention is maintenance, and
  // maintenance failing must never take down redaction. A full disk is a
  // problem; a proxy that refuses to start because it could not delete an
  // old backup is a worse one.
  const runRetention = (why) => {
    try {
      const r = retention.enforce(rules);
      if (r && r.actions && r.actions.length) {
        logger.warn('retention (' + why + '): ' + r.actions.map((a) => JSON.stringify(a)).join(', '));
      }
    } catch (e) {
      logger.warn('retention pass failed (' + e.message + '); logs may grow until this is fixed');
    }
  };
  if (!startupOnly) {
    const firstSweep = setTimeout(() => runRetention('startup'), 60 * 1000);
    if (firstSweep.unref) firstSweep.unref();
    const sweep = setInterval(() => runRetention('hourly'), 60 * 60 * 1000);
    if (sweep.unref) sweep.unref();
  }
  // Every warning already goes to the audit log, which nobody watches live.
  // Wrapping warn routes the same message into the status notices so it also
  // reaches the session. Callers hold `(m) => logger.warn(m)` closures that
  // resolve the property at call time, so they pick this up.
  const baseWarn = logger.warn;
  logger.warn = (m) => {
    baseWarn(m);
    status.note(/REFUSED|NOT MASK|EXPOSED|DIRECT CONNECTION|UNHEALTHY/.test(m) ? 'error' : 'warn', m);
  };

  // ---- Phase 4: keep local residue from accumulating ----
  //
  // Transcripts, file-history and shell snapshots are written before the
  // proxy sees anything, so they hold real values. A periodic scrub rewrites
  // them as the model saw them.
  //
  // Run in a DETACHED CHILD, never inline: it walks ~4000 files and several
  // hundred MB, which would stall the event loop and make the proxy stop
  // answering requests -- turning a privacy cleanup into an outage.
  const residueCfg = rules.residue || {};
  if (residueCfg.scrub && !startupOnly) {
    const everyMin = residueCfg.intervalMinutes || 60;
    const skipMin = residueCfg.skipNewerThanMin || 60;
    const script = path.join(__dirname, 'scrub-residue.js');
    let scrubbing = false;

    const runScrub = () => {
      if (scrubbing) return; // a slow pass must not stack up behind itself
      scrubbing = true;
      // A manifest per run, always: the scheduled pass uses --no-backup, so
      // without one there is no record at all of WHICH files it rewrote.
      // Counts answer "how many"; an audit needs "which".
      //
      // The raw log (actual values) is opt-in via residue.rawLog, because it
      // is a concentrated copy of the data the scrub just removed. It is
      // written owner-only and expires on the shortest retention window.
      const runId = new Date().toISOString().replace(/[:.]/g, '-');
      const runsDir = path.join(path.dirname(logPath), 'residue-runs');
      const manifestPath = path.join(runsDir, runId + '.manifest.json');
      const extraArgs = ['--manifest', manifestPath];
      if (residueCfg.rawLog) extraArgs.push('--raw-log', path.join(runsDir, runId + '.raw.jsonl'));

      const child = spawn(process.execPath,
        [script, '--write', '--quiet', '--skip-newer-than-min', String(skipMin), '--no-backup'].concat(extraArgs),
        // windowsHide is not cosmetic here. Without it every hourly pass
        // flashes a console window on the desktop, which is both alarming
        // and a good way to get a privacy tool disabled by its own user.
        // detached keeps the pass alive if the proxy restarts mid-scrub.
        { detached: true, windowsHide: true, stdio: ['ignore', 'pipe', 'pipe'] });
      let out = '';
      child.stdout.on('data', (c) => { out += c; });
      child.stderr.on('data', (c) => { out += c; });
      const startedAt = Date.now();
      child.on('close', (code) => {
        scrubbing = false;
        const m = /files rewritten\s*:\s*(\d+)/.exec(out);
        const v = /verify failures\s*:\s*(\d+)/.exec(out);
        const s = /files scanned\s*:\s*(\d+)/.exec(out);
        const filesRewritten = m ? Number(m[1]) : 0;
        const verifyFailures = v ? Number(v[1]) : 0;
        const failed = code !== 0 || (v && v[1] !== '0');
        lastScrub = { ts: Date.now(), ok: !failed, filesRewritten, verifyFailures, exitCode: code };
        // Durable, because lastScrub lives only in this process and the proxy
        // restarts at logon, on a crash, and whenever the watchdog revives
        // it. Without this the one job that MODIFIES the user's files has no
        // history to audit.
        residueLog.record({
          trigger: 'scheduled',
          ok: !failed,
          filesScanned: s ? Number(s[1]) : null,
          filesRewritten,
          verifyFailures,
          exitCode: code,
          durationMs: Date.now() - startedAt,
          manifest: manifestPath,
          hasRawLog: Boolean(residueCfg.rawLog),
          // The run's own output, kept per-run so a pass can be audited
          // after the fact rather than reduced to four numbers. `--quiet`
          // keeps this values-free: counts and paths, never file contents.
          output: out,
        });
        if (failed) {
          logger.warn(`residue scrub FAILED (exit ${code}, verify failures ${v ? v[1] : '?'}); local transcripts still hold real values`);
        } else if (m && m[1] !== '0') {
          logger.warn(`residue scrub: ${m[1]} file(s) rewritten`);
        }
      });
      child.on('error', (e) => { scrubbing = false; logger.warn(`residue scrub could not start: ${e.message}`); });
      child.unref();
    };

    // --no-backup on the scheduled pass on purpose: it runs hourly, and
    // keeping a 550MB copy every hour would fill the disk within a day. The
    // manual run backs up by default, which is the one to use before a
    // first-time or config-changing scrub.
    const firstRun = setTimeout(runScrub, 5 * 60 * 1000);
    if (firstRun.unref) firstRun.unref();
    const scrubTimer = setInterval(runScrub, everyMin * 60 * 1000);
    if (scrubTimer.unref) scrubTimer.unref();
    logger.warn(`residue scrub enabled: every ${everyMin} min, skipping files touched in the last ${skipMin} min`);
  }

  server.listen(port, '127.0.0.1', () => {
    publishStatus();
    logger.warn(
      `listening on http://127.0.0.1:${port} -> https://api.anthropic.com ` +
        `(literals=${compiled.literalCount} patterns=${compiled.patternCount} aliases=${aliases.length} rewrites=${normalizers.rewrites.length} remoteTools=${remoteTools.length} egress=${egMode === 'off' ? 'off' : egMode + (pool ? '+pool' : '') + ':' + (egressList.length || 0) + 'cfg'})`
    );
    // The dashboard token guards a route that REWRITES the user's PII rules,
    // so where it comes to rest matters more than convenience.
    //
    // It used to be logged in full, on the reasoning that status.json is
    // readable by other local processes but the audit log is "already
    // trusted". That reasoning was wrong, and measurably so: the log file
    // carries INHERITED ACLs (owner + SYSTEM + Administrators) while
    // redact.key has inheritance stripped and is owner-only. The log is
    // therefore a strictly WEAKER location than the one deliberately avoided,
    // and unlike a status snapshot it persists indefinitely.
    //
    // So the token goes to a file locked down exactly like the master key,
    // and the log gets a URL with no secret in it.
    const tokenPath = path.join(path.dirname(logPath), 'dash-token');
    let tokenStored = false;
    try {
      fs.writeFileSync(tokenPath, dashboard.token + '\n', { mode: 0o600 });
      // Node's mode is largely inert on Windows; restrictAcl strips
      // inheritance for real. If it fails, say so rather than implying the
      // file is protected when it is not.
      tokenStored = restrictAcl(tokenPath);
      if (!tokenStored) {
        baseWarn('dashboard: could not restrict permissions on ' + tokenPath + '; other local accounts may be able to read the dashboard token');
      }
    } catch (e) {
      baseWarn('dashboard: could not store the token (' + e.message + '); run `npm run dash` will not work');
    }
    baseWarn(
      'dashboard: http://127.0.0.1:' + port + '/_dash  (run `npm run dash` for the URL with its token' +
        (tokenStored ? '' : ' -- WARNING: token file is not permission-restricted') + ')'
    );

    if (egressAgent && ipCheckEnabled && !startupOnly) {
      // Verify masking at startup and then periodically, so a proxy that dies
      // or starts forwarding the real address is reported rather than assumed
      // good for the rest of the session.
      const runCheck = () =>
        verifyMasking({ health: egressHealth, agent: egressAgent, url: ipCheck, warn: (m) => logger.warn(m) }, (s) => {
          if (egMode === 'auto') {
            // A fresh observation resets the clock; decideTunnel owns the rule.
            egState.decidedAt = s.directCountry ? Date.now() : null;
            const d = decideTunnel({ mode: egMode, homeCountry, directCountry: s.directCountry, decidedAt: egState.decidedAt });
            egState.tunnel = d.tunnel;
            egState.reason = d.reason;
            if (egressHealth) egressHealth.setTunnelDecision(d.tunnel, d.reason);
            logger.warn(`egress auto: ${d.reason}`);
          }
          // What "masked" means depends on which path is in use. When auto
          // mode has decided not to tunnel, the agent connects directly, so
          // verifyMasking is measuring the DIRECT path -- apparent equals
          // direct by construction, and reading that as "not masking" is a
          // false alarm that contradicts the decision logged a tick earlier.
          const usingTunnel = egState.tunnel;
          const externallyMasked =
            Boolean(homeCountry) && Boolean(s.directCountry) && s.directCountry !== homeCountry;

          if (!usingTunnel) {
            // Deliberately direct. Masked only if something else is doing it.
            if (egressHealth) egressHealth.setExternallyMasked(externallyMasked, s.directCountry || null);
            if (externallyMasked) {
              logger.warn(
                'egress idle: not tunnelling, and traffic already leaves from ' +
                  s.directCountry + ' rather than ' + homeCountry + ' -- masked by other means'
              );
            } else {
              logger.warn(
                'EGRESS IDLE AND UNMASKED: not tunnelling, and traffic appears to come from ' +
                  (s.directCountry || 'an unknown country') + '. Your own address is in use.'
              );
            }
          } else if (s.masking === true) {
            logger.warn(
              'egress verified: traffic leaves via ' + s.active + ' as ' +
                (s.exitIp || 'a different address') + ' (' + (s.apparentCountry || 'country unknown') + ')'
            );
          } else if (s.masking === false) {
            logger.warn(
              'EGRESS NOT MASKING: tunnelling is ON, but the echo service sees the same address as a ' +
                'direct connection. The proxy is forwarding your real IP -- treat it as unmasked.'
            );
          } else {
            logger.warn('egress masking unconfirmed; tunnel itself is ' + (s.ok ? 'up' : 'down'));
          }
          publishStatus();
        });
      if (!startupOnly) detectProviders();
      if (pool && !startupOnly) refreshPool('startup');
      runCheck();
      // Auto mode polls near the decision TTL so the observation stays fresh;
      // other modes have no country decision to keep current.
      const recheckMs = egMode === 'auto' ? Math.max(60000, DECISION_TTL_MS - 30000) : 15 * 60 * 1000;
      const recheck = setInterval(runCheck, recheckMs);
      if (recheck.unref) recheck.unref();
    } else if (!egressAgent) {
      logger.warn('egress tunnel is OFF: requests go out from this machine\'s own IP');
    }
  });
  return server;
}

if (require.main === module) start();
module.exports = { start, LOG_PATH };
