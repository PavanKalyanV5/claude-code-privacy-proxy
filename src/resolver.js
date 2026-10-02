'use strict';

// Binds derived resolution to the filesystem and the cache.
//
// Derivation is authoritative for file edits: offsets must reflect the file as
// it is NOW. A stale cache entry could write personal data back into a file it
// had been removed from, so the cache is never consulted for Edit offsets --
// only for tools with no file to derive from.
//
// old_string/new_string derivation goes through pipeline.js's renderForModel/
// mapToSource -- the SAME function the outbound walk uses to decide what the
// model sees. Redaction, aliasing and normalization must all be reversed here,
// or a line any of those three stages touched can never be edited (see
// pipeline.js's header comment for the history of that bug).

const fs = require('fs');
const { redactWithSpans, makeLabel } = require('./spans');
const { rehydrate, LABEL_RE } = require('./resolve');
const { renderForModel, mapToSource, makeRenderConfig } = require('./pipeline');

// Tools whose input carries a path we can derive from.
const FILE_TOOLS = {
  Edit: 'file_path',
  MultiEdit: 'file_path',
  Write: 'file_path',
  NotebookEdit: 'notebook_path',
};

// Every built-in tool input that names a location or searches for a value.
// The model only ever sees labels, so a path or pattern it composes from
// something it read (a client name in a directory, say) carries the LABEL and
// must be turned back into the real value before the tool runs. Without this
// a Write to a new file creates a directory literally named "[PII:...]": the
// content was resolved but the destination was not, and nothing reported it.
//
//   paths    -- resolved from the cache only (there is no file to derive from,
//               and for a new file the path does not exist yet), and refused
//               if the substitution would climb out of the directory.
//   patterns -- regex/glob text; resolved from the cache, no path safety rule.
const TOOL_FIELDS = {
  Read: { paths: ['file_path'] },
  Write: { paths: ['file_path'] },
  Edit: { paths: ['file_path'] },
  MultiEdit: { paths: ['file_path'] },
  NotebookEdit: { paths: ['notebook_path'] },
  NotebookRead: { paths: ['notebook_path'] },
  LS: { paths: ['path'] },
  Glob: { paths: ['path'], patterns: ['pattern'] },
  Grep: { paths: ['path'], patterns: ['pattern', 'glob'] },
};

const dotDotSegments = (s) => s.split(/[\\/]+/).filter((x) => x === '..').length;

// Translate an edit expressed against the MODEL-VISIBLE text (rendered by the
// full redact -> alias -> normalize pipeline) into one expressed against the
// REAL text. Mirrors resolve.js's translateEdit, but sourced from `rendered`
// (all three stages) instead of a single redactWithSpans() result.
function translateEditViaPipeline({ realText, rendered, oldString, newString, kLabel, resolveNewString }) {
  if (typeof oldString !== 'string' || oldString.length === 0) return null;

  const hay = rendered.text;
  const idx = hay.indexOf(oldString);
  if (idx === -1) return null; // not found
  if (hay.indexOf(oldString, idx + 1) !== -1) return null; // ambiguous

  const realStart = mapToSource(idx, rendered.stages);
  const realEnd = mapToSource(idx + oldString.length, rendered.stages);
  if (realStart === null || realEnd === null) return null; // boundary inside a replaced span

  const realOld = realText.slice(realStart, realEnd);
  const realNew = resolveNewString
    ? resolveNewString(newString)
    : rehydrate(newString, rendered.redactSpans, kLabel);
  if (realNew === null) return null; // unknown label in new_string

  return { oldString: realOld, newString: realNew };
}

function createResolver({
  rules,
  kLabel,
  cache = null,
  stats = {},
  warn = () => {},
  remoteTools = [],
  aliases = [],
  normalizers = null,
  // Prefer passing the outbound walk's `ctx.render`: shared by reference, the
  // resolver cannot then be reasoning about a different pipeline than the one
  // that produced the text the model saw. The loose params remain for tests
  // that exercise redaction alone.
  render = null,
}) {
  const renderCfg = render || makeRenderConfig({ rules, kLabel, aliases, normalizers });
  function bump(k) {
    stats[k] = (stats[k] || 0) + 1;
  }

  // label -> value for every configured literal, recomputed from the rules and
  // the key rather than remembered. The cache only learns a label when a real
  // value is redacted on its way out, so it misses labels the scrubber wrote
  // into old transcripts, anything past its TTL or size cap, and a cache that
  // was lost or written under another key. A literal's label is derivable, so
  // none of those can strand it. Literals match case-insensitively and the
  // label hashes the MATCHED text, so the common spellings are precomputed;
  // an odd mixed-case one still depends on the cache. Category patterns
  // (email, ip, ...) are open-ended and always do.
  //
  // Every category, not just 'personal': a literal that a category pattern also
  // matches (an email or phone number you listed) is labelled under the
  // pattern's category, because the pattern wins the overlap. A label is an
  // exact keyed hash, so a candidate under the wrong category can never
  // resolve to a wrong value -- it simply never matches anything.
  const literalLabels = new Map();
  const ruleSet = renderCfg.rules || {};
  const categories = ruleSet.categories && ruleSet.categories.length ? ruleSet.categories : ['personal'];
  for (const v of ruleSet.literalValues || []) {
    const title = v.toLowerCase().replace(/(^|[^\p{L}\p{N}])(\p{L})/gu, (m, a, b) => a + b.toUpperCase());
    for (const spelling of new Set([v, v.toLowerCase(), v.toUpperCase(), title])) {
      for (const category of categories) {
        literalLabels.set(makeLabel(renderCfg.kLabel, category, spelling), spelling);
      }
    }
  }

  function lookupLabel(label) {
    const cached = cache ? cache.get(label) : undefined;
    if (cached !== undefined) {
      bump('cacheHit');
      return cached;
    }
    const derived = literalLabels.get(label);
    if (derived !== undefined) bump('literalDerived');
    return derived;
  }

  function fromCache(text) {
    if (typeof text !== 'string') return text;
    LABEL_RE.lastIndex = 0;
    if (!LABEL_RE.test(text)) return text;
    return text.replace(LABEL_RE, (label) => {
      const v = lookupLabel(label);
      return v === undefined ? label : v;
    });
  }

  // Resolve labels from THIS file's spans first (authoritative), then fall
  // back to the cache for labels whose source is some other file or an
  // earlier turn. Returns null if any label survives both -- callers decide
  // whether that means "refuse" or "warn and pass through".
  function resolveLabels(text, spans) {
    if (typeof text !== 'string') return text;
    let out = text;
    if (spans && spans.length) {
      const byLabel = new Map();
      for (const s of spans) byLabel.set(makeLabel(renderCfg.kLabel, s.category, s.value), s.value);
      for (const [label, value] of byLabel) {
        if (out.includes(label)) out = out.split(label).join(value);
      }
    }
    out = fromCache(out);
    LABEL_RE.lastIndex = 0;
    return LABEL_RE.test(out) ? null : out;
  }

  // Recursively walk a node and resolve all string values through resolveLabels.
  // Call onUnresolved() once if any label cannot be resolved.
  // Cache-only resolution since there's no file to derive from for MCP tools.
  function resolveStringsDeep(node, onUnresolved) {
    if (typeof node === 'string') {
      const r = resolveLabels(node, null); // no spans for MCP tools
      if (r === null) {
        onUnresolved();
        return node;
      }
      return r;
    }
    if (Array.isArray(node)) {
      return node.map((n) => resolveStringsDeep(n, onUnresolved));
    }
    if (node && typeof node === 'object') {
      const out = {};
      for (const k of Object.keys(node)) {
        out[k] = resolveStringsDeep(node[k], onUnresolved);
      }
      return out;
    }
    return node;
  }

  // Resolve labels in a path. All-or-nothing: a path with one label resolved
  // and another not points somewhere nobody asked for, so on any failure the
  // original is returned untouched and the failure is counted and warned.
  function resolvePathText(text, toolName, field) {
    if (typeof text !== 'string') return text;
    LABEL_RE.lastIndex = 0;
    if (!LABEL_RE.test(text)) return text;
    const out = resolveLabels(text, null);
    if (out === null) {
      bump('pathLabelUnresolved');
      warn(`a redaction label in ${toolName}.${field} could not be resolved; the tool will act on a path containing [PII:...] instead of the real one`);
      return text;
    }
    // A cached value must not be able to turn a path into a traversal.
    if (out.includes('\0') || dotDotSegments(out) > dotDotSegments(text)) {
      bump('pathUnsafe');
      warn(`a label in ${toolName}.${field} resolves to a value that would escape its directory; left unresolved`);
      return text;
    }
    bump('pathResolved');
    return out;
  }

  function resolveToolFields(toolName, input) {
    const spec = TOOL_FIELDS[toolName];
    if (!spec) return input;
    let out = input;
    const set = (k, v) => {
      if (v !== out[k]) out = out === input ? Object.assign({}, input, { [k]: v }) : Object.assign(out, { [k]: v });
    };
    for (const f of spec.paths || []) set(f, resolvePathText(input[f], toolName, f));
    for (const f of spec.patterns || []) {
      const v = input[f];
      if (typeof v !== 'string') continue;
      const r = resolveLabels(v, null);
      if (r === null) {
        bump('patternLabelUnresolved');
        warn(`a redaction label in ${toolName}.${f} could not be resolved; the search will look for the label text itself`);
      } else {
        set(f, r);
      }
    }
    return out;
  }

  // Check if a tool is in the remote list (by prefix match).
  function isRemoteTool(toolName) {
    if (typeof toolName !== 'string') return false;
    return remoteTools.some((prefix) => toolName.startsWith(prefix));
  }

  return {
    resolveToolInput(name, input) {
      if (!input || typeof input !== 'object') return input;

      // Destination first: everything below reads or writes the file this names.
      input = resolveToolFields(name, input);

      const field = FILE_TOOLS[name];
      if (!field) {
        // No file to derive from. Handle MCP tools, Bash, and others.

        // If this is an MCP tool that's in the remote list, return completely unmodified.
        if (name.startsWith('mcp__') && isRemoteTool(name)) {
          return input;
        }

        // If this is a local MCP tool (not in remote list), resolve all string values.
        if (name.startsWith('mcp__')) {
          let unresolved = false;
          const resolved = resolveStringsDeep(input, () => {
            unresolved = true;
          });
          if (unresolved) {
            warn(`a redaction label could not be resolved in ${name} input; the label will be sent verbatim to the remote server`);
          }
          return resolved;
        }

        // Bash: cache only (existing behavior).
        if (name === 'Bash' && typeof input.command === 'string') {
          return Object.assign({}, input, { command: fromCache(input.command) });
        }

        return input;
      }

      const filePath = input[field];
      if (typeof filePath !== 'string') return input;

      let realText;
      let rendered;
      try {
        realText = fs.readFileSync(filePath, 'utf8');
        rendered = renderForModel(realText, renderCfg);
      } catch (e) {
        bump('noFile');
        // Even with no file, try to resolve from cache (fallback path).
        if (name === 'Write') {
          const content = resolveLabels(input.content, null);
          if (content === null) {
            warn(`a redaction label could not be resolved and will be written verbatim to ${filePath} by ${name}; the file will contain [PII:...] instead of the real value`);
            bump('labelSurvivedWrite');
            return input;
          }
          bump('resolved');
          return Object.assign({}, input, { content });
        }
        if (name === 'NotebookEdit') {
          const newSource = resolveLabels(input.new_source, null);
          if (newSource === null) {
            warn(`a redaction label could not be resolved and will be written verbatim to ${filePath} by ${name}; the file will contain [PII:...] instead of the real value`);
            bump('labelSurvivedWrite');
            return input;
          }
          bump('resolved');
          return Object.assign({}, input, { new_source: newSource });
        }
        if (name === 'Edit') {
          const newString = resolveLabels(input.new_string, null);
          if (newString === null) {
            warn(`a redaction label could not be resolved and will be written verbatim to ${filePath} by ${name}; the file will contain [PII:...] instead of the real value`);
            bump('labelSurvivedWrite');
            return input;
          }
          bump('resolved');
          return Object.assign({}, input, { new_string: newString });
        }
        const edits = name === 'MultiEdit' && Array.isArray(input.edits) ? input.edits : null;
        if (edits) {
          const out = [];
          for (const e of edits) {
            const newString = resolveLabels(e.new_string, null);
            if (newString === null) {
              warn(`a redaction label could not be resolved and will be written verbatim to ${filePath} by ${name}; the file will contain [PII:...] instead of the real value`);
              bump('labelSurvivedWrite');
              return input; // all-or-nothing
            }
            out.push(Object.assign({}, e, { new_string: newString }));
          }
          bump('resolved');
          return Object.assign({}, input, { edits: out });
        }
        return input; // other file tools: nothing to derive
      }

      // From here on, `rendered.text` is authoritative for what the model saw
      // for this file -- whether or not anything was redacted, aliasing or
      // normalization may still have changed it, so there is no shortcut for
      // "nothing to derive" short of actually searching `rendered.text`.

      if (name === 'Write') {
        const content = resolveLabels(input.content, rendered.redactSpans);
        if (content === null) {
          warn(`a redaction label could not be resolved and will be written verbatim to ${filePath} by ${name}; the file will contain [PII:...] instead of the real value`);
          bump('labelSurvivedWrite');
          return input;
        }
        bump('resolved');
        return Object.assign({}, input, { content });
      }

      const edits = name === 'MultiEdit' && Array.isArray(input.edits) ? input.edits : null;
      if (edits) {
        const out = [];
        for (const e of edits) {
          // Pre-resolve new_string with cache fallback
          const resolvedNewString = resolveLabels(e.new_string, rendered.redactSpans);
          if (resolvedNewString === null) {
            warn(`a redaction label could not be resolved and will be written verbatim to ${filePath} by ${name}; the file will contain [PII:...] instead of the real value`);
            bump('labelSurvivedWrite');
            return input; // all-or-nothing: refuse if any edit has unresolvable label
          }
          const t = translateEditViaPipeline({
            realText, rendered, oldString: e.old_string, newString: resolvedNewString, kLabel: renderCfg.kLabel,
          });
          if (!t) {
            bump('refused');
            return input; // all-or-nothing: a partial MultiEdit is worse
          }
          out.push(Object.assign({}, e, { old_string: t.oldString, new_string: t.newString }));
        }
        bump('resolved');
        return Object.assign({}, input, { edits: out });
      }

      const srcOld = name === 'NotebookEdit' ? input.new_source : input.old_string;
      if (typeof srcOld !== 'string') return input;

      if (name === 'NotebookEdit') {
        const s = resolveLabels(input.new_source, rendered.redactSpans);
        if (s === null) {
          warn(`a redaction label could not be resolved and will be written verbatim to ${filePath} by ${name}; the file will contain [PII:...] instead of the real value`);
          bump('labelSurvivedWrite');
          return input;
        }
        bump('resolved');
        return Object.assign({}, input, { new_source: s });
      }

      // Pre-resolve new_string with cache fallback
      const resolvedNewString = resolveLabels(input.new_string, rendered.redactSpans);
      if (resolvedNewString === null) {
        warn(`a redaction label could not be resolved and will be written verbatim to ${filePath} by ${name}; the file will contain [PII:...] instead of the real value`);
        bump('labelSurvivedWrite');
        return input;
      }
      const t = translateEditViaPipeline({
        realText, rendered, oldString: input.old_string, newString: resolvedNewString, kLabel: renderCfg.kLabel,
      });
      if (!t) {
        bump('refused');
        return input;
      }
      bump('resolved');
      return Object.assign({}, input, { old_string: t.oldString, new_string: t.newString });
    },
  };
}

module.exports = { createResolver, FILE_TOOLS };
