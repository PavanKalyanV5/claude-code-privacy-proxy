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

  function fromCache(text) {
    if (!cache || typeof text !== 'string') return text;
    LABEL_RE.lastIndex = 0;
    if (!LABEL_RE.test(text)) return text;
    return text.replace(LABEL_RE, (label) => {
      const v = cache.get(label);
      if (v === undefined) return label;
      bump('cacheHit');
      return v;
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

  // Check if a tool is in the remote list (by prefix match).
  function isRemoteTool(toolName) {
    if (typeof toolName !== 'string') return false;
    return remoteTools.some((prefix) => toolName.startsWith(prefix));
  }

  return {
    resolveToolInput(name, input) {
      if (!input || typeof input !== 'object') return input;

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
