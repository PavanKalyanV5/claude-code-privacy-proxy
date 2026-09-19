'use strict';

// Inbound SSE transform.
//
// Only one thing happens here in Phase 1: reversing identity aliases inside
// tool_use inputs, so tools receive real paths. PII label resolution is Phase 2.
//
// tool_use inputs arrive as a sequence of input_json_delta fragments. An alias
// can be split across two fragments, where it cannot be matched at all, so
// fragments are held per block index and emitted as ONE corrected delta at
// content_block_stop. Buffering to the block boundary removes every
// partial-match edge case.
//
// text_delta is passed through untouched on purpose: Claude's prose keeps its
// labels, which means the on-disk transcript inherits no personal data.

const { toReal } = require('./aliases');

// Aliases are reversed for every tool by default, so MCP servers receive
// working paths. A server listed in `remoteTools` keeps the alias --
// use that for REMOTE servers, which have no business learning the real OS
// username. A local server runs as the user and could read it anyway.
function shouldUnalias(toolName, remoteTools = []) {
  if (typeof toolName !== 'string') return true;
  return !remoteTools.some((prefix) => toolName.startsWith(prefix));
}

// Un-alias by parsing the accumulated JSON and walking its string values --
// NEVER by string-replacing in the raw JSON text. A real path contains single
// backslashes, which are invalid unescaped inside a JSON string literal, so a
// raw replacement would emit `"C:\Users\SOMEONE"` and corrupt the payload.
function unaliasNode(node, aliases, stats) {
  if (typeof node === 'string') {
    const r = toReal(node, aliases);
    stats.resolvedAliases = (stats.resolvedAliases || 0) + r.count;
    return r.text;
  }
  if (Array.isArray(node)) return node.map((n) => unaliasNode(n, aliases, stats));
  if (node && typeof node === 'object') {
    const out = {};
    for (const k of Object.keys(node)) out[k] = unaliasNode(node[k], aliases, stats);
    return out;
  }
  return node;
}

function createSseTransformer({ aliases, stats = {}, resolver = null, remoteTools = [], aliasReverseExclude = [] }) {
  // remoteTools supersedes aliasReverseExclude for backward compatibility
  const remote = remoteTools.length > 0 ? remoteTools : aliasReverseExclude;
  let buf = '';
  const blocks = new Map(); // index -> { name, json }

  function emitEvent(rawEvent) {
    const dataLines = [];
    for (const line of rawEvent.split('\n')) {
      if (line.startsWith('data:')) dataLines.push(line.slice(5).trim());
    }
    if (dataLines.length === 0) return rawEvent;

    let payload;
    try {
      payload = JSON.parse(dataLines.join('\n'));
    } catch (e) {
      return rawEvent; // not ours to understand; forward verbatim
    }

    const idx = payload.index;

    if (payload.type === 'content_block_start') {
      const cb = payload.content_block || {};
      if (cb.type === 'tool_use') blocks.set(idx, { name: cb.name, json: '' });
      return rawEvent;
    }

    if (
      payload.type === 'content_block_delta' &&
      payload.delta &&
      payload.delta.type === 'input_json_delta' &&
      blocks.has(idx)
    ) {
      blocks.get(idx).json += payload.delta.partial_json || '';
      return ''; // held until the block closes
    }

    if (payload.type === 'content_block_stop' && blocks.has(idx)) {
      const block = blocks.get(idx);
      blocks.delete(idx);
      let json = block.json;
      if (shouldUnalias(block.name, remote)) {
        try {
          json = JSON.stringify(unaliasNode(JSON.parse(json), aliases, stats));
        } catch (e) {
          // Incomplete or non-JSON accumulation: forward as-is rather than
          // risk corrupting the tool input.
        }
      }
      // Resolution runs AFTER un-aliasing: file_path must be a real path
      // before the file can be read. A resolver failure must never break the
      // stream, so anything thrown leaves the input exactly as it arrived.
      if (resolver && json) {
        try {
          const parsed = JSON.parse(json);
          const resolved = resolver.resolveToolInput(block.name, parsed);
          if (resolved && typeof resolved === 'object') json = JSON.stringify(resolved);
        } catch (e) {
          /* leave `json` as-is */
        }
      }
      const delta = {
        type: 'content_block_delta',
        index: idx,
        delta: { type: 'input_json_delta', partial_json: json },
      };
      return (
        `event: content_block_delta\ndata: ${JSON.stringify(delta)}\n\n` + rawEvent
      );
    }

    return rawEvent;
  }

  return {
    push(chunk) {
      buf += chunk;
      let out = '';
      let i;
      while ((i = buf.indexOf('\n\n')) !== -1) {
        const rawEvent = buf.slice(0, i + 2);
        buf = buf.slice(i + 2);
        out += emitEvent(rawEvent);
      }
      return out;
    },
    flush() {
      const rest = buf;
      buf = '';
      return rest;
    },
  };
}

module.exports = { createSseTransformer, shouldUnalias };
