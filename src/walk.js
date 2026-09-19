'use strict';

// Outbound body transform.
//
// Walks ONLY the fields that carry user data. `tools[]` is skipped because it is
// static product documentation and ~45% of the body -- skipping it is the single
// largest performance decision here. Signed thinking blocks are skipped because
// altering one byte invalidates their signature and the API rejects the request;
// that is safe, since the model only ever saw labels, so its thinking contains
// labels rather than personal data.
//
// Per-block memoization is what makes this scale. The whole conversation is
// re-uploaded every turn, so without it a 4MB body at 1M context costs ~400ms
// per turn. History is append-only and redaction is deterministic, so a block
// transformed last turn transforms identically this turn.

const crypto = require('crypto');
const { makeLabel } = require('./spans');
const { renderForModel, makeRenderConfig } = require('./pipeline');

// Signed by the API; must travel byte-identical. `image`/`document` blocks
// carry their payload as base64 in `source.data` -- that is opaque binary,
// not text, so walking into it is both wrong (a boundary-matched literal or
// pattern hit inside base64 would corrupt the encoded bytes, since nothing
// here decodes/re-encodes base64) and wasteful (these blocks are often the
// largest thing in a body, so walking them for no benefit costs real time).
const SKIP_BLOCK_TYPES = new Set(['thinking', 'redacted_thinking', 'image', 'document']);

function freshStats() {
  return { counts: {}, aliased: 0, memoHit: 0, memoMiss: 0, walkedChars: 0, normalized: 0 };
}

function makeContext({ kLabel, kMemo, rules, aliases, cache = null, normalizers = null, deviceRewriter = null, memoMax = 2000 }) {
  return {
    kLabel,
    kMemo,
    rules,
    aliases,
    cache,
    normalizers,
    // Pass this to createResolver so the two cannot be given different
    // configs -- see pipeline.js makeRenderConfig.
    render: makeRenderConfig({ rules, kLabel, aliases, normalizers }),
    deviceRewriter,
    memoMax,
    memo: new Map(),
    stats: freshStats(),
  };
}

function resetStats(ctx) {
  ctx.stats = freshStats();
}

function transformString(s, ctx) {
  ctx.stats.walkedChars += s.length;

  // Single shared definition of "what the model sees" -- see pipeline.js.
  // Redaction must see the ORIGINAL text so its spans stay meaningful for
  // Phase 2 derivation, aliasing runs next, and normalization runs last so a
  // timestamp rewritten to UTC is not then re-scanned as a phone number.
  const rendered = renderForModel(s, ctx.render);

  for (const [k, v] of Object.entries(rendered.counts)) {
    ctx.stats.counts[k] = (ctx.stats.counts[k] || 0) + v;
  }
  if (ctx.cache) {
    for (const span of rendered.redactSpans) {
      ctx.cache.set(makeLabel(ctx.kLabel, span.category, span.value), span.value);
    }
  }
  ctx.stats.aliased += rendered.aliased;
  ctx.stats.normalized += rendered.normalized;

  return rendered.text;
}

function transformNode(node, ctx) {
  if (typeof node === 'string') return transformString(node, ctx);
  if (Array.isArray(node)) return node.map((n) => transformNode(n, ctx));
  if (node && typeof node === 'object') {
    if (SKIP_BLOCK_TYPES.has(node.type)) return node;
    const out = {};
    for (const k of Object.keys(node)) out[k] = transformNode(node[k], ctx);
    return out;
  }
  return node;
}

// Keyed rather than plain hash: the key is derived from the master key, so the
// memo keys reveal nothing even though they are computed over raw content.
function memoKey(ctx, block) {
  return crypto
    .createHmac('sha256', ctx.kMemo)
    .update(JSON.stringify(block))
    .digest('hex');
}

function memoized(block, ctx) {
  const key = memoKey(ctx, block);
  if (ctx.memo.has(key)) {
    const hit = ctx.memo.get(key);
    ctx.memo.delete(key); // refresh LRU position
    ctx.memo.set(key, hit);
    ctx.stats.memoHit++;
    return hit;
  }
  ctx.stats.memoMiss++;
  const out = transformNode(block, ctx);
  ctx.memo.set(key, out);
  if (ctx.memo.size > ctx.memoMax) {
    ctx.memo.delete(ctx.memo.keys().next().value);
  }
  return out;
}

function transformBody(body, ctx) {
  const out = Object.assign({}, body);

  if (Array.isArray(body.system)) out.system = body.system.map((b) => memoized(b, ctx));
  else if (typeof body.system === 'string') out.system = memoized(body.system, ctx);

  if (Array.isArray(body.messages)) out.messages = body.messages.map((m) => memoized(m, ctx));

  // metadata is otherwise passed through byte-identical; this is the single
  // exception, and only when explicitly enabled.
  if (ctx.deviceRewriter && body.metadata) out.metadata = ctx.deviceRewriter(body.metadata);

  // tools and everything else pass through untouched.
  return out;
}

module.exports = { makeContext, transformBody, resetStats, SKIP_BLOCK_TYPES };
