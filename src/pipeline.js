'use strict';

// THE single definition of what the model sees for a given piece of text.
//
// Both the outbound walk and the inbound resolver MUST go through here. They
// used to implement the pipeline separately, and drifted twice: aliasing and
// normalization were applied outbound but not reversed inbound, so any line
// they touched could not be edited at all. If you add a stage, add it here and
// nowhere else.

const { redactWithSpans } = require('./spans');
const { toAliasWithSpans } = require('./aliases');
const { normalizeWithSpans } = require('./normalize');

// The outbound walk and the inbound resolver must not merely run the same
// stages -- they must be handed the same CONFIG. Giving them separately-built
// configs is silent: the model sees text the resolver cannot reconstruct, and
// every Edit on an affected line either fails or corrupts. So the config is
// built once, frozen, and shared by reference; `makeContext` builds it and
// `createResolver` takes that same object.
function makeRenderConfig({ rules, kLabel, aliases = [], normalizers = null }) {
  return Object.freeze({ rules, kLabel, aliases: aliases || [], normalizers });
}

// Returns the model-visible text plus the per-stage offset maps, ordered
// first-applied to last-applied.
function renderForModel(text, { rules, kLabel, aliases, normalizers }) {
  const r = redactWithSpans(text, rules, kLabel);
  const a = toAliasWithSpans(r.text, aliases || []);
  const n = normalizers
    ? normalizeWithSpans(a.text, normalizers)
    : { text: a.text, count: 0, spans: [] };
  return {
    text: n.text,
    stages: [r.spans, a.spans, n.spans],
    redactSpans: r.spans,
    counts: r.counts,
    aliased: a.count,
    normalized: n.count,
  };
}

// Translate an offset in the model-visible text back to an offset in the
// original text, reversing each stage in turn. Returns null if the offset
// falls strictly inside any replacement, where no single source offset exists.
function mapToSource(outOffset, stages) {
  let o = outOffset;
  for (let i = stages.length - 1; i >= 0; i--) {
    o = mapBackOneStage(o, stages[i]);
    if (o === null) return null;
  }
  return o;
}

function mapBackOneStage(outOffset, spans) {
  let delta = 0;
  for (const s of spans) {
    const srcStart = s.srcStart !== undefined ? s.srcStart : s.realStart;
    const srcEnd = s.srcEnd !== undefined ? s.srcEnd : s.realEnd;
    const outStart = s.outStart !== undefined ? s.outStart : s.redStart;
    const outEnd = s.outEnd !== undefined ? s.outEnd : s.redEnd;
    if (outOffset <= outStart) break;
    if (outOffset < outEnd) return null;
    delta += (srcEnd - srcStart) - (outEnd - outStart);
  }
  return outOffset + delta;
}

module.exports = { renderForModel, mapToSource, mapBackOneStage, makeRenderConfig };
