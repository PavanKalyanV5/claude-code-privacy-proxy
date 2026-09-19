'use strict';
const { test } = require('node:test');
const assert = require('node:assert');
const { compile } = require('../rules');
const { redactWithSpans, makeLabel } = require('../spans');
const { mapOffset, rehydrate, translateEdit } = require('../resolve');

const K = Buffer.alloc(32, 13);
const RULES = compile({
  literals: ['Jane Q. Testerson'],
  patterns: [{ name: 'email', regex: '[A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\\.[A-Za-z]{2,24}', flags: 'gi' }],
});
const red = (t) => redactWithSpans(t, RULES, K);

test('mapOffset is identity before any span', () => {
  const r = red('xx jane.test@example.org yy');
  assert.strictEqual(mapOffset(0, r.spans), 0);
  assert.strictEqual(mapOffset(3, r.spans), 3);
});

test('mapOffset shifts by the length delta after a span', () => {
  const real = 'xx jane.test@example.org yy';
  const r = red(real);
  const s = r.spans[0];
  // The redacted end of the span maps to the real end of the span.
  assert.strictEqual(mapOffset(s.redEnd, r.spans), s.realEnd);
  // One char further on each side stays in step.
  assert.strictEqual(mapOffset(s.redEnd + 1, r.spans), s.realEnd + 1);
});

test('mapOffset refuses an offset strictly inside a span', () => {
  const r = red('xx jane.test@example.org yy');
  const s = r.spans[0];
  assert.strictEqual(mapOffset(s.redStart + 3, r.spans), null);
});

test('mapOffset accepts the exact span boundaries', () => {
  const r = red('xx jane.test@example.org yy');
  const s = r.spans[0];
  assert.strictEqual(mapOffset(s.redStart, r.spans), s.realStart);
  assert.strictEqual(mapOffset(s.redEnd, r.spans), s.realEnd);
});

test('rehydrate restores a label to its real value', () => {
  const real = 'contact jane.test@example.org here';
  const r = red(real);
  const label = makeLabel(K, 'email', 'jane.test@example.org');
  assert.strictEqual(rehydrate(`x ${label} y`, r.spans, K), 'x jane.test@example.org y');
});

test('rehydrate returns null when an unknown label survives', () => {
  const r = red('nothing here');
  assert.strictEqual(rehydrate('x [PII:email:deadbeefdeadbeef] y', r.spans, K), null);
});

test('rehydrate passes through text with no labels', () => {
  const r = red('nothing here');
  assert.strictEqual(rehydrate('plain text', r.spans, K), 'plain text');
});

test('translateEdit rewrites an edit spanning a redacted value', () => {
  const realText = 'const OWNER = "jane.test@example.org";\nconst X = 1;\n';
  const r = red(realText);
  const label = makeLabel(K, 'email', 'jane.test@example.org');

  const out = translateEdit({
    realText,
    redacted: r,
    oldString: `const OWNER = "${label}";`,
    newString: `const MAINTAINER = "${label}";`,
    kLabel: K,
  });

  assert.ok(out, 'expected a translation');
  assert.strictEqual(out.oldString, 'const OWNER = "jane.test@example.org";');
  assert.strictEqual(out.newString, 'const MAINTAINER = "jane.test@example.org";');
  // And it must actually apply to the real file.
  assert.ok(realText.includes(out.oldString));
});

test('translateEdit handles an edit with no redacted content', () => {
  const realText = 'const A = 1;\nconst B = 2;\n';
  const r = red(realText);
  const out = translateEdit({
    realText, redacted: r, oldString: 'const B = 2;', newString: 'const B = 3;', kLabel: K,
  });
  assert.ok(out);
  assert.strictEqual(out.oldString, 'const B = 2;');
  assert.strictEqual(out.newString, 'const B = 3;');
});

test('translateEdit refuses when old_string is not found', () => {
  const realText = 'const A = 1;\n';
  assert.strictEqual(
    translateEdit({ realText, redacted: red(realText), oldString: 'NOPE', newString: 'x', kLabel: K }),
    null
  );
});

test('translateEdit refuses when old_string is ambiguous', () => {
  const realText = 'dup\ndup\n';
  assert.strictEqual(
    translateEdit({ realText, redacted: red(realText), oldString: 'dup', newString: 'x', kLabel: K }),
    null
  );
});

test('translateEdit refuses when a boundary falls inside a redacted span', () => {
  const realText = 'mail jane.test@example.org now';
  const r = red(realText);
  const label = makeLabel(K, 'email', 'jane.test@example.org');
  // Slice into the middle of the label.
  const partial = label.slice(4);
  assert.strictEqual(
    translateEdit({ realText, redacted: r, oldString: partial, newString: 'x', kLabel: K }),
    null
  );
});

test('translateEdit refuses when new_string carries an unknown label', () => {
  const realText = 'const A = 1;\n';
  assert.strictEqual(
    translateEdit({
      realText, redacted: red(realText),
      oldString: 'const A = 1;',
      newString: 'const A = "[PII:email:0000000000000000]";',
      kLabel: K,
    }),
    null
  );
});

test('translateEdit survives multi-byte characters before the edit', () => {
  const realText = 'héllo → contact jane.test@example.org done';
  const r = red(realText);
  const label = makeLabel(K, 'email', 'jane.test@example.org');
  const out = translateEdit({
    realText, redacted: r,
    oldString: `contact ${label} done`,
    newString: `reach ${label} done`,
    kLabel: K,
  });
  assert.ok(out);
  assert.strictEqual(out.oldString, 'contact jane.test@example.org done');
  assert.ok(realText.includes(out.oldString));
});

test('property: a translated edit always applies cleanly to the real text', () => {
  const bodies = [
    'a jane.test@example.org b',
    'Jane Q. Testerson at jane.test@example.org',
    'line1\nline2 jane.test@example.org\nline3',
    'é jane.test@example.org é',
  ];
  for (const realText of bodies) {
    const r = red(realText);
    for (const s of r.spans) {
      const label = makeLabel(K, s.category, s.value);
      const out = translateEdit({
        realText, redacted: r, oldString: label, newString: 'REPLACED', kLabel: K,
      });
      assert.ok(out, `no translation for ${label} in ${realText}`);
      assert.ok(realText.includes(out.oldString), `old_string not in real text: ${out.oldString}`);
      assert.strictEqual(out.oldString, s.value);
    }
  }
});
