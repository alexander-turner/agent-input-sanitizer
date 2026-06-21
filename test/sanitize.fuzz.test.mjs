/**
 * Crash-resistance / no-silent-suppression fuzz targets for `sanitize`.
 * Arbitrary bytes, lone surrogates, and huge inputs must never throw, and any
 * change to the text must carry a warning (content can never vanish silently).
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { sanitize } from "../src/index.mjs";
import { fcRunOptions, cp } from "./test-helpers.mjs";

const INVISIBLE_VALUES = [
  cp(0x200b),
  cp(0x200c),
  cp(0x200d),
  cp(0x2060),
  cp(0x00ad),
  cp(0xfeff),
  cp(0xfe0f),
  cp(0x3164),
  cp(0x2800),
  `${cp(0x1b)}[31m`,
  `${cp(0x1b)}[0m`,
];
const STRUCTURAL_TOKENS = [
  '<div style="display:none">',
  "</div>",
  "<span style='visibility:hidden'>",
  "</span>",
  '<a href="x">',
  "![](u?q=)",
  "[t](/p?c=)",
  "${x}",
  "!important",
  "<!-- c -->",
];

const unicodeChar = fc
  .integer({ min: 0, max: 0x10ffff })
  .filter((c) => c < 0xd800 || c > 0xdfff)
  .map((c) => String.fromCodePoint(c));
const loneSurrogate = fc
  .integer({ min: 0xd800, max: 0xdfff })
  .map((c) => String.fromCharCode(c));
const adversarialChar = fc.oneof(
  unicodeChar,
  loneSurrogate,
  fc.constantFrom(...STRUCTURAL_TOKENS, ...INVISIBLE_VALUES),
);
const adversarialInput = fc
  .array(adversarialChar, { maxLength: 300 })
  .map((parts) => parts.join(""));

// Benign body: digits + safe punctuation only — no letters (no HTML keyword
// can form), no invisible/ANSI triggers. Every layer is a guaranteed no-op.
const benignChar = fc.constantFrom(..."0123456789 .,-_/:#%@".split(""));
const benignInput = fc
  .array(benignChar, { minLength: 1, maxLength: 300 })
  .map((parts) => parts.join(""));

const scaleTo = (unit, length) => {
  let out = unit;
  while (out.length < length) out += unit;
  return out.slice(0, length);
};

describe("fuzz: crash resistance and no silent suppression", () => {
  it("never throws on arbitrary bytes / lone surrogates (html path)", async () => {
    await fc.assert(
      fc.asyncProperty(adversarialInput, async (input) => {
        const result = await sanitize(input, { html: true });
        assert.equal(typeof result.cleaned, "string");
        // Any change must be accompanied by a warning — content can never
        // vanish silently.
        if (result.cleaned !== input) assert.ok(result.warnings.length > 0);
      }),
      fcRunOptions({ numRuns: 150 }),
    );
  });

  it("passes benign non-empty input through unchanged (never silently empties it)", async () => {
    await fc.assert(
      fc.asyncProperty(benignInput, async (input) => {
        const result = await sanitize(input, { html: true });
        assert.equal(result.cleaned, input);
        assert.deepEqual(result.warnings, []);
        assert.ok(result.cleaned.length > 0);
      }),
      fcRunOptions({ numRuns: 100 }),
    );
  });

  it("processes a huge flat input without throwing", async () => {
    const huge = scaleTo("pre [t](/p?c=x) post _ok_ ", 50_000);
    const result = await sanitize(huge, { html: true });
    assert.equal(typeof result.cleaned, "string");
    assert.ok(result.cleaned.length > 0);
  });
});
