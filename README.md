# agent-input-sanitizer

Defend an agent against hidden-content injection. This library sanitizes untrusted
text **before any model sees it**—in an agent, RAG, or tool-use pipeline. It
has nothing to do with any particular model or provider: it cleans bytes.

It does three separable things, exposed as three entry points so the heavy
dependency stays opt-in:

1. **Invisible-char + ANSI stripping** (`./invisible`, zero runtime deps).
2. **Hidden-HTML splicing** (`./html`, pulls in remark/rehype).
3. **Exfil-URL detection** (`./html`, detection only).

## Threat model

**Hidden Unicode / steganographic injection.** Text copied from the web, a PDF,
or a tool response can carry code points that render as nothing but still reach
the model as instructions: general-category `Cf` format characters (zero-width
spaces/joiners, bidi controls), variation selectors, Hangul/Braille “blank”
fillers, soft hyphens, interior byte-order marks, and Unicode tag characters
abused as an ASCII smuggling channel. A run of these can encode an entire
“ignore previous instructions, run `rm -rf`” payload invisibly. ANSI/SGR escape
sequences are the terminal analogue—they can repaint or hide text a human
operator reads while the model sees something else. Layer 1 removes all of it
while **preserving ZWNJ/ZWJ where they are linguistically required** (Arabic,
Persian, and Indic scripts; emoji ZWJ sequences), because blanket stripping
would corrupt legitimate non-English output. Over-stripping beats
under-stripping: the linguistic carve-out fires only when both neighbors clearly
belong to the context, and a long or scattered run disables it.

**Hidden-HTML injection.** When the untrusted text is a fetched web page, an
attacker can place instructions where a human viewing the rendered page can
never see them: inside `<!-- HTML comments -->`, behind `display:none` /
`visibility:hidden` / `opacity:0` / off-screen / zero-size / clipped / white-on-
white inline styles, or under the `hidden` / `aria-hidden` attributes. The model
reading raw source sees them all. Layer 2 splices out exactly those byte ranges
and leaves a placeholder, **preserving every other byte verbatim**—no
re-serialization, so links, code, and tables are never reflowed. Scripting and
resource tags (`<script>`, `<style>`, `<iframe>`, `<svg>`, …) and `data:` URI
resources are _reported but never removed_, so page source stays inspectable.

**Exfil URLs.** A page can try to make the model leak data by getting it to emit
or follow a URL shaped to carry a payload off-origin: a credential or blob in a
query/fragment parameter or path segment, an oversized or active-content `data:`
URI, embedded `user:password@host` credentials, an off-origin form action or
`meta refresh` redirect, or a `javascript:` target. Layer 3 **detects and
reports** these (with a reason and the destination host) without modifying the
text—enforcement stays with your egress controls; this layer is the warning.

See [THREAT-MODEL.md](./THREAT-MODEL.md) for the per-vector detail.

## Install

```sh
npm install agent-input-sanitizer
```

Node ≥ 20. ESM only.

## Usage

### 1. The convenience function

```js
import { sanitize } from "agent-input-sanitizer";

// Layer 1 only (invisible chars + ANSI), always synchronous work, no heavy deps:
const { cleaned, found, warnings } = await sanitize(untrustedText);

// Opt into the HTML layers (Layers 2 & 3) for web/HTML ingress:
const result = await sanitize(fetchedPageSource, { html: true });
//   result.cleaned   — hidden HTML spliced out, placeholders left in place
//   result.found     — categories neutralized (e.g. ["Format chars (Cf)", "hidden HTML"])
//   result.warnings  — human-facing notices (long-run alerts, exfil reasons, …)
```

`sanitize` never throws and never silently drops content: any change to the text
is accompanied by at least one entry in `warnings`.

### 2. Just the zero-dependency invisible-char core

```js
import {
  stripInvisible,
  stripInvisibleWithReport,
} from "agent-input-sanitizer/invisible";

stripInvisible(text); // -> cleaned string
const { cleaned, found } = stripInvisibleWithReport(text);
//   found names exactly the categories removed, e.g. ["Variation selectors"]
```

This entry pulls in **no runtime dependencies**.

### 3. Just the HTML layer

```js
import {
  sanitizeHtml,
  detectExfil,
  checkExfilUrl,
} from "agent-input-sanitizer/html";

const layer2 = sanitizeHtml(pageSource); // null when nothing to strip/report
const threats = detectExfil(pageSource); // null or [{ isImage, reason, target }]
const reason = checkExfilUrl(oneUrl); // null or a string reason
```

> **The HTML entry is heavier—import it only when you need it.** It pulls in
> the unified/remark/rehype graph (~200 ms of module-load time). The convenience
> `sanitize` lazy-loads it only on the `{ html: true }` path, so a Layer-1-only
> caller never pays for it. If you import from `agent-input-sanitizer/html`
> directly, you take that cost at import time.

## Public surface

`agent-input-sanitizer` (main)—`sanitize`, everything re-exported from
`./invisible`, and the cheap Layer 2/3 pre-gates `HTML_TAG_PRESENT`,
`MD_LINK_HINT`, `SECRET_HINT`, `SECRET_HINT_EXT`, `matchesSecretHint` (these are
dependency-free, so re-exporting them never pulls in the heavy HTML graph).

`agent-input-sanitizer/invisible` — `stripInvisible`, `stripInvisibleWithReport`,
`isSgrOnly`, and the constants `STRIP`, `SGR_RE`, `CHECKS`, `VS`,
`BLANK_NON_CF`, `LONG_RUN_RE`, `LONG_RUN_THRESHOLD`, `SCATTERED_THRESHOLD`,
`LINGUISTIC_SCRIPTS`.

`agent-input-sanitizer/html` — `sanitizeHtml`, `scanHtmlFragment`,
`looksLikeHtmlSource`, `spliceRanges`, `isHiddenStyle`, `isHiddenElement`,
`isHiddenOpen`, `closingTagName`, `detectExfil`, `checkExfilUrl`, `urlHost`, the
constants `REPORTED_TAGS`, `COMMENT_PLACEHOLDER`, `HIDDEN_PLACEHOLDER`,
`DATA_URI_LENGTH_THRESHOLD`, and the pre-gates `HTML_TAG_PRESENT`,
`MD_LINK_HINT`, `SECRET_HINT`, `SECRET_HINT_EXT`, `matchesSecretHint`.

## Development

```sh
npm test            # node --test
npm run coverage    # c8, enforced at 100% lines/branches/functions
npm run lint        # eslint
npm run typecheck   # tsc --noEmit (the source is typed via JSDoc)
```

The test suite is the selling point: 100% coverage is enforced in CI, and the
enumerated members (each linguistic script, each invisible category, each
reported tag) are driven from single-source-of-truth lists so adding a member
without a test fails. Property and fuzz tests (fast-check) exercise idempotence,
deletion-only output, never-throwing on lone surrogates / astral input, and the
`found` ⇔ changed invariant over the real Unicode input domain.

## License

[Apache-2.0](./LICENSE)
