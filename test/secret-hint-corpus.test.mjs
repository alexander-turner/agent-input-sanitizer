import { describe, it } from "node:test";
import assert from "node:assert/strict";
import {
  SECRET_HINT,
  SECRET_HINT_EXT,
  matchesSecretHint,
} from "../src/gates.mjs";

/**
 * Mutation-coverage corpus: one realistic, minimal matching sample per
 * alternation arm of SECRET_HINT / SECRET_HINT_EXT. Each sample is built to
 * respect the arm's exact quantifiers, char classes, and lookbehind boundaries
 * so that "remove arm" / "negate char class" Stryker mutants flip at least one
 * case. A leading space pins lookbehind arms to a token boundary.
 */

// [label, sampleString] — every case MUST match (positive).
const POSITIVE_CASES = [
  // ── SECRET_HINT keyword arms ──────────────────────────────────────────────
  ["secret keyword", "secret"],
  ["token keyword", "token"],
  ["password keyword", "password"],
  ["passwd keyword", "passwd"],
  ["pwd keyword", "pwd"],
  ["bearer keyword", "bearer"],
  ["credential keyword", "credential"],
  ["authorization keyword", "authorization"],
  // contrase[nñ]a — BOTH spellings, so negating the class breaks one of them.
  ["contraseña with ñ", "contraseña"],
  ["contrasena with n", "contrasena"],
  ["BEGIN pem header", "-----BEGIN RSA PRIVATE KEY-----"],

  // (?:api|auth|service|account|db|database|priv|private|client|access)[_-]?key
  ["api_key prefix", "api_key"],
  ["auth-key prefix", "auth-key"],
  ["servicekey prefix", "servicekey"],
  ["account_key prefix", "account_key"],
  ["db-key prefix", "db-key"],
  ["database_key prefix", "database_key"],
  ["priv-key prefix", "priv-key"],
  ["private_key prefix", "private_key"],
  ["client-key prefix", "client-key"],
  ["access_key prefix", "access_key"],

  // (?:db|database|key)[_-]?pass
  ["db_pass prefix", "db_pass"],
  ["database-pass prefix", "database-pass"],
  ["keypass prefix", "keypass"],

  // (?:A3T|AKIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASIA)[A-Z0-9]{16}
  // [A-Z0-9] only, so an uppercase low-entropy fill (not the lowercase `a` used
  // elsewhere) satisfies the class while staying obviously synthetic.
  ["A3T access key id", "A3T" + "A".repeat(16)],
  ["AKIA access key id", "AKIA" + "A".repeat(16)],
  ["AGPA access key id", "AGPA" + "A".repeat(16)],
  ["AIDA access key id", "AIDA" + "A".repeat(16)],
  ["AROA access key id", "AROA" + "A".repeat(16)],
  ["AIPA access key id", "AIPA" + "A".repeat(16)],
  ["ANPA access key id", "ANPA" + "A".repeat(16)],
  ["ANVA access key id", "ANVA" + "A".repeat(16)],
  ["ASIA access key id", "ASIA" + "A".repeat(16)],

  // gh[pousr]_[A-Za-z0-9]
  ["ghp_ token", "ghp_A"],
  ["gho_ token", "gho_A"],
  ["ghu_ token", "ghu_A"],
  ["ghs_ token", "ghs_A"],
  ["ghr_ token", "ghr_A"],
  ["github_pat_ token", "github_pat_"],

  // gl[a-z]{2,12}-[0-9A-Za-z_-]{20}
  // Synthetic low-entropy fills throughout this file: a run of a single class-
  // legal char satisfies each arm's quantifier without resembling a real
  // credential (which trips push-protection secret scanners).
  ["gitlab pat", "glpat-" + "a".repeat(20)],

  ["sk-ant- prefix", "sk-ant-"],
  // AIza[0-9A-Za-z_-]{35}
  ["AIza google api key", "AIza" + "a".repeat(35)],
  ["sk_live_ stripe", "sk_live_"],
  ["sk_test_ stripe", "sk_test_"],
  ["rk_live_ stripe", "rk_live_"],
  ["rk_test_ stripe", "rk_test_"],

  // xox[bpasr]-
  ["xoxb- slack", "xoxb-"],
  ["xoxp- slack", "xoxp-"],
  ["xoxa- slack", "xoxa-"],
  ["xoxs- slack", "xoxs-"],
  ["xoxr- slack", "xoxr-"],

  // eyJ[A-Za-z0-9]
  ["JWT eyJ header", "eyJ" + "a".repeat(8)],

  // do[opr]_v1_[a-f0-9]{16}
  ["digitalocean dop_v1", "dop_v1_" + "a".repeat(16)],
  ["digitalocean doo_v1", "doo_v1_" + "a".repeat(16)],
  ["digitalocean dor_v1", "dor_v1_" + "a".repeat(16)],

  // v1\.0-[a-f0-9]{24}-
  ["v1.0- token", "v1.0-" + "a".repeat(24) + "-"],

  // hv[sb]\.[A-Za-z0-9_-]{20}
  ["vault hvs token", "hvs." + "a".repeat(20)],
  ["vault hvb token", "hvb." + "a".repeat(20)],

  // (?<![a-z0-9])[a-z0-9]{14}\.atlasv1\.
  ["mongodb atlasv1", " " + "a".repeat(14) + ".atlasv1."],

  // sk-or-v1-[0-9a-f]{16}
  ["openrouter sk-or-v1", "sk-or-v1-" + "a".repeat(16)],
  // gsk_[A-Za-z0-9]{16}
  ["groq gsk_ token", "gsk_" + "a".repeat(16)],
  // xai-[A-Za-z0-9]{16}
  ["xai- token", "xai-" + "a".repeat(16)],
  // r8_[A-Za-z0-9]{16}
  ["replicate r8_ token", "r8_" + "a".repeat(16)],

  // ── SECRET_HINT_EXT arms ──────────────────────────────────────────────────
  // (?:AC|SK)[a-z0-9]{32}
  ["twilio AC sid", "AC" + "a".repeat(32)],
  ["twilio SK sid", "SK" + "a".repeat(32)],

  // SG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}
  ["sendgrid SG. token", "SG." + "a".repeat(22) + "." + "a".repeat(43)],

  // sq0csp-[0-9A-Za-z_-]{43}
  ["square sq0csp", "sq0csp-" + "a".repeat(43)],

  // (?<![0-9])[0-9]{8,10}:[0-9A-Za-z_-]{35}
  ["telegram bot token", " " + "1".repeat(8) + ":" + "a".repeat(35)],

  // (?<![0-9a-z])[0-9a-z]{32}-us[0-9]{1,2}
  ["mailchimp api key", " " + "a".repeat(32) + "-us1"],

  // (?<![A-Za-z0-9_-])[MNO][A-Za-z0-9_-]{23,25}\.[A-Za-z0-9_-]{6}\.[A-Za-z0-9_-]{27}
  [
    "discord bot token",
    " M" + "a".repeat(23) + "." + "a".repeat(6) + "." + "a".repeat(27),
  ],

  ["openai org T3BlbkFJ", "T3BlbkFJ"],
  ["pypi-AgE token", "pypi-AgE"],

  // (?<![A-Za-z0-9])AKC[A-Za-z0-9]{10}
  ["AKC token", " AKC" + "a".repeat(10)],

  // (?<![A-Za-z0-9])AP[0-9A-Fa-f][A-Za-z0-9]{8}
  ["AP hex token", " AP0" + "a".repeat(8)],

  // :\/\/[^\s:/@]{1,64}:[^\s:/@]{1,64}@
  ["url userinfo creds", "https://user:p4ssword@host"],

  // (?:key|pw|pass)["']?[\s:=>]+["']?[A-Za-z0-9_/+-]{20}
  ["key= value", "key=" + "a".repeat(20)],
  ["pw: value", "pw: " + "a".repeat(20)],
  ["pass => value", 'pass => "' + "a".repeat(20)],
];

// Ordinary prose / filenames that must NOT match any arm.
const NEGATIVE_CASES = [
  ["plain greeting", "hello world"],
  ["ordinary filename", "ordinary-file-name.txt"],
  ["short alnum", "abc123"],
  ["lorem ipsum", "lorem ipsum dolor sit amet"],
];

describe("SECRET_HINT / SECRET_HINT_EXT arm corpus", () => {
  for (const [label, sample] of POSITIVE_CASES) {
    it(`matches: ${label}`, () => {
      assert.equal(
        SECRET_HINT.test(sample) || SECRET_HINT_EXT.test(sample),
        true,
        label,
      );
      assert.equal(matchesSecretHint(sample), true, label);
    });
  }

  for (const [label, sample] of NEGATIVE_CASES) {
    it(`rejects: ${label}`, () => {
      assert.equal(
        SECRET_HINT.test(sample) || SECRET_HINT_EXT.test(sample),
        false,
        label,
      );
      assert.equal(matchesSecretHint(sample), false, label);
    });
  }
});
