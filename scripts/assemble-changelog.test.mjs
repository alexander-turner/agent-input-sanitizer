import { test } from "node:test";
import assert from "node:assert/strict";
import {
  mkdtempSync,
  mkdirSync,
  writeFileSync,
  readFileSync,
  rmSync,
} from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import {
  CATEGORIES,
  RELEASE_MARKER,
  parseFragmentName,
  readFragments,
  renderBody,
  assembleBody,
  releaseChangelog,
  main,
} from "./assemble-changelog.mjs";

/** Make a throwaway working dir with a changelog.d/ holding the given fragments. */
function scratch(fragments = {}) {
  const cwd = mkdtempSync(join(tmpdir(), "changelog-"));
  const dir = join(cwd, "changelog.d");
  mkdirSync(dir);
  for (const [name, content] of Object.entries(fragments)) {
    writeFileSync(join(dir, name), content);
  }
  return {
    cwd,
    dir,
    cleanup: () => rmSync(cwd, { recursive: true, force: true }),
  };
}

const SEED_CHANGELOG = `# Changelog\n\n## Unreleased\n\n${RELEASE_MARKER}\n\n## [1.0.0] - 2026-01-01\n\n### Added\n\n- The first thing.\n`;

test("parseFragmentName accepts <id>.<category>.md and rejects everything else", () => {
  assert.deepEqual(parseFragmentName("592.fixed.md"), {
    id: "592",
    category: "fixed",
  });
  // ids may contain dots; the last category+md wins.
  assert.deepEqual(parseFragmentName("feat.x.added.md"), {
    id: "feat.x",
    category: "added",
  });
  assert.equal(parseFragmentName("README.md"), null);
  assert.equal(parseFragmentName("592.bogus.md"), null);
  assert.equal(parseFragmentName("592.fixed.txt"), null);
});

test("CATEGORIES is the Keep a Changelog set in order", () => {
  assert.deepEqual(CATEGORIES, [
    "added",
    "changed",
    "deprecated",
    "removed",
    "fixed",
    "security",
  ]);
});

test("readFragments skips README, sorts by category then id, and returns [] for a missing dir", () => {
  const { cwd, dir, cleanup } = scratch({
    "README.md": "ignored",
    "2.added.md": "- second added",
    "1.added.md": "- first added",
    "1.fixed.md": "- a fix",
  });
  try {
    const frags = readFragments(dir);
    assert.deepEqual(
      frags.map((f) => f.name),
      ["1.added.md", "2.added.md", "1.fixed.md"],
    );
    assert.deepEqual(readFragments(join(cwd, "does-not-exist")), []);
  } finally {
    cleanup();
  }
});

test("readFragments throws on an unrecognized filename", () => {
  const { dir, cleanup } = scratch({ "oops.md": "- x" });
  try {
    assert.throws(() => readFragments(dir), /not a valid fragment name/);
  } finally {
    cleanup();
  }
});

test("readFragments throws on an empty (whitespace-only) fragment", () => {
  const { dir, cleanup } = scratch({ "1.added.md": "   \n  " });
  try {
    assert.throws(() => readFragments(dir), /fragment is empty/);
  } finally {
    cleanup();
  }
});

test("renderBody groups by category in order and omits empty categories", () => {
  const body = renderBody([
    { category: "fixed", content: "- a fix" },
    { category: "added", content: "- a feature" },
    { category: "added", content: "- another feature" },
  ]);
  assert.equal(
    body,
    "### Added\n\n- a feature\n- another feature\n\n### Fixed\n\n- a fix",
  );
  assert.equal(renderBody([]), "");
});

test("assembleBody renders the fragments on disk", () => {
  const { dir, cleanup } = scratch({
    "1.added.md": "- a feature",
    "1.fixed.md": "- a fix",
  });
  try {
    assert.equal(
      assembleBody(dir),
      "### Added\n\n- a feature\n\n### Fixed\n\n- a fix",
    );
  } finally {
    cleanup();
  }
});

test("releaseChangelog inserts a section below the marker and deletes the fragments", () => {
  const { cwd, dir, cleanup } = scratch({
    "1.added.md": "- a feature",
    "1.fixed.md": "- a fix",
  });
  const changelogPath = join(cwd, "CHANGELOG.md");
  writeFileSync(changelogPath, SEED_CHANGELOG);
  try {
    const result = releaseChangelog({
      cwd,
      version: "1.1.0",
      date: "2026-02-02",
    });
    assert.equal(result.section, "## [1.1.0] - 2026-02-02");
    assert.deepEqual(result.removed.sort(), ["1.added.md", "1.fixed.md"]);
    const out = readFileSync(changelogPath, "utf8");
    // New section sits directly below the marker, above the older release.
    const marker = out.indexOf(RELEASE_MARKER);
    const newer = out.indexOf("## [1.1.0]");
    const older = out.indexOf("## [1.0.0]");
    assert.ok(marker < newer && newer < older);
    // Consumed fragments are gone (only README would remain; here none).
    assert.deepEqual(readFragments(dir), []);
  } finally {
    cleanup();
  }
});

test("releaseChangelog throws when there is nothing to release", () => {
  const { cwd, cleanup } = scratch();
  writeFileSync(join(cwd, "CHANGELOG.md"), SEED_CHANGELOG);
  try {
    assert.throws(
      () => releaseChangelog({ cwd, version: "1.1.0", date: "2026-02-02" }),
      /no entries/,
    );
  } finally {
    cleanup();
  }
});

test("releaseChangelog throws when the marker is missing", () => {
  const { cwd, cleanup } = scratch({ "1.added.md": "- a feature" });
  writeFileSync(join(cwd, "CHANGELOG.md"), "# Changelog\n\nno marker here\n");
  try {
    assert.throws(
      () => releaseChangelog({ cwd, version: "1.1.0", date: "2026-02-02" }),
      /missing the release marker/,
    );
  } finally {
    cleanup();
  }
});

test("main --check counts valid fragments with correct pluralization", () => {
  const one = scratch({ "1.added.md": "- x" });
  try {
    assert.equal(
      main(["--check"], { cwd: one.cwd }),
      "changelog.d: 1 fragment valid.",
    );
  } finally {
    one.cleanup();
  }
  const two = scratch({ "1.added.md": "- x", "2.fixed.md": "- y" });
  try {
    assert.equal(
      main(["--check"], { cwd: two.cwd }),
      "changelog.d: 2 fragments valid.",
    );
  } finally {
    two.cleanup();
  }
});

test("main --draft prints the assembled body", () => {
  const { cwd, cleanup } = scratch({ "1.added.md": "- a feature" });
  try {
    assert.equal(main(["--draft"], { cwd }), "### Added\n\n- a feature");
  } finally {
    cleanup();
  }
});

test("main --release rolls the changelog and reports what it removed", () => {
  const { cwd, cleanup } = scratch({ "1.added.md": "- a feature" });
  writeFileSync(join(cwd, "CHANGELOG.md"), SEED_CHANGELOG);
  try {
    const msg = main(["--release", "1.1.0", "--date", "2026-03-03"], { cwd });
    assert.equal(
      msg,
      "Released ## [1.1.0] - 2026-03-03; removed 1 fragment(s).",
    );
    assert.match(
      readFileSync(join(cwd, "CHANGELOG.md"), "utf8"),
      /## \[1\.1\.0\] - 2026-03-03/,
    );
  } finally {
    cleanup();
  }
});

test("main --release defaults the date to today (UTC) when --date is omitted", () => {
  const { cwd, cleanup } = scratch({ "1.added.md": "- a feature" });
  writeFileSync(join(cwd, "CHANGELOG.md"), SEED_CHANGELOG);
  try {
    const today = new Date().toISOString().slice(0, 10);
    const msg = main(["--release", "1.1.0"], { cwd });
    assert.equal(msg, `Released ## [1.1.0] - ${today}; removed 1 fragment(s).`);
  } finally {
    cleanup();
  }
});

test("main rejects misuse loudly", () => {
  assert.throws(() => main(["--release"]), /usage: assemble-changelog/);
  assert.throws(
    () => main(["--release", "--date"]),
    /usage: assemble-changelog/,
  );
  assert.throws(
    () => main(["--release", "1.1.0", "--date"]),
    /--date requires/,
  );
  assert.throws(
    () => main(["--release", "1.1.0", "2026-03-03"]),
    /unexpected argument/,
  );
  assert.throws(() => main([]), /usage: assemble-changelog/);
  assert.throws(() => main(["--bogus"]), /usage: assemble-changelog/);
});
