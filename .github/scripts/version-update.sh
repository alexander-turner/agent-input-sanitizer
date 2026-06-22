#!/usr/bin/env bash
# Post-merge release publish. After a push to the default branch, publish the
# GitHub Release for the new version when this push advanced package.json's
# version and the release is missing, using that version's CHANGELOG section as
# its notes. No git tag is pushed and no commit is made: `gh release create`
# creates the tag implicitly at the released commit, so the version bump merged
# via the PR stays the visible head. Pairs with release-prep.sh, which does the
# pre-merge bump. Release creation is idempotent, so a rerun after a transient
# failure simply backfills the release.
set -euo pipefail
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=../../bin/lib/retry.bash disable=SC1091
source "$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel)/bin/lib/retry.bash"

read_version() { node -e 'process.stdout.write(JSON.parse(require("fs").readFileSync(0, "utf8")).version)'; }

NEW_VERSION=$(read_version <package.json)
if ! [[ "$NEW_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "Error: package.json version is not strict X.Y.Z: $NEW_VERSION" >&2
  exit 1
fi

# Only release when this push changed the version, so an ordinary commit never
# retro-releases the standing version onto an unrelated commit.
if PREV=$(git show "HEAD~1:package.json" 2>/dev/null); then
  OLD_VERSION=$(printf '%s' "$PREV" | read_version)
else
  OLD_VERSION=""
fi
if [[ "$NEW_VERSION" == "$OLD_VERSION" ]]; then
  echo "Version unchanged ($NEW_VERSION). No release."
  exit 0
fi

if gh release view "v$NEW_VERSION" >/dev/null 2>&1; then
  echo "Release v$NEW_VERSION already exists. Nothing to do."
  exit 0
fi

# Publish the GitHub Release with the version's CHANGELOG section as its notes.
# The section was curated in the release PR (release-prep.sh rolls the fragments
# into it), so a missing section is a broken release flow — changelog-notes.sh
# fails loudly rather than publishing blank notes. `gh release create` creates
# the tag at this commit; --target pins it to the exact pushed SHA so a later
# push can't move it.
NOTES_FILE=$(mktemp)
trap 'rm -f "$NOTES_FILE"' EXIT
"$SCRIPT_DIR/changelog-notes.sh" "$NEW_VERSION" >"$NOTES_FILE"
if ! retry_cmd 4 2 gh release create "v$NEW_VERSION" --target "${GITHUB_SHA:-HEAD}" \
  --title "v$NEW_VERSION" --notes-file "$NOTES_FILE"; then
  echo "Error: failed to create release v$NEW_VERSION after 4 attempts" >&2
  exit 1
fi
echo "Published release v$NEW_VERSION"
