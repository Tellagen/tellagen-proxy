import assert from "node:assert/strict";
import test from "node:test";

import { releaseNotes } from "../scripts/release-notes.mjs";

const changelog = `# Changelog

## [Unreleased]

### Added

- A thing in progress.

## [1.0.0] - 2026-12-01

### Added

- The first release.

## [0.9.0] - 2026-11-01

- Older.
`;

test("a release gets its own section", () => {
  assert.equal(releaseNotes(changelog, "1.0.0"), "### Added\n\n- The first release.");
});

test("a pre-release without a section gets the Unreleased notes", () => {
  assert.match(releaseNotes(changelog, "1.1.0-rc.1"), /A thing in progress/);
});

test("a stable release without a section fails", () => {
  assert.throws(() => releaseNotes(changelog, "1.1.0"), /no notes for 1\.1\.0/);
});

test("an empty section fails", () => {
  assert.throws(() => releaseNotes("## [Unreleased]\n\n## [1.0.0]\n\n- x\n", "1.1.0-rc.1"), /no notes/);
});
