#!/usr/bin/env node
// Prints the release notes of one version from CHANGELOG.md.
//
//   node scripts/release-notes.mjs <version> [CHANGELOG.md]
//
// A pre-release without a section of its own gets the Unreleased section.
import { readFileSync } from "node:fs";
import { pathToFileURL } from "node:url";

function section(changelog, name) {
  const lines = changelog.split("\n");
  const start = lines.findIndex((line) => line.match(/^## \[([^\]]+)\]/)?.[1].toLowerCase() === name.toLowerCase());
  if (start === -1) return null;
  const end = lines.findIndex((line, i) => i > start && line.startsWith("## "));
  return lines.slice(start + 1, end === -1 ? undefined : end).join("\n").trim();
}

export function releaseNotes(changelog, version) {
  const notes = section(changelog, version) || (version.includes("-") ? section(changelog, "Unreleased") : null);
  if (!notes) throw new Error(`CHANGELOG.md has no notes for ${version}`);
  return notes;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const [version, path = "CHANGELOG.md"] = process.argv.slice(2);
  if (!version) {
    console.error("usage: release-notes.mjs <version> [CHANGELOG.md]");
    process.exit(2);
  }
  try {
    console.log(releaseNotes(readFileSync(path, "utf8"), version));
  } catch (error) {
    console.error(`::error::${error.message}`);
    process.exit(1);
  }
}
