#!/usr/bin/env node
// Checks a tellagen-proxy image that was built with `--output type=oci`:
// the compressed size, the user, the entry point, the binary, and the license
// files of every module the index lists. It reads the layers itself, so it needs
// no registry and no container runtime.
//
//   node scripts/image-check.mjs [--max-bytes N] <image.tar>...
import { readFileSync } from "node:fs";
import { gunzipSync } from "node:zlib";
import { pathToFileURL } from "node:url";

export const defaultMaxBytes = 30 * 1024 * 1024;
const requiredModule = /^github\.com\/grafana\/mcp-grafana\/v2@v[^/]+\/LICENSE$/;
const forbiddenLicense = /\b(AGPL|LGPL|GPL|SSPL)/;
const attestationAnnotation = "vnd.docker.reference.type";

// readTar lists the regular files of a tar archive. It reads ustar names with a
// prefix, GNU long names and PAX paths, which is what BuildKit writes.
export function readTar(buffer) {
  const files = new Map();
  let longName = null;
  let offset = 0;
  while (offset + 512 <= buffer.length) {
    const header = buffer.subarray(offset, offset + 512);
    if (header.every((byte) => byte === 0)) break;
    const field = (start, length) => header.toString("latin1", start, start + length).replace(/\0.*$/s, "");
    const size = parseInt(field(124, 12).trim() || "0", 8);
    const type = field(156, 1) || "0";
    const body = buffer.subarray(offset + 512, offset + 512 + size);
    offset += 512 + Math.ceil(size / 512) * 512;
    if (type === "L") {
      longName = body.toString("utf8").replace(/\0.*$/s, "");
      continue;
    }
    if (type === "x") {
      const path = body.toString("utf8").match(/\d+ path=([^\n]*)\n/);
      if (path) longName = path[1];
      continue;
    }
    const prefix = field(345, 155);
    let name = longName ?? (prefix ? `${prefix}/${field(0, 100)}` : field(0, 100));
    longName = null;
    name = name.replace(/^\.\//, "");
    if (type === "0" || type === "\0") files.set(name, { data: body, mode: parseInt(field(100, 8).trim() || "0", 8) });
  }
  return files;
}

function blob(image, digest) {
  const entry = image.get(`blobs/${digest.replace(":", "/")}`);
  if (!entry) throw new Error(`the archive has no blob ${digest}`);
  return entry.data;
}

// indexEntries parses THIRD-PARTY.txt into [{ module, version, licenses, files }].
export function indexEntries(text) {
  const entries = [];
  for (const block of text.split(/\n(?=\S)/).slice(1)) {
    const lines = block.split("\n");
    const head = lines[0].match(/^(\S+) (\S+)$/);
    // tools/licenses writes the key with this spelling.
    const licenses = lines.find((line) => line.trim().startsWith("licence:"));
    const files = lines.find((line) => line.trim().startsWith("files:"));
    if (!head || !licenses || !files) continue;
    entries.push({
      module: head[1],
      version: head[2],
      licenses: licenses.split(":")[1].trim(),
      files: files.split(":")[1].split(",").map((name) => name.trim()).filter(Boolean),
    });
  }
  return entries;
}

// checkImage returns { platform, bytes, problems } for one OCI archive.
export function checkImage(path, { maxBytes = defaultMaxBytes } = {}) {
  const problems = [];
  const image = readTar(readFileSync(path));
  const index = JSON.parse(image.get("index.json").data.toString("utf8"));
  const manifests = index.manifests.filter((entry) => !entry.annotations?.[attestationAnnotation]);
  if (manifests.length !== 1) return { platform: "unknown", bytes: 0, problems: [`${path}: expected one image manifest, found ${manifests.length}`] };
  const manifest = JSON.parse(blob(image, manifests[0].digest).toString("utf8"));
  const platform = manifests[0].platform ? `${manifests[0].platform.os}/${manifests[0].platform.architecture}` : "unknown";
  const label = `${path} (${platform})`;

  const bytes = manifest.layers.reduce((total, layer) => total + layer.size, manifest.config.size);
  if (bytes > maxBytes) problems.push(`${label}: compressed size is ${bytes} bytes, above the limit of ${maxBytes}`);

  const config = JSON.parse(blob(image, manifest.config.digest).toString("utf8"));
  if (config.config?.User !== "65532:65532") problems.push(`${label}: the user is ${JSON.stringify(config.config?.User)}, not 65532:65532`);
  if (JSON.stringify(config.config?.Entrypoint) !== JSON.stringify(["/tellagen-proxy"])) problems.push(`${label}: the entry point is not /tellagen-proxy`);

  const files = new Map();
  for (const layer of manifest.layers) {
    if (!layer.mediaType.endsWith("tar+gzip")) {
      problems.push(`${label}: a layer is ${layer.mediaType}, and this check reads gzip layers`);
      continue;
    }
    for (const [name, file] of readTar(gunzipSync(blob(image, layer.digest)))) files.set(name, file);
  }

  const binary = files.get("tellagen-proxy");
  if (!binary) problems.push(`${label}: /tellagen-proxy is missing`);
  else if ((binary.mode & 0o111) === 0) problems.push(`${label}: /tellagen-proxy is not executable`);
  for (const shell of ["bin/sh", "bin/bash", "bin/busybox", "usr/bin/apt"]) {
    if (files.has(shell)) problems.push(`${label}: the image holds /${shell}, and it must stay distroless`);
  }

  const indexFile = files.get("licenses/THIRD-PARTY.txt");
  if (!indexFile) {
    problems.push(`${label}: /licenses/THIRD-PARTY.txt is missing`);
    return { platform, bytes, problems };
  }
  const entries = indexEntries(indexFile.data.toString("utf8"));
  if (entries.length === 0) problems.push(`${label}: THIRD-PARTY.txt lists no module`);
  const shipped = [];
  for (const entry of entries) {
    if (forbiddenLicense.test(entry.licenses)) problems.push(`${label}: ${entry.module} is under ${entry.licenses}`);
    if (!entry.files.some((name) => /^(license|licence|copying|unlicense)/i.test(name))) problems.push(`${label}: ${entry.module} lists no license file`);
    for (const name of entry.files) {
      const where = `licenses/${entry.module}@${entry.version}/${name}`;
      shipped.push(where);
      const file = files.get(where);
      if (!file || file.data.length === 0) problems.push(`${label}: ${where} is missing or empty`);
    }
  }
  if (!shipped.some((where) => requiredModule.test(where.replace(/^licenses\//, "")))) {
    problems.push(`${label}: the Apache-2.0 license of grafana-mcp is not in the image`);
  }
  return { platform, bytes, problems };
}

function main(argv) {
  let maxBytes = defaultMaxBytes;
  const paths = [];
  for (let i = 0; i < argv.length; i++) {
    if (argv[i] === "--max-bytes") maxBytes = Number(argv[++i]);
    else paths.push(argv[i]);
  }
  if (paths.length === 0 || !Number.isInteger(maxBytes) || maxBytes <= 0) {
    console.error("usage: image-check.mjs [--max-bytes N] <image.tar>...");
    return 2;
  }
  let failed = false;
  for (const path of paths) {
    const result = checkImage(path, { maxBytes });
    console.log(`${result.platform}: ${(result.bytes / 1024 / 1024).toFixed(1)} MiB compressed`);
    for (const problem of result.problems) console.error(`::error::${problem}`);
    failed ||= result.problems.length > 0;
  }
  return failed ? 1 : 0;
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  process.exit(main(process.argv.slice(2)));
}
