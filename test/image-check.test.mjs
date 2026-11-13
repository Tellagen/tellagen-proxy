import assert from "node:assert/strict";
import { createHash } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";
import { gzipSync } from "node:zlib";

import { checkImage, indexEntries, readTar } from "../scripts/image-check.mjs";

function tarHeader(name, size, type, mode) {
  const header = Buffer.alloc(512);
  header.write(name, 0, 100, "latin1");
  header.write(mode.toString(8).padStart(7, "0"), 100, "latin1");
  header.write(size.toString(8).padStart(11, "0"), 124, "latin1");
  header.write(type, 156, "latin1");
  header.write("        ", 148, "latin1");
  let sum = 0;
  for (const byte of header) sum += byte;
  header.write(sum.toString(8).padStart(6, "0") + "\0 ", 148, "latin1");
  return header;
}

function padded(data) {
  return Buffer.concat([data, Buffer.alloc((512 - (data.length % 512)) % 512)]);
}

// makeTar writes a tar with GNU long names, as BuildKit does for long paths.
function makeTar(files) {
  const parts = [];
  for (const [name, { data, mode = 0o644 }] of Object.entries(files)) {
    const body = Buffer.from(data);
    if (name.length >= 100) {
      const long = Buffer.from(`${name}\0`);
      parts.push(tarHeader("././@LongLink", long.length, "L", 0), padded(long));
    }
    parts.push(tarHeader(name.slice(0, 99), body.length, "0", mode), padded(body));
  }
  parts.push(Buffer.alloc(1024));
  return Buffer.concat(parts);
}

const digestOf = (buffer) => `sha256:${createHash("sha256").update(buffer).digest("hex")}`;
const longModule = "go.opentelemetry.io/contrib/instrumentation/net/http/httptrace/otelhttptrace";

const goodIndex = [
  "Third-party software in tellagen-proxy",
  "Each folder next to this file holds the license text of one module.",
  "",
  "github.com/grafana/mcp-grafana/v2 v2.2.0",
  "  licence: Apache-2.0",
  "  files: LICENSE",
  `${longModule} v0.72.0`,
  "  licence: Apache-2.0",
  "  files: LICENSE",
  "go go1.26.10",
  "  licence: BSD-3-Clause",
  "  files: LICENSE, PATENTS",
  "",
].join("\n");

function goodFiles() {
  return {
    "tellagen-proxy": { data: "binary", mode: 0o755 },
    "licenses/THIRD-PARTY.txt": { data: goodIndex },
    "licenses/github.com/grafana/mcp-grafana/v2@v2.2.0/LICENSE": { data: "Apache License" },
    [`licenses/${longModule}@v0.72.0/LICENSE`]: { data: "Apache License" },
    "licenses/go@go1.26.10/LICENSE": { data: "BSD" },
    "licenses/go@go1.26.10/PATENTS": { data: "patents" },
  };
}

// buildImage writes an OCI archive the way `docker buildx build --output type=oci` does.
function buildImage(dir, { files = goodFiles(), user = "65532:65532", entrypoint = ["/tellagen-proxy"], extraManifest = false, layerSize } = {}) {
  const layer = gzipSync(makeTar(files));
  const config = Buffer.from(JSON.stringify({ architecture: "arm64", os: "linux", config: { User: user, Entrypoint: entrypoint } }));
  const manifest = Buffer.from(
    JSON.stringify({
      schemaVersion: 2,
      config: { mediaType: "application/vnd.oci.image.config.v1+json", digest: digestOf(config), size: config.length },
      layers: [{ mediaType: "application/vnd.oci.image.layer.v1.tar+gzip", digest: digestOf(layer), size: layerSize ?? layer.length }],
    }),
  );
  const manifests = [{ digest: digestOf(manifest), size: manifest.length, platform: { os: "linux", architecture: "arm64" } }];
  const blobs = { [digestOf(manifest)]: manifest, [digestOf(config)]: config, [digestOf(layer)]: layer };
  if (extraManifest) {
    const attestation = Buffer.from("{}");
    manifests.push({ digest: digestOf(attestation), size: 2, annotations: { "vnd.docker.reference.type": "attestation-manifest" } });
    blobs[digestOf(attestation)] = attestation;
  }
  const entries = { "index.json": { data: JSON.stringify({ schemaVersion: 2, manifests }) } };
  for (const [digest, data] of Object.entries(blobs)) entries[`blobs/${digest.replace(":", "/")}`] = { data };
  const path = join(dir, `image-${Math.random().toString(16).slice(2)}.tar`);
  writeFileSync(path, makeTar(entries));
  return path;
}

function withDir(run) {
  const dir = mkdtempSync(join(tmpdir(), "proxy-image-"));
  try {
    return run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

test("a good image passes and reports its platform and size", () =>
  withDir((dir) => {
    const result = checkImage(buildImage(dir));
    assert.deepEqual(result.problems, []);
    assert.equal(result.platform, "linux/arm64");
    assert.ok(result.bytes > 0);
  }));

test("an attestation manifest next to the image is ignored", () =>
  withDir((dir) => {
    assert.deepEqual(checkImage(buildImage(dir, { extraManifest: true })).problems, []);
  }));

test("an image above the size limit fails and names both numbers", () =>
  withDir((dir) => {
    const result = checkImage(buildImage(dir, { layerSize: 40 * 1024 * 1024 }));
    assert.equal(result.problems.length, 1);
    assert.match(result.problems[0], /compressed size is \d+ bytes, above the limit of 31457280/);
    assert.deepEqual(checkImage(buildImage(dir, { layerSize: 40 * 1024 * 1024 }), { maxBytes: 100 * 1024 * 1024 }).problems, []);
  }));

test("the user and the entry point are checked", () =>
  withDir((dir) => {
    const root = checkImage(buildImage(dir, { user: "0:0", entrypoint: ["/bin/sh"] }));
    assert.equal(root.problems.length, 2);
    assert.match(root.problems.join("\n"), /the user is "0:0"/);
    assert.match(root.problems.join("\n"), /entry point is not \/tellagen-proxy/);
  }));

test("a missing or non-executable binary fails", () =>
  withDir((dir) => {
    const files = goodFiles();
    files["tellagen-proxy"] = { data: "binary", mode: 0o644 };
    assert.match(checkImage(buildImage(dir, { files })).problems[0], /not executable/);
    delete files["tellagen-proxy"];
    assert.match(checkImage(buildImage(dir, { files })).problems[0], /\/tellagen-proxy is missing/);
  }));

test("a shell in the image fails", () =>
  withDir((dir) => {
    const files = { ...goodFiles(), "bin/sh": { data: "sh", mode: 0o755 } };
    assert.match(checkImage(buildImage(dir, { files })).problems[0], /must stay distroless/);
  }));

test("a license file named in the index but absent from the image fails", () =>
  withDir((dir) => {
    const files = goodFiles();
    delete files["licenses/go@go1.26.10/PATENTS"];
    const problems = checkImage(buildImage(dir, { files })).problems;
    assert.equal(problems.length, 1);
    assert.match(problems[0], /licenses\/go@go1\.26\.10\/PATENTS is missing or empty/);
  }));

test("a module with long path is found through its GNU long name", () =>
  withDir((dir) => {
    const files = goodFiles();
    delete files[`licenses/${longModule}@v0.72.0/LICENSE`];
    assert.match(checkImage(buildImage(dir, { files })).problems[0], /otelhttptrace@v0\.72\.0\/LICENSE is missing or empty/);
  }));

test("a GNU license in the index fails", () =>
  withDir((dir) => {
    const files = goodFiles();
    files["licenses/THIRD-PARTY.txt"] = { data: goodIndex.replace("licence: BSD-3-Clause", "licence: AGPL-3.0") };
    assert.match(checkImage(buildImage(dir, { files })).problems[0], /go is under AGPL-3\.0/);
  }));

test("the image must carry the Apache-2.0 license of grafana-mcp", () =>
  withDir((dir) => {
    const files = goodFiles();
    files["licenses/THIRD-PARTY.txt"] = { data: goodIndex.replace("github.com/grafana/mcp-grafana/v2 v2.2.0", "github.com/grafana/other v2.2.0") };
    delete files["licenses/github.com/grafana/mcp-grafana/v2@v2.2.0/LICENSE"];
    files["licenses/github.com/grafana/other@v2.2.0/LICENSE"] = { data: "Apache License" };
    assert.match(checkImage(buildImage(dir, { files })).problems.join("\n"), /Apache-2\.0 license of grafana-mcp is not in the image/);
  }));

test("a module that lists no license file fails", () =>
  withDir((dir) => {
    const files = goodFiles();
    files["licenses/THIRD-PARTY.txt"] = { data: goodIndex.replace("files: LICENSE, PATENTS", "files: PATENTS") };
    assert.match(checkImage(buildImage(dir, { files })).problems[0], /go lists no license file/);
  }));

test("an image with no index fails", () =>
  withDir((dir) => {
    const files = goodFiles();
    delete files["licenses/THIRD-PARTY.txt"];
    assert.match(checkImage(buildImage(dir, { files })).problems[0], /THIRD-PARTY\.txt is missing/);
  }));

test("readTar returns regular files and handles long names", () => {
  const files = readTar(makeTar({ [`licenses/${longModule}@v0.72.0/LICENSE`]: { data: "text" }, "a/b": { data: "x" } }));
  assert.equal(files.get(`licenses/${longModule}@v0.72.0/LICENSE`).data.toString(), "text");
  assert.equal(files.get("a/b").data.toString(), "x");
});

test("indexEntries reads modules, licenses and files", () => {
  const entries = indexEntries(goodIndex);
  assert.equal(entries.length, 3);
  assert.deepEqual(entries[2], { module: "go", version: "go1.26.10", licenses: "BSD-3-Clause", files: ["LICENSE", "PATENTS"] });
});
