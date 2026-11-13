import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";

const read = (path) => readFileSync(path, "utf8");
const dockerfile = read("Dockerfile");

test("the Dockerfile builds a static, stripped, trimmed binary on distroless as user 65532", () => {
  assert.match(dockerfile, /CGO_ENABLED=0/);
  assert.match(dockerfile, /-trimpath/);
  assert.match(dockerfile, /-ldflags="-s -w -X main\.version=\$\{VERSION\}"/);
  assert.match(dockerfile, /^ARG BASE_IMAGE=gcr\.io\/distroless\/static:nonroot@sha256:[0-9a-f]{64}$/m);
  assert.match(dockerfile, /^USER 65532:65532$/m);
  assert.match(dockerfile, /^ENTRYPOINT \["\/tellagen-proxy"\]$/m);
  assert.match(dockerfile, /COPY --from=build \/out\/licenses \/licenses/);
});

test("the build cross-compiles, so arm64 needs no emulation, and both base images are pinned by digest", () => {
  assert.match(dockerfile, /^FROM --platform=\$BUILDPLATFORM \$\{GO_IMAGE\} AS build$/m);
  assert.match(dockerfile, /^ARG GO_IMAGE=\S+@sha256:[0-9a-f]{64}$/m);
  assert.match(dockerfile, /GOOS=\$TARGETOS GOARCH=\$TARGETARCH/);
});

test("the Go version of the image build equals the module", () => {
  const goVersion = read("go.mod").match(/^go (\S+)$/m)[1];
  assert.match(dockerfile, new RegExp(`ARG GO_IMAGE=golang:${goVersion.replaceAll(".", "\\.")}-alpine`));
});

test("the build context holds only what the image needs", () => {
  const ignore = read(".dockerignore").split("\n");
  assert.equal(ignore.find((line) => !line.startsWith("#") && line !== ""), "*", "everything is out unless it is let in");
  for (const path of ["go.mod", "go.sum", "cmd", "internal", "protocol", "redact", "tools"]) assert.ok(ignore.includes(`!${path}`), path);
  for (const path of ["helm", ".github", "test", ".git"]) assert.ok(!ignore.includes(`!${path}`), path);
});
