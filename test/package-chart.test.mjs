import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import test from "node:test";

const helm = spawnSync("helm", ["version"], { encoding: "utf8" });
const skip = helm.status !== 0 && "helm not on PATH";
const digest = `sha256:${"b".repeat(64)}`;

function withDir(run) {
  const dir = mkdtempSync(join(tmpdir(), "package-chart-"));
  try {
    return run(dir);
  } finally {
    rmSync(dir, { recursive: true, force: true });
  }
}

const unpack = (archive, file) => spawnSync("tar", ["-xzOf", archive, `tellagen-proxy/${file}`], { encoding: "utf8" }).stdout;

test("the package carries the release version and the image digest", { skip }, () =>
  withDir((dir) => {
    const result = spawnSync("scripts/package-chart.sh", ["1.2.3-rc.1", digest, dir], { encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    const archive = join(dir, "tellagen-proxy-1.2.3-rc.1.tgz");
    assert.match(unpack(archive, "Chart.yaml"), /^version: 1\.2\.3-rc\.1$/m);
    assert.match(unpack(archive, "Chart.yaml"), /^appVersion: 1\.2\.3-rc\.1$/m);
    assert.match(unpack(archive, "values.yaml"), new RegExp(`^  digest: "${digest}"$`, "m"));
  }));

test("a digest that is not a sha256 is refused", { skip }, () =>
  withDir((dir) => {
    const result = spawnSync("scripts/package-chart.sh", ["1.2.3", "latest", dir], { encoding: "utf8" });
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /digest must look like sha256/);
  }));
