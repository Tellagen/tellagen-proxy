import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { mkdtempSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import nodeTest from "node:test";

// The contract of release.yml: what a tag publishes, in which order, with which
// credentials. Needs ruby on PATH to parse YAML.

const ruby = spawnSync("ruby", ["-v"], { encoding: "utf8" });
const test = (name, run) => nodeTest(name, { skip: ruby.status !== 0 && "ruby not on PATH" }, run);

const read = (path) => readFileSync(path, "utf8");
const source = read(".github/workflows/release.yml");
const workflow = ruby.status !== 0 ? { jobs: {}, on: {} } : (() => {
  const result = spawnSync("ruby", ["-rjson", "-ryaml", "-e", "puts JSON.generate(YAML.load(STDIN.read))"], { input: source, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const parsed = JSON.parse(result.stdout);
  return { ...parsed, on: parsed.on ?? parsed.true };
})();

const steps = (job) => workflow.jobs[job].steps;
const text = (job) => steps(job).map((step) => `${step.name ?? ""}\n${step.uses ?? ""}\n${step.run ?? ""}\n${JSON.stringify(step.with ?? {})}`).join("\n");
const stepUsing = (job, action) => steps(job).find((step) => step.uses?.startsWith(action));
const indexOf = (job, predicate) => steps(job).findIndex(predicate);

test("a v tag releases, a manual run is a dry run, and a pull request never releases", () => {
  assert.deepEqual(workflow.on.push.tags, ["v*"]);
  assert.equal(workflow.on.push.branches, undefined);
  assert.ok("workflow_dispatch" in workflow.on);
  assert.equal(workflow.on.pull_request, undefined);
  assert.equal(workflow.concurrency["cancel-in-progress"], false, "a release is never cancelled half way");
});

test("the checks of CI run first, and every publishing job needs them", () => {
  assert.equal(workflow.jobs.verify.uses, "./.github/workflows/ci.yml");
  assert.equal(workflow.jobs.verify.secrets, undefined, "the called workflow gets no secret");
  assert.deepEqual([].concat(workflow.jobs.release.needs), ["verify"]);
  assert.equal(workflow.jobs.release.if, "github.event_name == 'push' && startsWith(github.ref, 'refs/tags/v')");
  assert.deepEqual([].concat(workflow.jobs["github-release"].needs), ["release"]);
  assert.deepEqual([].concat(workflow.jobs["classic-repository"].needs), ["release"]);
});

test("the release job stops first unless the commit of the tag is on master", () => {
  const [checkout, check] = steps("release");
  assert.equal(checkout.with["fetch-depth"], 0);
  assert.equal(checkout.with["persist-credentials"], false);
  assert.match(check.name, /on master/);
  const git = (cwd, ...args) => {
    const result = spawnSync("git", ["-c", "user.name=t", "-c", "user.email=t@example.invalid", ...args], { cwd, encoding: "utf8" });
    assert.equal(result.status, 0, result.stderr);
    return result.stdout.trim();
  };
  const repo = mkdtempSync(join(tmpdir(), "release-"));
  try {
    git(repo, "init", "--quiet", "--initial-branch=master");
    git(repo, "commit", "--quiet", "--allow-empty", "-m", "first");
    git(repo, "update-ref", "refs/remotes/origin/master", "HEAD");
    const run = () => spawnSync("bash", ["-c", check.run], { cwd: repo, encoding: "utf8" });
    assert.equal(run().status, 0, "a commit on master passes");
    git(repo, "tag", "--annotate", "--message", "release", "v1.0.0");
    git(repo, "checkout", "--quiet", "--detach", "v1.0.0");
    assert.equal(run().status, 0, "an annotated tag on master passes");
    git(repo, "commit", "--quiet", "--allow-empty", "-m", "on a branch");
    const refused = run();
    assert.equal(refused.status, 1, "a commit off master stops the job");
    assert.match(refused.stdout, /is not on master/);
  } finally {
    rmSync(repo, { recursive: true, force: true });
  }
});

test("the tag is read through an environment variable, never pasted into a script", () => {
  const version = steps("release").find((step) => step.id === "version");
  assert.equal(version.env.TAG, "${{ github.ref_name }}");
});

test("moving major and minor tags go only to stable releases, and a bad tag is refused", () => {
  const version = steps("release").find((step) => step.id === "version").run;
  assert.match(version, /\[\[ -z "\$\{BASH_REMATCH\[5\]\}" \]\]/);
  const run = (tag) => {
    const dir = mkdtempSync(join(tmpdir(), "release-version-"));
    try {
      const outputFile = join(dir, "github-output");
      const output = spawnSync("bash", ["-c", `export TAG=${tag} GITHUB_OUTPUT=${outputFile}; touch "$GITHUB_OUTPUT"; ${version}`], { encoding: "utf8" });
      return { status: output.status, stdout: readFileSync(outputFile, "utf8"), stderr: output.stdout + output.stderr };
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
  assert.equal(run("v1.2.3").stdout, "version=1.2.3\ntags=1.2.3,1,1.2\n");
  assert.equal(run("v1.2.3-rc.1").stdout, "version=1.2.3-rc.1\ntags=1.2.3-rc.1\n");
  assert.equal(run("v1.0.0-beta.2").stdout, "version=1.0.0-beta.2\ntags=1.0.0-beta.2\n");
  assert.equal(run("v0.0.1").stdout, "version=0.0.1\ntags=0.0.1,0,0.0\n");
  for (const bad of ["v1.2", "v01.2.3", "vlatest", "v1.2.3+meta", "v1.2.3-", "1.2.3", "proxy-v1.2.3"]) {
    const result = run(bad);
    assert.equal(result.status, 1, bad);
    assert.match(result.stderr, /is not v<major>/);
  }
});

test("the notes are read before anything is logged in, built or pushed", () => {
  const notes = indexOf("release", (step) => /release-notes\.mjs "\$VERSION"/.test(step.run ?? ""));
  assert.ok(notes > 0, "the release job reads the notes");
  const firstPublish = indexOf("release", (step) => /docker\/(login|build-push)-action/.test(step.uses ?? ""));
  assert.ok(notes < firstPublish, "a stable tag without notes must fail before the first push");
  assert.equal(steps("release")[notes].env.VERSION, "${{ steps.version.outputs.version }}");
  assert.match(steps("release")[notes].run, /RELEASE-NOTES\.md/);
});

test("the release job holds no secret but the token of the run, and nothing mentions Docker Hub", () => {
  for (const job of ["verify", "dry-run", "github-release", "classic-repository"]) {
    assert.doesNotMatch(JSON.stringify(workflow.jobs[job]), /secrets\./, job);
  }
  assert.equal(workflow.jobs.release.environment, "release", "the release environment limits the job to v* tags");
  const names = [...JSON.stringify(workflow.jobs.release).matchAll(/secrets\.(\w+)/g)].map((match) => match[1]);
  assert.deepEqual([...new Set(names)], ["GITHUB_TOKEN"]);
  for (const path of [".github/workflows/ci.yml", ".github/workflows/release.yml", "README.md", "DESIGN.md", "CLAUDE.md", "CHANGELOG.md", "Dockerfile"]) {
    assert.doesNotMatch(read(path), /dockerhub|docker\.io|docker hub/i, path);
  }
  assert.equal(workflow.jobs.verify.environment, undefined);
  assert.equal(workflow.jobs["dry-run"].environment, undefined);
  assert.deepEqual(workflow.jobs["classic-repository"].environment, { name: "github-pages", url: "https://charts.tellagen.com" });
});

test("the dry run builds and packages and publishes nothing", () => {
  const job = workflow.jobs["dry-run"];
  assert.equal(job.if, "github.event_name == 'workflow_dispatch'");
  assert.equal(job.permissions, undefined);
  const build = stepUsing("dry-run", "docker/build-push-action");
  assert.equal(build.with.push, false);
  assert.equal(build.with.platforms, "linux/amd64,linux/arm64");
  assert.doesNotMatch(text("dry-run"), /login|cosign|helm push|helm registry|upload-pages|deploy-pages|gh release|imagetools create/);
  assert.match(text("dry-run"), /scripts\/package-chart\.sh 0\.0\.0-dry-run/);
});

test("the image is built for both platforms with an SBOM and max provenance, and pushed by digest", () => {
  const build = stepUsing("release", "docker/build-push-action");
  assert.equal(build.with.platforms, "linux/amd64,linux/arm64");
  assert.equal(build.with.sbom, true);
  assert.equal(build.with.provenance, "mode=max");
  assert.equal(build.with.push, true);
  assert.equal(build.with.context, ".");
  assert.equal(build.with.file, undefined, "the Dockerfile is in the root");
  assert.match(build.with["build-args"], /VERSION=\$\{\{ steps\.version\.outputs\.version \}\}/);
  assert.equal(build.with.tags, "${{ steps.refs.outputs.refs }}", "the moving tags are pushed with the image");
  assert.match(text("release"), /SBOM Provenance/);
  assert.match(text("release"), /jq -e 'type == "object" and length > 0'/);
});

test("the image is signed with cosign keyless and verified by the identity of this workflow", () => {
  const release = text("release");
  assert.match(release, /sigstore\/cosign-installer@[0-9a-f]{40}/);
  assert.match(release, /cosign sign --yes "\$\{IMAGE_GHCR\}@\$\{DIGEST\}"\n/);
  assert.match(release, /\[\[ "\$DIGEST" =~ \^sha256:\[0-9a-f\]\{64\}\$ \]\]/);
  assert.match(release, /"\$\{IMAGE_GHCR\}@\$\{DIGEST\}" >\/dev\/null/);
  assert.match(release, /cosign verify/);
  assert.match(release, /--certificate-identity "\$IDENTITY"/);
  assert.match(release, /--certificate-oidc-issuer https:\/\/token\.actions\.githubusercontent\.com/);
  assert.match(source, /IDENTITY: https:\/\/github\.com\/\$\{\{ github\.repository \}\}\/\.github\/workflows\/release\.yml@\$\{\{ github\.ref \}\}/);
  assert.doesNotMatch(source, /cosign sign[^\n]*--key|COSIGN_PRIVATE_KEY|COSIGN_PASSWORD/, "keyless only");
  assert.ok(indexOf("release", (step) => /cosign sign --yes/.test(step.run ?? "")) < indexOf("release", (step) => /cosign verify/.test(step.run ?? "")));
});

test("the registry is ghcr.io/tellagen only, with one login, and nothing is tagged latest", () => {
  assert.match(source, /IMAGE_GHCR: ghcr\.io\/tellagen\/tellagen-proxy/);
  assert.match(source, /CHART_GHCR: ghcr\.io\/tellagen\/charts/);
  assert.doesNotMatch(source, /:latest\b|tag.*latest/);
  assert.equal(steps("release").filter((step) => step.name?.startsWith("Mirror")).length, 0, "no second registry to mirror to");
  const logins = steps("release").filter((step) => step.uses?.startsWith("docker/login-action"));
  assert.equal(logins.length, 1, "one login, for ghcr.io");
  assert.equal(logins[0].with.registry, "ghcr.io");
  assert.equal(logins[0].with.password, "${{ secrets.GITHUB_TOKEN }}");
});

test("the image tags: a stable release also gets the major and minor tags, a pre-release never does", () => {
  const refs = steps("release").find((step) => step.id === "refs");
  assert.equal(refs.env.TAGS, "${{ steps.version.outputs.tags }}");
  assert.ok(indexOf("release", (step) => step.id === "refs") < indexOf("release", (step) => step.id === "build"));
  const run = (tags) => {
    const dir = mkdtempSync(join(tmpdir(), "release-refs-"));
    try {
      const outputFile = join(dir, "github-output");
      const output = spawnSync("bash", ["-c", `export TAGS=${tags} IMAGE_GHCR=ghcr.io/example/image GITHUB_OUTPUT=${outputFile}; touch "$GITHUB_OUTPUT"; ${refs.run}`], { encoding: "utf8" });
      assert.equal(output.status, 0, output.stderr);
      return readFileSync(outputFile, "utf8");
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  };
  assert.equal(run("1.2.3,1,1.2"), "refs=ghcr.io/example/image:1.2.3,ghcr.io/example/image:1,ghcr.io/example/image:1.2\n");
  assert.equal(run("1.2.3-rc.1"), "refs=ghcr.io/example/image:1.2.3-rc.1\n");
});

test("the chart gets the image digest and the release version, is pushed as an OCI chart, signed, and verified", () => {
  const release = text("release");
  assert.match(release, /scripts\/package-chart\.sh "\$VERSION" "\$DIGEST" "\$RUNNER_TEMP\/release"/);
  assert.match(release, /helm push .* "oci:\/\/\$\{CHART_GHCR\}"/);
  assert.match(release, /cosign sign --yes "\$\{CHART_GHCR\}\/tellagen-proxy@\$\{chart_digest\}"/);
  assert.match(release, /cosign verify[^]*"\$\{CHART_GHCR\}\/tellagen-proxy@\$\{chart_digest\}"/);
  const values = read("helm/tellagen-proxy/values.yaml");
  assert.equal(values.match(/^  digest: ""$/gm).length, 1, "exactly one empty digest line for the release to fill");
  const script = read("scripts/package-chart.sh");
  assert.match(script, /grep -c '\^  digest: ""\$'/);
  assert.match(script, /helm package .*--version "\$version" --app-version "\$version"/);
  assert.match(script, /helm lint .* --strict/);
  assert.ok(indexOf("release", (step) => /package-chart\.sh/.test(step.run ?? "")) > indexOf("release", (step) => /cosign verify/.test(step.run ?? "")), "the chart is packaged after the image is signed and verified");
});

test("the artifact keeps the chart, the SBOM, the provenance and the notes for 90 days", () => {
  const upload = stepUsing("release", "actions/upload-artifact");
  assert.equal(upload.with["if-no-files-found"], "error");
  assert.equal(upload.with["retention-days"], 90);
  assert.equal(workflow.jobs.release.outputs.version, "${{ steps.version.outputs.version }}");
});

test("the GitHub Release uses the notes of the changelog, marks a pre-release, and verifies the tag", () => {
  const job = workflow.jobs["github-release"];
  assert.deepEqual(job.permissions, { contents: "write" });
  const run = job.steps.find((step) => /gh release create/.test(step.run ?? ""));
  assert.match(run.run, /--verify-tag/);
  assert.match(run.run, /--notes-file "\$RUNNER_TEMP\/assets\/RELEASE-NOTES\.md"/);
  assert.match(run.run, /\[\[ "\$VERSION" == \*-\* \]\] && flags\+=\(--prerelease\)/);
  assert.match(run.run, /\[\[ "\$file" == \*\/RELEASE-NOTES\.md \]\] \|\| files\+=/);
  assert.equal(run.env.TAG, "${{ github.ref_name }}");
});

test("the classic repository merges the previous index and refuses to replace it unless the host says it has none", () => {
  const classic = text("classic-repository");
  assert.match(classic, /helm repo index .* --url https:\/\/charts\.tellagen\.com/);
  assert.match(classic, /--merge/);
  assert.match(classic, /upload-pages-artifact@[0-9a-f]{40}/);
  assert.match(classic, /deploy-pages@[0-9a-f]{40}/);
  assert.match(classic, /Not publishing without the previous index/);
  const step = steps("classic-repository").find((candidate) => candidate.name === "Add the chart to the published index");
  assert.match(step.run, /404\) rm -f/);
  assert.match(step.run, /\*\) echo "::error::.*exit 1/);
  assert.match(step.run, /cp "\$RUNNER_TEMP"\/new\/tellagen-proxy-\*\.tgz "\$site\/"/);
  assert.deepEqual(workflow.jobs["classic-repository"].permissions, { contents: "read", pages: "write", "id-token": "write" });
});
