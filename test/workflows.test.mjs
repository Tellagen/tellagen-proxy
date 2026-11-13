import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readFileSync, readdirSync } from "node:fs";
import nodeTest from "node:test";

// The safety rules of the workflows that every file shares, and the contract of
// ci.yml. The release has its own file. Needs ruby on PATH to parse YAML.

const ruby = spawnSync("ruby", ["-v"], { encoding: "utf8" });
const test = (name, run) => nodeTest(name, { skip: ruby.status !== 0 && "ruby not on PATH" }, run);

const dir = ".github/workflows";
const read = (path) => readFileSync(path, "utf8");

export function parse(source) {
  const result = spawnSync("ruby", ["-rjson", "-ryaml", "-e", "puts JSON.generate(YAML.load(STDIN.read))"], { input: source, encoding: "utf8" });
  assert.equal(result.status, 0, result.stderr);
  const workflow = JSON.parse(result.stdout);
  // YAML 1.1 reads the bare `on` key as boolean true.
  return { ...workflow, on: workflow.on ?? workflow.true };
}

const files = readdirSync(dir).filter((name) => name.endsWith(".yml")).sort();
const sources = Object.fromEntries(files.map((name) => [name, read(`${dir}/${name}`)]));
const workflows = Object.fromEntries(files.map((name) => [name, ruby.status === 0 ? parse(sources[name]) : {}]));
const ci = workflows["ci.yml"];
const release = workflows["release.yml"];

const jobsOf = (workflow) => Object.entries(workflow.jobs);
const stepsOf = (workflow) => Object.values(workflow.jobs).flatMap((job) => job.steps ?? []);
const steps = (job) => ci.jobs[job].steps;
const textOf = (list) => list.map((step) => `${step.name ?? ""}\n${step.uses ?? ""}\n${step.run ?? ""}\n${JSON.stringify(step.with ?? {})}`).join("\n");
const stepUsing = (job, action) => steps(job).find((step) => step.uses?.startsWith(action));

test("the repository has exactly the CI and release workflows", () => {
  assert.deepEqual(files, ["ci.yml", "release.yml"]);
});

test("every action is pinned to a commit with a version comment, and local calls stay local", () => {
  for (const name of files) {
    const unpinned = [];
    for (const line of sources[name].split("\n")) {
      const match = line.match(/^\s*(?:-\s+)?uses:\s+([^\s#]+)(.*)$/);
      if (!match || match[1].startsWith("./")) continue;
      if (!/^[\w.-]+\/[\w./-]+@[0-9a-f]{40}$/.test(match[1]) || !/^\s+# v\d/.test(match[2])) unpinned.push(line.trim());
    }
    assert.deepEqual(unpinned, [], name);
  }
});

test("one action has one pin in both workflows", () => {
  const pins = new Map();
  for (const source of Object.values(sources)) {
    for (const [, action, sha] of source.matchAll(/uses:\s+([\w.-]+\/[\w./-]+)@([0-9a-f]{40})/g)) {
      assert.equal(pins.get(action) ?? sha, sha, `${action} has two different pins`);
      pins.set(action, sha);
    }
  }
  assert.ok(pins.size >= 10);
});

test("every job runs on a GitHub-hosted runner, because a public repository must not use a long-lived machine", () => {
  for (const name of files) {
    for (const [id, job] of jobsOf(workflows[name])) {
      if (!job.uses) assert.equal(job["runs-on"], "ubuntu-24.04", `${name}: ${id}`);
    }
  }
});

test("the default permission is read-only contents, and a job asks for more only by name", () => {
  const allowed = {
    release: { contents: "read", packages: "write", "id-token": "write" },
    "github-release": { contents: "write" },
    "classic-repository": { contents: "read", pages: "write", "id-token": "write" },
  };
  for (const name of files) {
    assert.deepEqual(workflows[name].permissions, { contents: "read" }, name);
    for (const [id, job] of jobsOf(workflows[name])) {
      if (job.permissions) assert.deepEqual(job.permissions, allowed[id], `${name}: ${id}`);
    }
  }
});

test("every job has a timeout, and every checkout drops its credentials", () => {
  for (const name of files) {
    for (const [id, job] of jobsOf(workflows[name])) {
      if (!job.uses) assert.ok(job["timeout-minutes"] > 0, `${name}: ${id} has no timeout`);
    }
    for (const step of stepsOf(workflows[name]).filter((s) => s.uses?.startsWith("actions/checkout@"))) {
      assert.equal(step.with?.["persist-credentials"], false, name);
    }
  }
});

test("a context value never reaches a shell script: the tag, the branch and the digest come through env", () => {
  for (const name of files) {
    for (const step of stepsOf(workflows[name])) {
      assert.doesNotMatch(step.run ?? "", /\$\{\{/, `${name}: ${step.name ?? step.run}`);
    }
  }
});

test("no workflow runs code of a pull request with secrets", () => {
  for (const name of files) assert.equal(workflows[name].on.pull_request_target, undefined, name);
  assert.equal(release.on.pull_request, undefined);
  assert.doesNotMatch(JSON.stringify(ci), /secrets\./);
  assert.equal(jobsOf(ci).some(([, job]) => job.environment), false);
  assert.doesNotMatch(textOf(stepsOf(ci)), /docker\/login-action|helm registry login|--push|push: true|cosign sign/, "CI logs in nowhere and pushes nothing");
});

test("CI runs on master and on pull requests, can be started by hand, and is callable by the release", () => {
  assert.deepEqual(ci.on.push.branches, ["master"]);
  assert.equal(ci.on.push.tags, undefined);
  assert.deepEqual(ci.on.pull_request.branches, ["master"]);
  assert.ok("workflow_dispatch" in ci.on);
  assert.ok("workflow_call" in ci.on);
  assert.equal(ci.concurrency["cancel-in-progress"], "${{ github.event_name == 'pull_request' }}");
});

test("the Go job runs gofmt, vet, golangci-lint and race tests with the version of go.mod", () => {
  const text = textOf(steps("go"));
  assert.match(text, /gofmt -l \./);
  assert.match(text, /go vet \.\/\.\.\./);
  assert.match(text, /golangci\/golangci-lint-action@[0-9a-f]{40}/);
  assert.match(text, /go test -race -count=1 \.\/\.\.\./);
  assert.equal(stepUsing("go", "actions/setup-go").with["go-version-file"], "go.mod");
  assert.match(stepUsing("go", "golangci/golangci-lint-action").with.version, /^v2\.\d+\.\d+$/);
});

test("the chart job lints the chart in every secret mode and runs the Node tests on Node 22", () => {
  const text = textOf(steps("chart"));
  assert.match(text, /for values in helm\/tellagen-proxy\/ci\/\*\.yaml/);
  assert.match(text, /helm lint helm\/tellagen-proxy --strict --values "\$values"/);
  assert.match(text, /node --test "test\/\*\.test\.mjs"/);
  assert.equal(stepUsing("chart", "actions/setup-node").with["node-version"], "22");
  assert.ok(stepUsing("chart", "azure/setup-helm"));
});

test("the image job builds both platforms without provenance, and checks size, user, binary and licenses", () => {
  const text = textOf(steps("image"));
  assert.match(text, /for platform in amd64 arm64/);
  assert.match(text, /--provenance=false --sbom=false/);
  assert.match(text, /type=oci,dest=/);
  assert.match(text, /node scripts\/image-check\.mjs --max-bytes "\$MAX_IMAGE_BYTES"/);
  assert.equal(ci.env.MAX_IMAGE_BYTES, String(30 * 1024 * 1024));
  assert.ok(stepUsing("image", "docker/setup-buildx-action"));
  assert.match(text, /docker buildx build --platform linux\/amd64 .*--load --tag tellagen-proxy:ci/s);
  assert.match(text, /test "\$\(docker run --rm tellagen-proxy:ci version\)" = "tellagen-proxy 0\.0\.0-ci"/);
  assert.doesNotMatch(text, /docker load/);
  assert.match(text, /--read-only --cap-drop ALL --security-opt no-new-privileges tellagen-proxy:ci doctor/);
  assert.match(text, /TELLAGEN_PROXY_TOKEN or TELLAGEN_PROXY_TOKEN_FILE is required/);
});

test("the kind job runs on a pull request that changes the chart, on a tag and by hand, and never waits for a rollout", () => {
  const job = ci.jobs.kind;
  assert.equal(job.needs, "changes");
  assert.match(job.if, /!cancelled\(\)/);
  assert.match(job.if, /github\.event_name == 'workflow_dispatch'/);
  assert.match(job.if, /startsWith\(github\.ref, 'refs\/tags\/'\)/);
  assert.match(job.if, /needs\.changes\.outputs\.helm == 'true'/);
  assert.equal(ci.jobs.changes.if, "github.event_name == 'pull_request'");
  assert.match(textOf(steps("changes")), /git diff --quiet "\$BASE" HEAD -- helm/);
  assert.equal(stepUsing("kind", "helm/kind-action").with.version, "v0.33.0");
  assert.match(textOf(steps("kind")), /helm\/tellagen-proxy\/ci\/kind-test\.sh tellagen-proxy kind/);
  const script = read("helm/tellagen-proxy/ci/kind-test.sh");
  assert.doesNotMatch(script, /rollout status[^\n]*tellagen-proxy/, "the proxy never turns ready without Tellagen");
  assert.match(script, /helm uninstall tellagen-proxy/);
  assert.match(script, /delete pod tellagen-proxy-doctor/);
});
