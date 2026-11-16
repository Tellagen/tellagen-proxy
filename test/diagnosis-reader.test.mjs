import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { readdirSync } from "node:fs";
import nodeTest from "node:test";

// Renders the diagnosis-reader chart and checks what it can grant. The role is
// the point of the chart, so these tests read every rule it can render. They
// need helm and ruby (to parse YAML) on PATH and skip with a message otherwise.

const tools = { helm: ["version"], ruby: ["-v"] };
const missing = Object.keys(tools).filter((command) => spawnSync(command, tools[command], { encoding: "utf8" }).status !== 0);
const test = (name, run) => nodeTest(name, { skip: missing.length > 0 && `${missing.join(" and ")} not on PATH` }, run);

const chart = "helm/diagnosis-reader";
const allowedVerbs = new Set(["get", "list", "watch"]);
const neverGranted = ["secrets", "configmaps", "pods/exec", "pods/attach", "pods/portforward", "serviceaccounts", "tokenreviews", "*"];

function helm(args) {
  return spawnSync("helm", ["template", "diagnosis-reader", chart, "--namespace", "tools", "--kube-version", "1.30.0", ...args], { encoding: "utf8" });
}

function render(args = []) {
  const result = helm(args);
  assert.equal(result.status, 0, result.stderr);
  const ruby = spawnSync("ruby", ["-rjson", "-ryaml", "-e", "puts JSON.generate(YAML.load_stream(STDIN.read))"], { encoding: "utf8", input: result.stdout });
  assert.equal(ruby.status, 0, ruby.stderr);
  return JSON.parse(ruby.stdout).filter(Boolean);
}

const isHook = (doc) => Boolean(doc.metadata.annotations?.["helm.sh/hook"]);
const installed = (docs) => docs.filter((doc) => !isHook(doc));
const ofKind = (docs, kind) => docs.filter((doc) => doc.kind === kind);
const sets = (values) => Object.entries(values).flatMap(([key, value]) => ["--set-json", `${key}=${JSON.stringify(value)}`]);

const variants = {
  "route A cluster": [],
  "route B cluster": sets({ "bind.serviceAccount": true }),
  "route B only": sets({ "bind.groups": [], "bind.serviceAccount": true }),
  "route A namespaces": sets({ scope: "namespaces", namespaces: ["a", "b"] }),
  "route B namespaces": sets({ scope: "namespaces", namespaces: ["a", "b"], "bind.serviceAccount": true }),
  "no logs, no metrics": sets({ "read.podLogs": false, "read.metrics": false }),
};

const readRules = (docs) => installed(docs).filter((doc) => doc.kind === "ClusterRole" || (doc.kind === "Role" && doc.rules.some((rule) => !rule.resources.includes("serviceaccounts/token")))).flatMap((doc) => doc.rules);

for (const [name, args] of Object.entries(variants)) {
  test(`${name}: the read role holds get, list and watch only, and never a secret, a shell or a wildcard`, () => {
    const rules = readRules(render(args));
    assert.ok(rules.length > 0);
    for (const rule of rules) {
      for (const verb of rule.verbs) assert.ok(allowedVerbs.has(verb), `verb ${verb}`);
      for (const resource of rule.resources) assert.ok(!neverGranted.includes(resource), `resource ${resource}`);
      assert.deepEqual(rule.apiGroups.filter((group) => group === "*"), []);
      assert.equal(rule.resourceNames, undefined);
    }
  });
}

test("the cluster scope makes one ClusterRole and one binding, and nothing namespaced", () => {
  const docs = installed(render());
  assert.deepEqual(docs.map((doc) => doc.kind).sort(), ["ClusterRole", "ClusterRoleBinding"]);
  const binding = ofKind(docs, "ClusterRoleBinding")[0];
  assert.deepEqual(binding.subjects, [{ kind: "Group", name: "tellagen-diagnosis", apiGroup: "rbac.authorization.k8s.io" }]);
  assert.equal(binding.roleRef.name, ofKind(docs, "ClusterRole")[0].metadata.name);
});

test("the namespaces scope makes a Role and a RoleBinding in each namespace, and no ClusterRole", () => {
  const docs = installed(render(variants["route A namespaces"]));
  assert.deepEqual(ofKind(docs, "ClusterRole"), []);
  assert.deepEqual(ofKind(docs, "ClusterRoleBinding"), []);
  assert.deepEqual(ofKind(docs, "Role").map((doc) => doc.metadata.namespace).sort(), ["a", "b"]);
  assert.deepEqual(ofKind(docs, "RoleBinding").map((doc) => doc.metadata.namespace).sort(), ["a", "b"]);
  const resources = readRules(docs).flatMap((rule) => rule.resources);
  for (const clusterOwned of ["nodes", "namespaces", "persistentvolumes"]) assert.ok(!resources.includes(clusterOwned), clusterOwned);
});

test("the cluster scope reads nodes and their metrics", () => {
  const resources = readRules(render()).flatMap((rule) => rule.resources);
  for (const resource of ["nodes", "namespaces", "pods", "pods/log", "events"]) assert.ok(resources.includes(resource), resource);
});

test("read.podLogs and read.metrics each remove their rules", () => {
  const resources = readRules(render(variants["no logs, no metrics"])).flatMap((rule) => rule.resources);
  assert.ok(!resources.includes("pods/log"));
  assert.ok(resources.includes("pods"));
  const groups = readRules(render(variants["no logs, no metrics"])).flatMap((rule) => rule.apiGroups);
  assert.ok(!groups.includes("metrics.k8s.io"));
  assert.ok(readRules(render()).flatMap((rule) => rule.apiGroups).includes("metrics.k8s.io"));
});

test("route B makes a service account, binds it, and lets the groups create its token and nothing else", () => {
  const docs = installed(render(variants["route B cluster"]));
  const account = ofKind(docs, "ServiceAccount")[0];
  assert.equal(account.automountServiceAccountToken, false);
  assert.equal(account.metadata.namespace, "tools");
  assert.deepEqual(ofKind(docs, "ClusterRoleBinding")[0].subjects.at(-1), { kind: "ServiceAccount", name: account.metadata.name, namespace: "tools" });
  const tokenRole = ofKind(docs, "Role")[0];
  assert.deepEqual(tokenRole.rules, [{ apiGroups: [""], resources: ["serviceaccounts/token"], resourceNames: [account.metadata.name], verbs: ["create"] }]);
  const tokenBinding = ofKind(docs, "RoleBinding")[0];
  assert.deepEqual(tokenBinding.subjects, [{ kind: "Group", name: "tellagen-diagnosis", apiGroup: "rbac.authorization.k8s.io" }]);
});

test("route B without a group makes no token role, because nobody could use it", () => {
  const docs = installed(render(variants["route B only"]));
  assert.deepEqual(ofKind(docs, "Role"), []);
  assert.equal(ofKind(docs, "ServiceAccount").length, 1);
});

test("route A makes no service account", () => {
  assert.deepEqual(ofKind(installed(render()), "ServiceAccount"), []);
});

test("the Helm test asks the four questions as the bound subject and cleans up after itself", () => {
  const hooks = render(variants["route B cluster"]).filter(isHook);
  assert.deepEqual(hooks.map((doc) => doc.kind).sort(), ["ClusterRole", "ClusterRoleBinding", "Pod", "ServiceAccount"]);
  for (const doc of hooks) assert.equal(doc.metadata.annotations["helm.sh/hook"], "test");
  for (const doc of hooks) assert.match(doc.metadata.annotations["helm.sh/hook-delete-policy"], /hook-succeeded/);
  const script = hooks.find((doc) => doc.kind === "Pod").spec.containers[0].args[0];
  for (const check of ["check yes", "list pods", "delete pods", "get secrets", "--subresource=exec", "--subresource=log"]) assert.ok(script.includes(check), check);
  assert.match(script, /"group:tellagen-diagnosis"/);
  assert.match(script, /"serviceaccount:tools:diagnosis-reader"/);
  const impersonation = hooks.find((doc) => doc.kind === "ClusterRole").rules;
  assert.ok(impersonation.every((rule) => rule.verbs.length === 1 && rule.verbs[0] === "impersonate" && rule.resourceNames?.length > 0));
});

test("the Helm test expects no log access when the logs are off", () => {
  const pod = render(variants["no logs, no metrics"]).find((doc) => doc.kind === "Pod");
  assert.match(pod.spec.containers[0].args[0], /check no "\$subject" "\$scope" get pods --subresource=log/);
});

test("the Helm test pod meets the restricted Pod Security profile", () => {
  const pod = render().find((doc) => doc.kind === "Pod");
  assert.equal(pod.spec.securityContext.runAsNonRoot, true);
  assert.equal(pod.spec.securityContext.seccompProfile.type, "RuntimeDefault");
  const security = pod.spec.containers[0].securityContext;
  assert.equal(security.allowPrivilegeEscalation, false);
  assert.deepEqual(security.capabilities.drop, ["ALL"]);
});

const refused = {
  "an unknown key at the top": ["--set-json", 'rules=[{"verbs":["delete"]}]'],
  "an unknown key under bind": ["--set-json", "bind.verbs=[\"delete\"]"],
  "an unknown key under read": ["--set-json", "read.secrets=true"],
  "a scope that does not exist": ["--set", "scope=everything"],
  "a group that is not a list": ["--set", "bind.groups=oncall"],
  "a group with shell characters": sets({ "bind.groups": ["a$(id)"] }),
  "a name override with a newline": sets({ nameOverride: "a\nb" }),
  "a namespace that is not a name": sets({ scope: "namespaces", namespaces: ["Not A Name"] }),
};
for (const [name, args] of Object.entries(refused)) {
  test(`values.schema.json refuses ${name}`, () => {
    const result = helm(args);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, /values don't meet the specifications of the schema/);
  });
}

const stopped = {
  "nothing is bound": [sets({ "bind.groups": [] }), /Nothing is bound/],
  "a group that holds everybody": [sets({ "bind.groups": ["system:authenticated"] }), /starts with system:/],
  "a system group of nodes": [sets({ "bind.groups": ["system:nodes"] }), /starts with system:/],
  "namespaces scope without a namespace": [["--set", "scope=namespaces"], /list at least one namespace/],
  "namespaces under the cluster scope": [sets({ namespaces: ["a"] }), /scope is cluster|Set scope to namespaces/],
};
for (const [name, [args, message]] of Object.entries(stopped)) {
  test(`the install stops when ${name}`, () => {
    const result = helm(args);
    assert.notEqual(result.status, 0);
    assert.match(result.stderr, message);
  });
}

test("every values file in ci/ renders", () => {
  const files = readdirSync(`${chart}/ci`).filter((name) => name.endsWith(".yaml"));
  assert.ok(files.length >= 5);
  for (const file of files) assert.ok(render(["-f", `${chart}/ci/${file}`]).length > 0, file);
});
