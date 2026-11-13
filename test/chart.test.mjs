import assert from "node:assert/strict";
import { spawnSync } from "node:child_process";
import { existsSync, mkdirSync, readFileSync, readdirSync, writeFileSync } from "node:fs";
import nodeTest from "node:test";

// Renders the chart with helm and checks its contract: three secret modes, a
// hardened pod, and the same setting names as the binary. The tests need helm
// and ruby (to parse YAML) on PATH and skip with a message when one is missing.
// Refresh the snapshots with UPDATE_SNAPSHOTS=1.

const tools = { helm: ["version"], ruby: ["-v"] };
const missing = Object.keys(tools).filter((command) => spawnSync(command, tools[command], { encoding: "utf8" }).status !== 0);
const test = (name, run) => nodeTest(name, { skip: missing.length > 0 && `${missing.join(" and ")} not on PATH` }, run);

const chart = "helm/tellagen-proxy";
const snapshotDir = "test/fixtures/chart";
const update = process.env.UPDATE_SNAPSHOTS === "1";
const read = (path) => readFileSync(path, "utf8");

function ruby(script, input) {
  const result = spawnSync("ruby", ["-rjson", "-ryaml", "-e", script], { encoding: "utf8", input });
  assert.equal(result.status, 0, result.stderr);
  return JSON.parse(result.stdout);
}

function helm(args) {
  return spawnSync("helm", ["template", "tellagen-proxy", chart, "--namespace", "tellagen", "--kube-version", "1.30.0", ...args], { encoding: "utf8" });
}

function render(args = []) {
  const result = helm(args);
  assert.equal(result.status, 0, result.stderr);
  const documents = ruby("puts JSON.generate(YAML.load_stream(STDIN.read))", result.stdout).filter(Boolean);
  return documents.sort((a, b) => `${a.kind}/${a.metadata.name}`.localeCompare(`${b.kind}/${b.metadata.name}`));
}

const base = ["--set", "grafana.url=https://grafana.example.com"];
const modes = {
  token: [`-f`, `${chart}/ci/token.yaml`],
  "existing-secret": [`-f`, `${chart}/ci/existing-secret.yaml`],
  "secret-files-vault": [`-f`, `${chart}/ci/secret-files-vault.yaml`],
  "corporate-network": [`-f`, `${chart}/ci/corporate-network.yaml`],
};

const find = (documents, kind, name) => documents.find((doc) => doc.kind === kind && (name === undefined || doc.metadata.name === name));
const deployment = (documents) => find(documents, "Deployment");
const container = (documents) => deployment(documents).spec.template.spec.containers[0];
const envOf = (workload) => Object.fromEntries((workload.env ?? []).map((entry) => [entry.name, entry.value]));

for (const [name, args] of Object.entries(modes)) {
  test(`the ${name} mode renders what the snapshot holds`, () => {
    const documents = render(args);
    const path = `${snapshotDir}/${name}.json`;
    const text = `${JSON.stringify(documents, null, 2)}\n`;
    if (update) {
      mkdirSync(snapshotDir, { recursive: true });
      writeFileSync(path, text);
    }
    assert.ok(existsSync(path), `${path} is missing. Run UPDATE_SNAPSHOTS=1 node --test ${import.meta.filename}`);
    assert.deepEqual(documents, JSON.parse(read(path)), `the render of ${name} changed. If it is on purpose, run UPDATE_SNAPSHOTS=1`);
  });
}

test("helm lint passes for every mode with the schema and strict checks", () => {
  for (const [name, args] of Object.entries(modes)) {
    const result = spawnSync("helm", ["lint", chart, "--strict", ...args], { encoding: "utf8" });
    assert.equal(result.status, 0, `${name}\n${result.stdout}${result.stderr}`);
  }
});

test("token mode makes a Secret and mounts the whole directory", () => {
  const documents = render(modes.token);
  const secret = find(documents, "Secret");
  assert.deepEqual(Object.keys(secret.stringData).sort(), ["grafana-service-account-token", "tellagen-proxy-token"]);
  const env = envOf(container(documents));
  assert.equal(env.TELLAGEN_PROXY_TOKEN_FILE, "/etc/tellagen-proxy/secrets/tellagen-proxy-token");
  assert.equal(env.GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE, "/etc/tellagen-proxy/secrets/grafana-service-account-token");
  assert.equal(env.TELLAGEN_LABELS, "cluster=prod-eu-1,env=prod");
  const spec = deployment(documents).spec.template.spec;
  assert.deepEqual(spec.volumes, [{ name: "secrets", secret: { secretName: secret.metadata.name, defaultMode: 288 } }]);
  assert.deepEqual(spec.containers[0].volumeMounts, [{ name: "secrets", mountPath: "/etc/tellagen-proxy/secrets", readOnly: true }]);
});

test("existingSecret mode makes no Secret and reads the keys of yours", () => {
  const documents = render([...modes["existing-secret"], "--set", "secretKeys.tellagenToken=token"]);
  assert.equal(find(documents, "Secret"), undefined);
  const spec = deployment(documents).spec.template.spec;
  assert.equal(spec.volumes[0].secret.secretName, "tellagen-proxy");
  const env = envOf(spec.containers[0]);
  assert.equal(env.TELLAGEN_PROXY_TOKEN_FILE, "/etc/tellagen-proxy/secrets/token");
  assert.equal(env.GRAFANA_ORG_ID, "2");
  assert.equal(env.GRAFANA_ALLOWED_DATASOURCE_UIDS, "prom-prod,loki-prod");
});

test("secretFiles mode makes no Secret, mounts none, and points at the files", () => {
  const documents = render(modes["secret-files-vault"]);
  assert.equal(find(documents, "Secret"), undefined);
  const spec = deployment(documents).spec.template.spec;
  const env = envOf(spec.containers[0]);
  assert.equal(env.TELLAGEN_PROXY_TOKEN_FILE, "/vault/secrets/tellagen-proxy-token");
  assert.equal(env.GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE, "/vault/secrets/grafana-token");
  assert.equal(spec.containers[0].volumeMounts, undefined);
  assert.deepEqual(spec.volumes.map((volume) => volume.name), ["vault-token"]);
});

test("a token can come from a file and the other from the Secret", () => {
  const documents = render([...base, "--set-string", "tellagen.token=tlg_proxy_x.y", "--set", "secretFiles.grafanaToken=/vault/secrets/grafana-token"]);
  const env = envOf(container(documents));
  assert.equal(env.TELLAGEN_PROXY_TOKEN_FILE, "/etc/tellagen-proxy/secrets/tellagen-proxy-token");
  assert.equal(env.GRAFANA_SERVICE_ACCOUNT_TOKEN_FILE, "/vault/secrets/grafana-token");
  assert.deepEqual(Object.keys(find(documents, "Secret").stringData), ["tellagen-proxy-token"]);
});

const failures = [
  ["no Grafana address", ["--set", "existingSecret=s"], /grafana\.url is required/],
  ["no Tellagen token", [...base, "--set", "grafana.token=g"], /Tellagen proxy token is missing/],
  ["no Grafana token", [...base, "--set", "tellagen.token=t"], /Grafana service account token is missing/],
  ["a token and an existing Secret", [...base, "--set", "existingSecret=s", "--set", "tellagen.token=t"], /tellagen\.token and existingSecret are both set/],
  ["a Grafana token and an existing Secret", [...base, "--set", "existingSecret=s", "--set", "grafana.token=t"], /grafana\.token and existingSecret are both set/],
  ["a token and a file", [...base, "--set", "existingSecret=s", "--set", "tellagen.token=t", "--set", "secretFiles.tellagenToken=/f"], /tellagen\.token and secretFiles\.tellagenToken are both set/],
  ["a Grafana token and a file", [...base, "--set", "existingSecret=s", "--set", "grafana.token=t", "--set", "secretFiles.grafanaToken=/f"], /grafana\.token and secretFiles\.grafanaToken are both set/],
  ["a value the schema does not know", [...base, "--set", "existingSecret=s", "--set", "bogus=1"], /additional properties 'bogus' not allowed/],
  ["a relative file path", [...base, "--set", "existingSecret=s", "--set", "secretFiles.grafanaToken=relative/path"], /does not match pattern/],
  ["an org id that is not a number", [...base, "--set", "existingSecret=s", "--set-string", "grafana.orgId=abc"], /does not match pattern/],
  ["a digest that is not a sha256", [...base, "--set", "existingSecret=s", "--set", "image.digest=latest"], /does not match pattern/],
  ["no replica", [...base, "--set", "existingSecret=s", "--set", "replicaCount=0"], /minimum/],
];
for (const [name, args, message] of failures) {
  test(`helm template refuses ${name}`, () => {
    const result = helm(args);
    assert.notEqual(result.status, 0, "the render should fail");
    assert.match(`${result.stdout}${result.stderr}`, message);
  });
}

const allRenders = () => [...Object.entries(modes).map(([name, args]) => [name, render(args)]), ["openshift", render([...modes.token, "--set", "openshift=true"])]];

test("no secret reaches the environment or a command line", () => {
  for (const [name, documents] of allRenders()) {
    const text = JSON.stringify(documents.filter((doc) => doc.kind !== "Secret"));
    assert.doesNotMatch(text, /secretKeyRef|valueFrom/, name);
    assert.doesNotMatch(text, /tlg_proxy_test|glsa_test/, name);
    for (const pod of podSpecs(documents)) {
      for (const entry of pod.containers[0].env) assert.match(entry.name, /^[A-Z][A-Z0-9_]+$/);
    }
  }
});

function podSpecs(documents) {
  return documents.flatMap((doc) => {
    if (doc.kind === "Deployment") return [doc.spec.template.spec];
    if (doc.kind === "Pod") return [doc.spec];
    return [];
  });
}

test("no volume mount uses subPath, so a changed Secret reaches the pod", () => {
  for (const [name, documents] of allRenders()) {
    for (const pod of podSpecs(documents)) {
      for (const mount of pod.containers[0].volumeMounts ?? []) assert.equal(mount.subPath, undefined, `${name}: ${mount.name}`);
    }
  }
});

test("the pod and the test pod meet the Pod Security restricted profile", () => {
  const allowedVolumes = new Set(["configMap", "secret", "projected", "emptyDir", "downwardAPI", "csi", "ephemeral", "persistentVolumeClaim"]);
  for (const [name, documents] of allRenders()) {
    const pods = podSpecs(documents);
    assert.equal(pods.length, 2, `${name}: a Deployment and a test Pod`);
    for (const pod of pods) {
      assert.equal(pod.securityContext.runAsNonRoot, true, name);
      assert.equal(pod.securityContext.seccompProfile.type, "RuntimeDefault", name);
      assert.equal(pod.automountServiceAccountToken, false, name);
      for (const key of ["hostNetwork", "hostPID", "hostIPC"]) assert.equal(pod[key], undefined, `${name}: ${key}`);
      for (const volume of pod.volumes ?? []) {
        const kind = Object.keys(volume).find((key) => key !== "name");
        assert.ok(allowedVolumes.has(kind), `${name}: volume type ${kind}`);
      }
      assert.equal(pod.containers.length, 1);
      const security = pod.containers[0].securityContext;
      assert.equal(security.allowPrivilegeEscalation, false, name);
      assert.equal(security.readOnlyRootFilesystem, true, name);
      assert.equal(security.runAsNonRoot, true, name);
      assert.equal(security.privileged, undefined, name);
      assert.deepEqual(security.capabilities, { drop: ["ALL"] }, name);
      for (const port of pod.containers[0].ports ?? []) assert.equal(port.hostPort, undefined, name);
    }
  }
});

test("the user id is 65532, and openshift leaves it to the security context constraint", () => {
  const normal = deployment(render(modes.token)).spec.template.spec.securityContext;
  assert.deepEqual([normal.runAsUser, normal.runAsGroup, normal.fsGroup], [65532, 65532, 65532]);
  for (const documents of [render([...modes.token, "--set", "openshift=true"]), render(modes["corporate-network"])]) {
    for (const pod of podSpecs(documents)) {
      assert.equal(pod.securityContext.runAsUser, undefined);
      assert.equal(pod.securityContext.runAsGroup, undefined);
      assert.equal(pod.securityContext.fsGroup, undefined);
      assert.equal(pod.securityContext.runAsNonRoot, true);
    }
  }
});

test("there is no service account token and no RBAC unless vaultAuth is on", () => {
  for (const [name, documents] of allRenders()) {
    const kinds = documents.map((doc) => doc.kind);
    for (const forbidden of ["Role", "RoleBinding", "ClusterRole", "ClusterRoleBinding"]) assert.ok(!kinds.includes(forbidden), `${name}: ${forbidden}`);
    assert.equal(find(documents, "ServiceAccount").automountServiceAccountToken, false, name);
  }
  const plain = deployment(render(modes.token)).spec.template;
  assert.equal(plain.spec.volumes.some((volume) => volume.projected), false);
  assert.equal(plain.metadata.annotations, undefined);
});

test("vaultAuth mounts a projected token with the audience vault for the agent only", () => {
  const template = deployment(render(modes["secret-files-vault"])).spec.template;
  const projected = template.spec.volumes.find((volume) => volume.name === "vault-token").projected.sources;
  assert.equal(projected.length, 1);
  assert.equal(projected[0].serviceAccountToken.audience, "vault");
  assert.ok(projected[0].serviceAccountToken.expirationSeconds >= 600);
  assert.equal(template.metadata.annotations["vault.hashicorp.com/agent-service-account-token-volume-name"], "vault-token");
  assert.equal(template.metadata.annotations["vault.hashicorp.com/role"], "tellagen-proxy");
  assert.equal(template.spec.automountServiceAccountToken, false);
  assert.equal((template.spec.containers[0].volumeMounts ?? []).some((mount) => mount.name === "vault-token"), false);
});

test("requests, limits, replicas and the disruption budget", () => {
  const documents = render(modes.token);
  assert.deepEqual(container(documents).resources, { requests: { cpu: "50m", memory: "64Mi" }, limits: { cpu: "500m", memory: "256Mi" } });
  assert.equal(deployment(documents).spec.replicas, 2);
  assert.equal(find(documents, "PodDisruptionBudget").spec.minAvailable, 1);
  const single = render([...modes.token, "--set", "replicaCount=1"]);
  assert.equal(find(single, "PodDisruptionBudget"), undefined, "a budget of one would block every node drain");
  assert.equal(find(render([...modes.token, "--set", "podDisruptionBudget.enabled=false"]), "PodDisruptionBudget"), undefined);
});

test("the probes and the one port", () => {
  const spec = container(render(modes.token));
  assert.deepEqual(spec.ports, [{ name: "http", containerPort: 8080, protocol: "TCP" }]);
  assert.equal(spec.livenessProbe.httpGet.path, "/healthz");
  assert.equal(spec.readinessProbe.httpGet.path, "/readyz");
  assert.equal(spec.startupProbe.httpGet.path, "/healthz");
  assert.equal(find(render(modes.token), "Service"), undefined, "no Service unless metrics are on");
});

test("the corporate network mode sets the proxy, the CA bundle and the policy file", () => {
  const documents = render(modes["corporate-network"]);
  const spec = deployment(documents).spec.template.spec;
  const env = envOf(spec.containers[0]);
  assert.equal(env.HTTPS_PROXY, "http://proxy.corp.example:3128");
  assert.equal(env.NO_PROXY, ".corp.example,10.0.0.0/8,.svc,.cluster.local");
  assert.equal(env.TELLAGEN_CA_FILE, "/etc/tellagen-proxy/ca/ca.crt");
  assert.equal(env.GRAFANA_CA_FILE, "/etc/tellagen-proxy/ca/ca.crt");
  assert.equal(env.GRAFANA_PUBLIC_URL, "https://grafana.example.com");
  assert.equal(env.TELLAGEN_POLICY_FILE, "/etc/tellagen-proxy/policy/policy.yaml");
  assert.deepEqual(spec.volumes.find((volume) => volume.name === "ca").configMap.name, "corp-ca");
  const policy = ruby("puts JSON.generate(YAML.load(STDIN.read))", find(documents, "ConfigMap").data["policy.yaml"]);
  assert.deepEqual(policy.datasourceUIDs, ["prom-prod", "loki-prod"]);
  assert.match(deployment(documents).spec.template.metadata.annotations["checksum/policy"], /^[0-9a-f]{64}$/);
  const changed = render([...modes["corporate-network"], "--set", "policy.logs.maxLines=5"]);
  assert.notEqual(deployment(changed).spec.template.metadata.annotations["checksum/policy"], deployment(documents).spec.template.metadata.annotations["checksum/policy"]);
});

test("the NetworkPolicy allows DNS, Tellagen and Grafana, and nothing else", () => {
  const policy = find(render(modes["corporate-network"]), "NetworkPolicy");
  assert.deepEqual(policy.spec.policyTypes, ["Ingress", "Egress"]);
  assert.equal(policy.spec.egress.length, 3);
  assert.deepEqual(policy.spec.egress[1], { ports: [{ port: 3128, protocol: "TCP" }], to: [{ ipBlock: { cidr: "192.0.2.0/24" } }] });
  assert.deepEqual(policy.spec.ingress[0].ports, [{ port: 8080, protocol: "TCP" }]);
  assert.equal(find(render(modes.token), "NetworkPolicy"), undefined, "off by default");
  const closed = find(render([...modes.token, "--set", "networkPolicy.enabled=true"]), "NetworkPolicy");
  assert.deepEqual(closed.spec.ingress, []);
  assert.equal(closed.spec.egress[1].to, undefined);
});

test("the metrics Service and ServiceMonitor appear only when asked for", () => {
  const documents = render(modes["corporate-network"]);
  assert.equal(find(documents, "Service").spec.ports[0].port, 8080);
  assert.equal(find(documents, "ServiceMonitor").spec.endpoints[0].path, "/metrics");
  assert.equal(find(render(modes.token), "ServiceMonitor"), undefined);
});

test("helm test runs doctor with the same settings as the proxy", () => {
  const documents = render(modes["corporate-network"]);
  const testPod = find(documents, "Pod");
  assert.equal(testPod.metadata.annotations["helm.sh/hook"], "test");
  assert.deepEqual(testPod.spec.containers[0].args, ["doctor"]);
  assert.equal(testPod.spec.restartPolicy, "Never");
  assert.deepEqual(testPod.spec.containers[0].env, container(documents).env);
  assert.deepEqual(testPod.spec.containers[0].volumeMounts, container(documents).volumeMounts);
  assert.deepEqual(testPod.spec.volumes, deployment(documents).spec.template.spec.volumes);
});

test("the image is the chart appVersion, a tag you choose, or a tag with a digest", () => {
  const digest = `sha256:${"a".repeat(64)}`;
  const appVersion = read(`${chart}/Chart.yaml`).match(/^appVersion: "?([^"\n]+)"?$/m)[1];
  assert.equal(container(render(modes.token)).image, `ghcr.io/tellagen/tellagen-proxy:${appVersion}`);
  assert.equal(container(render([...modes.token, "--set", "image.tag=1.4.2"])).image, "ghcr.io/tellagen/tellagen-proxy:1.4.2");
  assert.equal(container(render([...modes.token, "--set", "image.tag=1.4.2", "--set", `image.digest=${digest}`])).image, `ghcr.io/tellagen/tellagen-proxy:1.4.2@${digest}`);
  assert.equal(container(render([...modes.token, "--set", "image.pullPolicy=Always"])).imagePullPolicy, "Always");
  assert.equal(read(`${chart}/values.yaml`).match(/^  tag: ""$/m) !== null, true, "the default tag stays empty: it follows the chart appVersion, never latest");
});

test("the replicas spread over nodes by default, and affinity replaces that rule", () => {
  const spec = deployment(render(modes.token)).spec.template.spec;
  assert.equal(spec.affinity.podAntiAffinity.preferredDuringSchedulingIgnoredDuringExecution[0].podAffinityTerm.topologyKey, "kubernetes.io/hostname");
  const own = deployment(render([...modes.token, "--set", "affinity.nodeAffinity.requiredDuringSchedulingIgnoredDuringExecution.nodeSelectorTerms[0].matchExpressions[0].key=pool"])).spec.template.spec;
  assert.equal(own.affinity.podAntiAffinity, undefined);
  assert.ok(own.affinity.nodeAffinity);
});

test("every setting the chart sets is one the binary reads", () => {
  const source = read("internal/settings/settings.go");
  const known = new Set();
  for (const [, name] of source.matchAll(/"([A-Z][A-Z0-9]*(?:_[A-Z0-9]+)+)"/g)) {
    known.add(name);
    known.add(`${name}_FILE`);
  }
  const chartNames = new Set();
  for (const [, documents] of allRenders()) {
    for (const pod of podSpecs(documents)) for (const entry of pod.containers[0].env) chartNames.add(entry.name);
  }
  assert.ok(chartNames.size >= 12, "the renders cover the settings");
  const unknown = [...chartNames].filter((name) => !known.has(name));
  assert.deepEqual(unknown, []);
});

test("the chart folder has the files a release needs and ships no CI values", () => {
  const files = readdirSync(chart);
  for (const file of ["Chart.yaml", "values.yaml", "values.schema.json", ".helmignore", "templates", "examples"]) assert.ok(files.includes(file), file);
  assert.match(read(`${chart}/.helmignore`), /^\/ci\/$/m);
  assert.doesNotMatch(read(`${chart}/.helmignore`), /^tests\/$/m, "a tests/ rule would also drop templates/tests");
  const cilium = read(`${chart}/examples/cilium-fqdn-networkpolicy.yaml`);
  const parsed = ruby("puts JSON.generate(YAML.load(STDIN.read))", cilium);
  assert.equal(parsed.kind, "CiliumNetworkPolicy");
  assert.ok(parsed.spec.egress.some((rule) => rule.toFQDNs?.some((fqdn) => fqdn.matchName === "connect.tellagen.com")));
});

test("the chart version is a placeholder that the release workflow replaces", () => {
  const chartFile = read(`${chart}/Chart.yaml`);
  assert.match(chartFile, /^version: 0\.0\.0$/m);
  assert.match(chartFile, /^appVersion: 0\.0\.0$/m);
});
