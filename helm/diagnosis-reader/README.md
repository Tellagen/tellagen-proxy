# diagnosis-reader

A Helm chart that installs one read-only Kubernetes role for AI diagnosis and binds it. It runs no pod. Install it once for each cluster, and a platform team can review the whole result with `helm template`.

The role grants `get`, `list` and `watch` on pods, events, workloads, services, ingresses and nodes, plus `get` and `list` on `metrics.k8s.io`. It never grants secrets, configmaps, `pods/exec`, `pods/attach` or `pods/portforward`. No value changes that: the schema rejects any key it does not know, so there is no value that adds a verb or a resource.

## Install

Route A binds a group of a separate read-only identity that your OIDC provider or cloud access entry sends. This is the recommended route, because each person signs in as themselves and the audit log shows who read what.

```sh
helm install diagnosis-reader oci://ghcr.io/tellagen/charts/diagnosis-reader \
  --version <version> -n tellagen --create-namespace -f values.yaml
```

```yaml
# values.yaml
bind:
  groups: [oncall-responders]
```

Route B binds a service account and lets the same groups create short-lived tokens for it. Use it when your cluster has no group for a read-only identity.

```yaml
# values.yaml
bind:
  groups: [oncall-responders]
  serviceAccount: true
```

Then a person mints a token for the account (the service account is named after the release, `diagnosis-reader` here):

```sh
kubectl create token diagnosis-reader -n tellagen --duration 8h
```

You can also add the chart as a repository: `helm repo add tellagen https://charts.tellagen.com`.

## Values

| Value | Default | What it does |
| --- | --- | --- |
| `bind.groups` | `[tellagen-diagnosis]` | Groups that get the read role. Route A. A group that starts with `system:` is refused. |
| `bind.serviceAccount` | `false` | Makes a service account, binds it, and lets `bind.groups` create its tokens (`create` on `serviceaccounts/token`, for that one account). Route B. |
| `scope` | `cluster` | `cluster` makes a ClusterRole and a ClusterRoleBinding. `namespaces` makes a Role and a RoleBinding in each namespace of `namespaces`. |
| `namespaces` | `[]` | The namespaces to read. Required with `scope: namespaces`, and refused with `scope: cluster`. Nodes, namespaces and persistent volumes belong to the cluster, so the namespaced scope does not read them. |
| `read.podLogs` | `true` | `false` removes `pods/log`, so log lines stay away from the model provider. Diagnosis then works from events and status. |
| `read.metrics` | `true` | Adds `metrics.k8s.io` for pods, and for nodes with `scope: cluster`. It needs metrics-server. |
| `test.image` | `alpine/kubectl` | The image of the Helm test. It needs kubectl and a shell. |

The install stops with a message when nothing is bound (`bind.groups` empty and `bind.serviceAccount` false).

## Check it

```sh
helm test diagnosis-reader -n tellagen --logs
```

The test starts a pod that asks the API server, as each bound subject, whether it can list pods (yes), delete pods (no), get secrets (no) and create `pods/exec` (no, asked with `--subresource=exec`), and whether it can read pod logs (as `read.podLogs` says). The pod holds only the right to impersonate those subjects. Helm removes the pod and its rights when the test succeeds. If the test fails, Helm keeps its pod, service account and impersonation role so you can read the logs. Remove them when you are done: `kubectl delete pod,serviceaccount diagnosis-reader-test -n tellagen` and `kubectl delete clusterrole,clusterrolebinding diagnosis-reader-test` (use your release name in place of `diagnosis-reader`). The test needs a role that can create a ClusterRole, because impersonating a group is a cluster right.

You can ask the same questions yourself, with the kubeconfig a responder uses:

```sh
kubectl auth can-i list pods -A     # yes
kubectl auth can-i delete pods -A   # no
kubectl auth can-i get secrets -A   # no
kubectl auth can-i create pods --subresource=exec -A   # no
```

## Develop

```sh
helm lint helm/diagnosis-reader --strict --values helm/diagnosis-reader/ci/route-a-cluster.yaml
node --test test/diagnosis-reader.test.mjs
helm/diagnosis-reader/ci/kind-test.sh   # needs a kind cluster as the current context
```

The files in `ci/` are the routes and scopes that CI installs.
