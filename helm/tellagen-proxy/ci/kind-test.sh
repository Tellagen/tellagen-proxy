#!/usr/bin/env bash
# Installs the chart in a kind cluster and checks that the proxy reaches a fake
# Grafana. The namespace enforces the Pod Security "restricted" profile, so a pod
# that breaks the profile is never created. There is no Tellagen in the test, so
# the proxy never turns ready, and the checks read the doctor output instead.
#
#   helm/tellagen-proxy/ci/kind-test.sh <image-repository> <image-tag>
#
# The image must be loaded into the cluster first (kind load docker-image).
set -euo pipefail

repository=${1:?usage: kind-test.sh <image-repository> <image-tag>}
tag=${2:?usage: kind-test.sh <image-repository> <image-tag>}
namespace=tellagen-proxy-test
chart=$(cd "$(dirname "$0")/.." && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT

fail() {
  echo "::error::$*" >&2
  kubectl -n "$namespace" get pods,events -o wide 2>&1 | tail -40 >&2 || true
  for pod in $(kubectl -n "$namespace" get pods -l app.kubernetes.io/name=tellagen-proxy -o name 2>/dev/null); do
    echo "--- $pod" >&2
    kubectl -n "$namespace" logs "$pod" --tail=20 >&2 || true
  done
  exit 1
}

# wait_for <seconds> <description> <command...> runs the command until it succeeds.
wait_for() {
  local seconds=$1 description=$2
  shift 2
  local end=$((SECONDS + seconds))
  until "$@" >/dev/null 2>&1; do
    ((SECONDS < end)) || fail "timed out after ${seconds}s waiting for $description"
    sleep 3
  done
}

pods_running() {
  local phases
  phases=$(kubectl -n "$namespace" get pods -l app.kubernetes.io/name=tellagen-proxy -o jsonpath='{range .items[*]}{.status.phase}{"\n"}{end}')
  [[ $(grep -c '^Running$' <<<"$phases") -eq 2 && $(grep -vc '^Running$' <<<"$phases") -eq 0 ]]
}

doctor_output() {
  kubectl -n "$namespace" exec deploy/tellagen-proxy -- /tellagen-proxy doctor 2>&1 || true
}

doctor_shows() {
  doctor_output | grep -Eq "$1"
}

kubectl create namespace "$namespace"
kubectl label namespace "$namespace" pod-security.kubernetes.io/enforce=restricted pod-security.kubernetes.io/enforce-version=latest

# A fake Grafana: fixed answers for the calls the doctor makes. It runs under the
# same profile as the proxy.
kubectl -n "$namespace" create configmap fake-grafana --from-file=fake-grafana.py="$chart/ci/fake-grafana.py"
kubectl -n "$namespace" apply -f - <<'YAML'
apiVersion: apps/v1
kind: Deployment
metadata:
  name: fake-grafana
spec:
  replicas: 1
  selector:
    matchLabels: {app: fake-grafana}
  template:
    metadata:
      labels: {app: fake-grafana}
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 65532
        seccompProfile: {type: RuntimeDefault}
      containers:
        - name: grafana
          image: python:3.13-alpine
          command: ["python", "/app/fake-grafana.py"]
          env: [{name: PYTHONDONTWRITEBYTECODE, value: "1"}]
          ports: [{containerPort: 3000}]
          securityContext:
            allowPrivilegeEscalation: false
            readOnlyRootFilesystem: true
            capabilities: {drop: [ALL]}
          volumeMounts: [{name: app, mountPath: /app}]
      volumes:
        - name: app
          configMap: {name: fake-grafana}
---
apiVersion: v1
kind: Service
metadata:
  name: fake-grafana
spec:
  selector: {app: fake-grafana}
  ports: [{port: 3000}]
YAML
kubectl -n "$namespace" rollout status deploy/fake-grafana --timeout=120s || fail "the fake Grafana did not start"

existing_secret=tellagen-proxy-existing
token() { printf 'tlg_proxy_01KIND000.secret%s' "$1"; }
echo -n "glsa_kind_test" >"$work/grafana-token"
echo -n "$(token AAAA)" >"$work/tellagen-token"

install_args=(
  --namespace "$namespace"
  --set image.repository="$repository" --set image.tag="$tag"
  --set grafana.url=http://fake-grafana:3000
  --set tellagen.url=http://127.0.0.1:9
)

echo "== token mode"
helm install tellagen-proxy "$chart" "${install_args[@]}" \
  --set-file tellagen.token="$work/tellagen-token" --set-file grafana.token="$work/grafana-token"
wait_for 180 "two running pods" pods_running
wait_for 60 "the doctor to reach the fake Grafana" doctor_shows '\[ok\] +grafana +http://fake-grafana:3000 v12\.2\.1, org 1, role Viewer'
doctor_shows '\[ok\] +config +token from TELLAGEN_PROXY_TOKEN_FILE \(tlg_proxy_01KIND00…AAAA\)' || fail "the doctor does not read the token from the mounted file"

echo "== helm test runs the doctor in a pod that meets the profile"
helm test tellagen-proxy --namespace "$namespace" --logs >"$work/helm-test.txt" 2>&1 || true
grep -Eq '\[ok\] +grafana +http://fake-grafana:3000' "$work/helm-test.txt" || { cat "$work/helm-test.txt" >&2; fail "the helm test pod did not reach the fake Grafana"; }
# The doctor fails on the missing Tellagen, so Helm keeps the pod, and it carries
# the labels of the proxy pods. Remove it, or it counts as a pod that is not running.
kubectl -n "$namespace" delete pod tellagen-proxy-doctor --ignore-not-found --wait=true

# The proxy never turns ready here, because there is no Tellagen to reach, so a
# rollout never finishes: the new pod stays unready and the old pods are never
# replaced. The second mode is therefore a fresh install, not an upgrade.
echo "== existingSecret mode, then a rotation without a restart"
helm uninstall tellagen-proxy --namespace "$namespace" --wait --timeout 120s
kubectl -n "$namespace" create secret generic "$existing_secret" \
  --from-file=tellagen-proxy-token="$work/tellagen-token" --from-file=grafana-service-account-token="$work/grafana-token"
helm install tellagen-proxy "$chart" "${install_args[@]}" --set existingSecret="$existing_secret"
wait_for 180 "two running pods" pods_running
doctor_shows '\(tlg_proxy_01KIND00…AAAA\)' || fail "the doctor does not read the token of the existing Secret"
before=$(kubectl -n "$namespace" get pods -l app.kubernetes.io/name=tellagen-proxy -o jsonpath='{.items[*].metadata.uid}')

echo -n "$(token BBBB)" >"$work/tellagen-token"
kubectl -n "$namespace" create secret generic "$existing_secret" \
  --from-file=tellagen-proxy-token="$work/tellagen-token" --from-file=grafana-service-account-token="$work/grafana-token" \
  --dry-run=client -o yaml | kubectl -n "$namespace" apply -f -
wait_for 240 "the rotated token to reach the mounted file" doctor_shows '\(tlg_proxy_01KIND00…BBBB\)'
after=$(kubectl -n "$namespace" get pods -l app.kubernetes.io/name=tellagen-proxy -o jsonpath='{.items[*].metadata.uid}')
[[ "$before" == "$after" ]] || fail "the pods were replaced during the rotation"
restarts=$(kubectl -n "$namespace" get pods -l app.kubernetes.io/name=tellagen-proxy -o jsonpath='{.items[*].status.containerStatuses[*].restartCount}')
[[ -z "${restarts//[0 ]/}" ]] || fail "a container restarted: $restarts"

echo "The proxy reached the fake Grafana in both secret modes, and a rotated token reached it without a restart."
