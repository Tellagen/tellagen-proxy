#!/usr/bin/env bash
# Installs the chart in a kind cluster, once for each file in ci/, and checks what
# the bound subjects may do. It asks the API server as the cluster admin, who
# impersonates the subject, and it runs the chart's own Helm test too.
#
#   helm/diagnosis-reader/ci/kind-test.sh
set -euo pipefail

release=diagnosis-reader
namespace=tellagen
chart=$(cd "$(dirname "$0")/.." && pwd)
group=tellagen-diagnosis
failed=0

fail() {
  echo "::error::$*" >&2
  failed=1
}

# expect <yes|no> <as arguments> <can-i arguments...>
expect() {
  local expected=$1 as=$2
  shift 2
  local answer
  # shellcheck disable=SC2086
  answer=$(kubectl auth can-i "$@" $as 2>/dev/null || true)
  [[ $answer == "$expected" ]] || fail "$* as [$as]: got '${answer}', expected '${expected}'"
}

# check_subject <as arguments> <yes|no for pod logs> <scope arguments...>
check_subject() {
  local as=$1 logs=$2
  shift 2
  local scope
  for scope in "$@"; do
    expect yes "$as" list pods "$scope"
    expect yes "$as" get deployments.apps "$scope"
    expect yes "$as" watch events "$scope"
    expect "$logs" "$as" get pods --subresource=log "$scope"
    expect no "$as" delete pods "$scope"
    expect no "$as" create pods "$scope"
    expect no "$as" update deployments.apps "$scope"
    expect no "$as" get secrets "$scope"
    expect no "$as" list secrets "$scope"
    expect no "$as" get configmaps "$scope"
    expect no "$as" create pods --subresource=exec "$scope"
    expect no "$as" create pods --subresource=attach "$scope"
    expect no "$as" create pods --subresource=portforward "$scope"
  done
}

for target in reader-test-a reader-test-b other-namespace; do
  kubectl create namespace "$target" --dry-run=client -o yaml | kubectl apply -f -
done

for values in "$chart"/ci/route-*.yaml; do
  name=$(basename "$values" .yaml)
  echo "== $name"
  helm install "$release" "$chart" --namespace "$namespace" --create-namespace --values "$values" --wait --timeout 120s

  logs=yes
  grep -Eq '^\s+podLogs: false' "$values" && logs=no
  account="--as=system:serviceaccount:$namespace:$release"
  if grep -q '^scope: namespaces' "$values"; then
    scopes=(-n=reader-test-a -n=reader-test-b)
    nodes=no
  else
    scopes=(-A)
    nodes=yes
  fi

  if grep -q 'groups: \[tellagen-diagnosis\]' "$values"; then
    check_subject "--as=u --as-group=$group" "$logs" "${scopes[@]}"
    expect "$nodes" "--as=u --as-group=$group" list nodes
    expect no "--as=u --as-group=not-$group" list pods "${scopes[0]}"
    # A namespace that is not listed gets nothing.
    [[ $nodes == yes ]] || expect no "--as=u --as-group=$group" list pods -n=other-namespace
  fi

  if grep -q 'serviceAccount: true' "$values"; then
    check_subject "$account" "$logs" "${scopes[@]}"
    expect "$nodes" "$account" list nodes
    [[ $nodes == yes ]] || expect no "$account" list pods -n=other-namespace
    if grep -q 'groups: \[tellagen-diagnosis\]' "$values"; then
      # The group may mint a token for the account, and nobody else may.
      kubectl create token "$release" --namespace "$namespace" --duration 10m --as=u --as-group="$group" >/dev/null || fail "$name: the group cannot create a token"
      if kubectl create token "$release" --namespace "$namespace" --duration 10m --as=u --as-group="not-$group" >/dev/null 2>&1; then
        fail "$name: a user outside the group created a token"
      fi
      expect no "--as=u --as-group=$group" create serviceaccounts --namespace "$namespace"
    fi
  fi

  if ! helm test "$release" --namespace "$namespace" --logs; then
    fail "$name: the Helm test failed"
  fi
  helm uninstall "$release" --namespace "$namespace" --wait --timeout 120s
done

if ((failed)); then
  exit 1
fi
echo "Every subject can read and cannot change anything, read secrets or open a shell, in every route and scope."
