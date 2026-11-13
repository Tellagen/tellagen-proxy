#!/usr/bin/env bash
# Packages the chart for a release: the release version becomes the chart version
# and appVersion, and the digest of the signed image goes into values.yaml.
#
#   scripts/package-chart.sh <version> <sha256:digest> <output-dir>
set -euo pipefail

version=${1:?usage: package-chart.sh <version> <sha256:digest> <output-dir>}
digest=${2:?usage: package-chart.sh <version> <sha256:digest> <output-dir>}
out=${3:?usage: package-chart.sh <version> <sha256:digest> <output-dir>}
[[ $digest =~ ^sha256:[0-9a-f]{64}$ ]] || { echo "the digest must look like sha256:<64 hex digits>" >&2; exit 1; }

root=$(cd "$(dirname "$0")/.." && pwd)
stage=$(mktemp -d)
trap 'rm -rf "$stage"' EXIT

cp -R "$root/helm/tellagen-proxy" "$stage/tellagen-proxy"
values="$stage/tellagen-proxy/values.yaml"
[[ $(grep -c '^  digest: ""$' "$values") -eq 1 ]] || { echo "values.yaml must hold exactly one empty image digest" >&2; exit 1; }
sed "s|^  digest: \"\"\$|  digest: \"${digest}\"|" "$values" >"$values.new"
mv "$values.new" "$values"

helm lint "$stage/tellagen-proxy" --strict --values "$root/helm/tellagen-proxy/ci/token.yaml"
mkdir -p "$out"
helm package "$stage/tellagen-proxy" --version "$version" --app-version "$version" --destination "$out"
