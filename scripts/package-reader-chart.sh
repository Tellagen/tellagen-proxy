#!/usr/bin/env bash
# Packages the diagnosis-reader chart for a release: the release version becomes
# the chart version and appVersion. The chart runs no image, so there is no digest.
#
#   scripts/package-reader-chart.sh <version> <output-dir>
set -euo pipefail

version=${1:?usage: package-reader-chart.sh <version> <output-dir>}
out=${2:?usage: package-reader-chart.sh <version> <output-dir>}

root=$(cd "$(dirname "$0")/.." && pwd)
chart="$root/helm/diagnosis-reader"

for values in "$chart"/ci/*.yaml; do
  helm lint "$chart" --strict --values "$values"
done
mkdir -p "$out"
helm package "$chart" --version "$version" --app-version "$version" --destination "$out"
