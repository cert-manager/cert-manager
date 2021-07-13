#!/bin/bash

# Copyright 2021 The cert-manager Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit
set -o nounset
set -o pipefail

if [[ -n "${BUILD_WORKSPACE_DIRECTORY:-}" ]]; then # 'bazel run //hack:update-helmgen'
  IN_DIR="$BUILD_WORKSPACE_DIRECTORY/deploy/charts/cert-manager"
  OUT_DIR="$BUILD_WORKSPACE_DIRECTORY/deploy/charts/cert-manager"
fi

if [[ -n "${IN_DIR:-}" && -n "${OUT_DIR:-}" ]]; then # 'bazel build //deploy/charts/cert-manager:template'
  echo "Updating templated helm README.md & Chart.yaml..." >&2
elif ! command -v bazel &>/dev/null; then
  echo "Install bazel at https://bazel.build" >&2
  exit 1
else # './hack/update-helmgen.sh'
  (
    set -o xtrace
    bazel run //hack:update-helmgen
  )
  exit 0
fi

if [[ "$1" == "unversioned" ]]; then 
  VERSION="v0.0.1"
  IS_PRERELEASE="true"
  FILE_SUFFIX=""
else
  version=$PWD/$1
  VERSION=$(cat "$version")
  IS_PRERELEASE=$(grep -q '^v[0-9]\\+.[0-9]\\+.[0-9]\\+$$' "$version" && echo "false" || echo "true")
  FILE_SUFFIX=".versioned"
fi

tem=$PWD/$2

shift 2

doc=$(mktemp -t doc.XXXX.yaml)

cat << EOF > "$doc"
{
  "Repository": {
    "Name": "jetstack",
    "URL": "https://charts.jetstack.io"
  },
  "Chart": {
    "Name": "cert-manager",
    "Version": "${VERSION}",
    "IsPrerelease": "${IS_PRERELEASE}"
  },
  "Release": {
    "Name": "my-cert-manager",
    "Namespace": "cert-manager"
  }
}
EOF

cat "$doc"

"$tem" \
  -f Run="$doc" \
  -t "$IN_DIR/Chart.template.yaml" \
  > "$OUT_DIR/Chart$FILE_SUFFIX.yaml"

"$tem" \
  -f Run="$doc" \
  -f Values="$IN_DIR/values.yaml" \
  -t "$IN_DIR/README.template.md" \
  > "$OUT_DIR/README$FILE_SUFFIX.md"
