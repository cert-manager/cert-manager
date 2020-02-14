#!/usr/bin/env bash

# Copyright 2019 The Jetstack cert-manager contributors.
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

if [[ -n "${BUILD_WORKSPACE_DIRECTORY:-}" ]]; then # Running inside bazel
  echo "Updating generated CRDs..." >&2
elif ! command -v bazel &>/dev/null; then
  echo "Install bazel at https://bazel.build" >&2
  exit 1
else
  (
    set -o xtrace
    bazel run //hack:update-crds
  )
  exit 0
fi

go=$(realpath "$1")
controllergen="$(realpath "$2")"
helm="$(realpath "$3")"
export PATH=$(dirname "$go"):$PATH

# This script should be run via `bazel run //hack:update-crds`
REPO_ROOT=${BUILD_WORKSPACE_DIRECTORY}
cd "${REPO_ROOT}"

"$controllergen" \
  schemapatch:manifests=./deploy/charts/cert-manager-crds/templates \
  output:dir=./deploy/charts/cert-manager-crds/templates \
  paths=./pkg/apis/...

out="./deploy/manifests/00-crds.yaml"
rm "$out" || true
touch "$out"
# template all files while removing blank (^$) lines
"$helm" template ./deploy/charts/cert-manager-crds/ | sed '/^$$/d' >> "$out"
printf -- "---\n" >> "$out"
chmod 644 "$out"


echo "Generated 00-crds.yaml"
