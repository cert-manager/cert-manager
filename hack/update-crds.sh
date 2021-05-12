#!/usr/bin/env bash

# Copyright 2020 The cert-manager Authors.
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
cue="$(realpath "$3")"

export PATH=$(dirname "$go"):$PATH

# This script should be run via `bazel run //hack:update-crds`
REPO_ROOT=${BUILD_WORKSPACE_DIRECTORY}
cd "${REPO_ROOT}"

set -xe

# controller-gen silently skips YAML crd-*.yaml files that are not proper
# YAML. As detailed in [1], this issue prevented anyone from updating the
# crd-*.yaml files. To avoid this issue from happening again, we want to
# make sure every CRD file is a valid YAML file, before running
# controller-gen.
#
# We could just use yq (the python CLI) to parse the YAML... But I didn't
# want us to rely on python things. And its Go equivalent, mikefarah/yq,
# has a pretty poor CLI UX. So I just used the excellent CUE tool. ALthough
# CUE is meant for validating schemas, we don't care about schemas here,
# that's why we use a dummy valid-crd.cue.
#
# [1]: https://github.com/jetstack/cert-manager/pull/3989
"$cue" vet hack/valid-crd.cue deploy/crds/*.yaml

"$controllergen" \
  schemapatch:manifests=./deploy/crds \
  output:dir=./deploy/crds \
  paths=./pkg/apis/...
