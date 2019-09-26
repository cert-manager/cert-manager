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

if [[ -n "${TEST_WORKSPACE:-}" ]]; then # Running inside bazel
  echo "Checking modules for changes..." >&2
elif ! command -v bazel &>/dev/null; then
  echo "Install bazel at https://bazel.build" >&2
  exit 1
else
  (
    set -o xtrace
    bazel test --test_output=streamed //hack:verify-crds
  )
  exit 0
fi

MANIFESTS_DIR="deploy/manifests"

ret=0
diff -Naupr "${MANIFESTS_DIR}/00-crds.yaml" "${MANIFESTS_DIR}/crds.yaml.generated" || ret=$?
if [[ $ret -eq 0 ]]
then
  echo "${MANIFESTS_DIR}/00-crds.yaml up to date."
else
  echo "${MANIFESTS_DIR}/00-crds.yaml is out of date. Please run 'bazel run //hack:update-crds"
  exit 1
fi
