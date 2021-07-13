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

if [[ -n "${TEST_WORKSPACE:-}" ]]; then # Running inside bazel
  echo "Checking templated helm README.md & Chart.yaml for changes..." >&2
elif ! command -v bazel &>/dev/null; then
  echo "Install bazel at https://bazel.build" >&2
  exit 1
else
  (
    set -o xtrace
    bazel test --test_output=streamed //hack:verify-helmgen
  )
  exit 0
fi

tmpfiles=$TEST_TMPDIR/files

(
  mkdir -p "$tmpfiles"
  cp -aL "./deploy/charts/cert-manager/." "$tmpfiles/"
  IN_DIR="./deploy/charts/cert-manager" OUT_DIR="$tmpfiles" "$@"
)

# Avoid diff -N so we handle empty files correctly
diff=$(diff -upr \
  -I '^Copyright.*' \
  "./deploy/charts/cert-manager" "$tmpfiles" 2>/dev/null || true)

if [[ -n "${diff}" ]]; then
  echo "${diff}" >&2
  echo >&2
  echo "ERROR: templated helm README.md & Chart.yaml changed. Update with ./hack/update-helmgen.sh" >&2
  exit 1
fi
echo "SUCCESS: templated helm README.md & Chart.yaml up-to-date"
