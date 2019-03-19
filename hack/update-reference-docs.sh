#!/bin/bash

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

# This script should be run via `bazel run //hack:update-reference-docs`
REPO_ROOT=${BUILD_WORKSPACE_DIRECTORY:-"$(cd "$(dirname "$0")" && pwd -P)"/..}
SCRIPT_RUNFILES="${runfiles:-$(pwd)}"
cd "${REPO_ROOT}"

# The final directory path to store the generated output data
OUTPUT_DIR="$(cd "${REPO_ROOT}/docs/generated/reference/output/reference/api-docs" 2> /dev/null && pwd -P)"

TMP_OUTPUT="$(mktemp -d)"

tar -C "${TMP_OUTPUT}" -xf "${SCRIPT_RUNFILES}/docs/generated/reference/generate/generated.tar.gz"

rm -Rf "${OUTPUT_DIR}"
mkdir -p "${OUTPUT_DIR}"
mv "${TMP_OUTPUT}"/* "${OUTPUT_DIR}"
