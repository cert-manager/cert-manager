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

# This script should be run via `bazel run //hack:update-crds`
REPO_ROOT=${BUILD_WORKSPACE_DIRECTORY:-"$(cd "$(dirname "$0")" && pwd -P)"/..}
runfiles="$(pwd)"
export PATH="${runfiles}/hack/bin:${PATH}"
cd "${REPO_ROOT}"

output="$(mktemp -d)"
gencrd generate \
    --domain "k8s.io" \
    --output-dir "${output}"

echo "Copying files to output file"
out="deploy/manifests/00-crds.yaml"
rm "$out" > /dev/null 2>&1 || true
mkdir -p "$(dirname $out)"
touch "$out"
for file in $(find "${output}" -type f | sort -V); do
    cat "$file" >> "$out"
    echo "---" >> "$out"
done
