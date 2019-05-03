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

readonly REPO_ROOT=$(git rev-parse --show-toplevel)

chart_dir="deploy/charts/cert-manager"

echo "Linting chart: ${chart_dir}"

cleanup() {
    rm "${REPO_ROOT}/${chart_dir}"/requirements.lock > /dev/null 2>&1 || true
}

cleanup
trap cleanup EXIT

if ! docker run -v ${REPO_ROOT}:/workspace --workdir /workspace \
    quay.io/helmpack/chart-testing:v2.3.3 \
    ct lint \
        --check-version-increment=false \
        --charts "/workspace/${chart_dir}" \
        --validate-maintainers=false \
        --debug; then
    echo "Linting failed"
    exit 1
fi

echo "Linting succeeded!"
