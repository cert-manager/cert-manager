#!/usr/bin/env bash

# Copyright 2022 The cert-manager Authors.
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

HACK_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"

CTR=${CTR:-docker}
HELM=${HELM:-helm}
HELMCHK=${HELMCHK:-helmchk}

chart_tarball=${1:-}

if [ -z "${chart_tarball}" ]; then
    echo "usage: $0 <path to helm chart tarball>"
    exit 1
fi

echo "Linting chart '${chart_tarball}'"

# Extract the chart tarball to a temporary directory
tmpdir="$(mktemp -d)"
trap "rm -rf ${tmpdir}" EXIT
tar -C "${tmpdir}" -xvf "$chart_tarball"

# Run helm lint
${HELM} lint "${tmpdir}/cert-manager"

# Run chart-testing lint
if ! ${CTR} run -v "${tmpdir}":/workspace --workdir /workspace \
    quay.io/helmpack/chart-testing:v3.8.0 \
    ct lint \
    --check-version-increment=false \
    --validate-maintainers=false \
    --charts "/workspace/cert-manager" \
    --debug; then
    echo "Linting failed"
    exit 1
fi

# Run helmchk
${HELMCHK} --exceptions "${HACK_DIR}/helmchk-exceptions.txt" "${tmpdir}/cert-manager"

echo "Linting succeeded!"
