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

if [ -z "${1:-}" ]; then
	echo "usage: $0 <path to helm chart tarball>"
	exit 1
fi

chart_tarball=$1

chart_dir="deploy/charts/cert-manager"

echo "Linting chart '${chart_tarball}' using internal dir '${chart_dir}'"

tmpdir="$(mktemp -d)"
trap "rm -rf ${tmpdir}" EXIT

tar -C "${tmpdir}" -xvf $chart_tarball

if ! docker run -v "${tmpdir}":/workspace --workdir /workspace \
    quay.io/helmpack/chart-testing:v3.4.0 \
    ct lint \
        --check-version-increment=false \
        --validate-maintainers=false \
        --charts "/workspace/cert-manager" \
        --debug; then
    echo "Linting failed"
    exit 1
fi

echo "Linting succeeded!"
