#!/usr/bin/env bash

# Copyright 2020 The Jetstack cert-manager contributors.
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

set -o nounset
set -o errexit
set -o pipefail

# This script will run the end-to-end test suite against an already configured
# kind cluster.
# If a cluster does not already exist, create one with 'cluster/create.sh'.

export SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/lib/lib.sh"

check_bazel

mkdir -p "${REPO_ROOT}/_artifacts"
bazel build //hack/bin:helm //test/e2e:e2e.test
# Set KUBECONFIG environment variable if not already set
export KUBECONFIG="${KUBECONFIG:-$HOME/.kube/config}"
# Run e2e tests
bazel run @com_github_onsi_ginkgo//ginkgo -- \
	-nodes 10 \
	-flakeAttempts ${FLAKE_ATTEMPTS:-1} \
	$(bazel info bazel-genfiles)/test/e2e/e2e.test \
	-- \
	--repo-root="${REPO_ROOT}" \
	--report-dir="${ARTIFACTS:-$REPO_ROOT/_artifacts}" \
	"$@"
