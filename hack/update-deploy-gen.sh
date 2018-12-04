#!/bin/bash

# Copyright 2018 The Jetstack cert-manager contributors.
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

# This script should be run via `bazel run //hack:update-deploy-gen`
REPO_ROOT=${BUILD_WORKSPACE_DIRECTORY:-"$(cd "$(dirname "$0")" && pwd -P)"/..}
runfiles="$(pwd)"
export PATH="${runfiles}/hack/bin:${PATH}"
cd "${REPO_ROOT}"

# This will set Capabilities.KubeVersion.Major/Minor when generating manifests
KUBE_VERSION=1.9

gen() {
	OUTPUT=$1
	TMP_OUTPUT=$(mktemp)
	mkdir -p "$(dirname ${OUTPUT})"
	helm template \
		"${REPO_ROOT}/deploy/chart" \
		--values "${REPO_ROOT}/deploy/manifests/helm-values.yaml" \
		--kube-version "${KUBE_VERSION}" \
		--namespace "cert-manager" \
		--name "cert-manager" \
		--set "createNamespaceResource=true" > "${TMP_OUTPUT}"
	mv "${TMP_OUTPUT}" "${OUTPUT}"
}

export HELM_HOME="$(mktemp -d)"
helm init --client-only
helm dep update "${REPO_ROOT}/deploy/chart"
gen "${REPO_ROOT}/deploy/manifests/cert-manager.yaml"
