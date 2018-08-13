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

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
REPO_ROOT="${SCRIPT_ROOT}/.."
# This will set Capabilities.KubeVersion.Major/Minor when generating manifests
KUBE_VERSION=1.9

gen() {
	VALUES=$1
	OUTPUT=$2
	TMP_OUTPUT=$(mktemp)
	mkdir -p "$(dirname ${OUTPUT})"
	helm template \
		"${REPO_ROOT}/contrib/charts/cert-manager" \
		--values "${SCRIPT_ROOT}/deploy/${VALUES}.yaml" \
		--kube-version "${KUBE_VERSION}" \
		--namespace "cert-manager" \
		--name "cert-manager" \
		--set "fullnameOverride=cert-manager" \
		--set "createNamespaceResource=true" > "${TMP_OUTPUT}"
	mv "${TMP_OUTPUT}" "${OUTPUT}"
}

gen rbac-values "${REPO_ROOT}/contrib/manifests/cert-manager/with-rbac.yaml"
gen without-rbac-values "${REPO_ROOT}/contrib/manifests/cert-manager/without-rbac.yaml"
