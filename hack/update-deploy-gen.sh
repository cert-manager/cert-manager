#!/bin/bash

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
