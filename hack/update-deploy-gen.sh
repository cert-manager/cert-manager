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
	OUTPUT_DIR=$2
	TMP_OUTPUT=$(mktemp -d)
	mkdir -p "${OUTPUT_DIR}"
	helm template \
		"${REPO_ROOT}/contrib/charts/cert-manager" \
		--values "${SCRIPT_ROOT}/deploy/${VALUES}.yaml" \
		--kube-version "${KUBE_VERSION}" \
		--namespace "cert-manager" \
		--name "cert-manager" \
		--set "fullnameOverride=cert-manager" \
		--set "createNamespaceResource=true" \
		--output-dir "${TMP_OUTPUT}"
	mv "${TMP_OUTPUT}"/cert-manager/templates/*.* "${OUTPUT_DIR}/"
}

gen rbac-values "${REPO_ROOT}/contrib/manifests/cert-manager/rbac"
gen without-rbac-values "${REPO_ROOT}/contrib/manifests/cert-manager/without-rbac"
