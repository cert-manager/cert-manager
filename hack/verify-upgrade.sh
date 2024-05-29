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

set -o nounset
set -o errexit
set -o pipefail

SCRIPT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"
export REPO_ROOT="${SCRIPT_ROOT}/.."
source "${REPO_ROOT}/hack/build/version.sh"

kube::version::last_published_release

LATEST_RELEASE="${KUBE_LAST_RELEASE}"

usage_and_exit() {
	echo "usage: $0 <path-to-helm> <path-to-kind> <path-to-ytt> <path-to-kubectl> <path-to-cmctl>" >&2
	exit 1
}

if [[ -z "${1:-}" || -z "${2:-}" || -z "${3:-}" ||-z "${4:-}" || -z "${5:-}" ]]; then
	usage_and_exit
fi

helm=$(realpath "$1")
kind=$(realpath "$2")
ytt=$(realpath "$3")
kubectl=$(realpath "$4")
cmctl=$(realpath "$5")

# Set up a fresh kind cluster

$kind delete clusters kind || :
make e2e-setup-kind

################################################
# VERIFY INSTALL, UPGRADE, UNINSTALL WITH HELM #
################################################

# Namespace we'll deploy into
NAMESPACE="${NAMESPACE:-cert-manager}"

# Release name to use with Helm
RELEASE_NAME="${RELEASE_NAME:-cert-manager}"

HELM_URL="https://charts.jetstack.io"

# cert-manager Helm chart location
HELM_CHART="cmupgradetest/cert-manager"

echo "+++ Testing upgrading from ${LATEST_RELEASE} to commit ${KUBE_GIT_COMMIT} with Helm"

# This will target the host's helm repository cache
$helm repo add cmupgradetest $HELM_URL
$helm repo update

# 1. INSTALL THE LATEST PUBLISHED HELM CHART

echo "+++ Installing cert-manager ${LATEST_RELEASE} Helm chart into the cluster..."

# Upgrade or install latest published cert-manager Helm release
# We use the deprecated installCRDs=true value, to make the install work for older versions of cert-manager
$helm upgrade \
    --install \
    --wait \
    --namespace "${NAMESPACE}" \
    --set installCRDs=true \
    --create-namespace \
    --version "${LATEST_RELEASE}" \
    "$RELEASE_NAME" \
    "$HELM_CHART"

# Wait for the cert-manager api to be available
$cmctl check api --wait=2m -v=5

echo "+++ Creating some cert-manager resources.."

# Create a cert-manager issuer and cert
$kubectl apply -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml" --selector=test="first"

# Ensure cert becomes ready
$kubectl wait --for=condition=Ready cert/test1 --timeout=180s

# 2. BUILD AND UPGRADE TO HELM CHART FROM THE CURRENT MASTER

# e2e-setup-certamanager both builds and deploys the latest available chart based on the current checkout
make e2e-setup-certmanager

# Wait for the cert-manager api to be available
$cmctl check api --wait=2m -v=5

# Test that the existing cert-manager resources can still be retrieved
$kubectl get issuer/selfsigned-issuer cert/test1

echo "+++ Creating some more cert-manager resources.."

# Create another certificate
$kubectl apply -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml" --selector=test="second"

# Ensure cert becomes ready
$kubectl wait --for=condition=Ready cert/test2 --timeout=180s

# 3. UNINSTALL HELM RELEASE

echo "+++ Uninstalling the Helm release"

$kubectl delete -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml"

$helm uninstall \
    --namespace "${NAMESPACE}" \
    "$RELEASE_NAME"

$kubectl delete "namespace/${NAMESPACE}" --wait

############################################################
# VERIFY INSTALL, UPGRADE, UNINSTALL WITH STATIC MANIFESTS #
############################################################

# 1. INSTALL THE LATEST PUBLISHED RELEASE WITH STATIC MANIFESTS

echo "+++ Testing cert-manager upgrade from ${LATEST_RELEASE} to commit ${KUBE_GIT_COMMIT} using static manifests"

echo "+++ Installing cert-manager ${LATEST_RELEASE} using static manifests"

$kubectl apply \
	-f "https://github.com/cert-manager/cert-manager/releases/download/${LATEST_RELEASE}/cert-manager.yaml" \
	--wait

$kubectl wait \
	--for=condition=available \
	--timeout=180s deployment/cert-manager-webhook \
	--namespace "${NAMESPACE}"

# Wait for the cert-manager api to be available
$cmctl check api --wait=2m -v=5

# Create a cert-manager issuer and cert
$kubectl apply -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml" --selector=test="first"

# Ensure cert becomes ready
$kubectl wait --for=condition=Ready cert/test1 --timeout=180s

# 2. VERIFY UPGRADE TO THE LATEST BUILD FROM MASTER

MANIFEST_LOCATION=${REPO_ROOT}/_bin/yaml/cert-manager.yaml

echo "+++ Installing cert-manager commit ${KUBE_GIT_COMMIT} using static manifests"

# Build the static manifests
make release-manifests

RELEASE_VERSION=$(make --silent release-version)

# Overwrite image tags in the static manifests and deploy.
$ytt -f "${REPO_ROOT}/test/fixtures/upgrade/overlay/controller-ops.yaml" \
     -f "${REPO_ROOT}/test/fixtures/upgrade/overlay/cainjector-ops.yaml" \
     -f "${REPO_ROOT}/test/fixtures/upgrade/overlay/webhook-ops.yaml" \
     -f "${REPO_ROOT}/test/fixtures/upgrade/overlay/values.yaml" \
     -f $MANIFEST_LOCATION \
     --data-value app_version="${RELEASE_VERSION}" \
     --ignore-unknown-comments | kubectl apply -f -

rollout_cmd="$kubectl rollout status deployment/cert-manager-webhook --namespace ${NAMESPACE}"
attempts=0

until $rollout_cmd; do
  $rollout_cmd
  ((attempts++))
  if [[ $attempts -gt  30 ]]; then
    echo "Upgrade failed to complete in 5 minutes"
    exit 1
  fi
  sleep 10
done

# Wait for the cert-manager api to be available
$cmctl check api --wait=2m -v=5

# Test that the existing cert-manager resources can still be retrieved
$kubectl get issuer/selfsigned-issuer cert/test1

echo "+++ Creating some cert-manager resources"

# Create another certificate
$kubectl apply -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml" --selector=test="second"

# Ensure cert becomes ready
$kubectl wait --for=condition=Ready cert/test2 --timeout=180s

# 3. UNINSTALL

echo "+++ Uninstalling cert-manager"

$kubectl delete -f $MANIFEST_LOCATION --wait
