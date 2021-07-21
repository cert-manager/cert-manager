#!/usr/bin/env bash

# Copyright 2021 The cert-manager Authors.
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
source "${REPO_ROOT}/devel/lib/lib.sh"
source "${REPO_ROOT}/hack/build/version.sh"

kube::version::last_published_release

LATEST_RELEASE="${KUBE_LAST_RELEASE}"
CURRENT_VERSION="${KUBE_GIT_VERSION}"

# Ensure helm, kind, kubectl, ytt, jq are available
bazel build //hack/bin:helm //hack/bin:kind //hack/bin:ytt //hack/bin:jq //hack/bin:kubectl //hack/bin:kubectl-cert_manager
bindir="$(bazel info bazel-bin)"
export PATH="${bindir}/hack/bin/:$PATH"

echo "Testing upgrade from ${LATEST_RELEASE} to ${CURRENT_VERSION}"

# Namespace to deploy into
NAMESPACE="${NAMESPACE:-cert-manager}"
# Release name to use with Helm
RELEASE_NAME="${RELEASE_NAME:-cert-manager}"
# cert-manager Helm chart
HELM_CHART="jetstack/cert-manager"

############
# VERIFY INSTALL, UPGRADE, UNINSTALL WITH HELM
############

# This will target the host's helm repository cache
helm repo add jetstack https://charts.jetstack.io
helm repo update

# 1. INSTALL THE LATEST PUBLISHED HELM CHART

echo "Installing cert-manager ${LATEST_RELEASE} Helm chart into the cluster..."

# Upgrade or install latest published cert-manager Helm release
helm upgrade \
    --install \
    --wait \
    --namespace "${NAMESPACE}" \
    --set installCRDs=true \
    --create-namespace \
    --version "${LATEST_RELEASE}" \
    "$RELEASE_NAME" \
    "$HELM_CHART"

# Wait for the cert-manager api to be available
kubectl cert-manager check api --wait=1m -v

# Create a cert-manager issuer and cert
kubectl apply -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml" --selector=test="first"

# Ensure cert becomes ready
kubectl wait --for=condition=Ready cert/test1 --timeout=180s

# 1. BUILD AND UPGRADE TO HELM CHART FROM THE CURRENT MASTER

echo "Upgrading cert-manager Helm release to ${CURRENT_VERSION}..."
"${REPO_ROOT}/devel/addon/certmanager/install.sh"

# Wait for the cert-manager api to be available
kubectl cert-manager check api --wait=1m -v

# Test that the existing cert-manager resources can still be retrieved
kubectl get issuer/selfsigned-issuer cert/test1

# # Create another certificate
kubectl apply -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml" --selector=test="second"

# Ensure cert becomes ready
kubectl wait --for=condition=Ready cert/test2 --timeout=180s

# 1. UNINSTALL HELM RELEASE
kubectl delete \
	-f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml"

helm uninstall \
    --namespace "${NAMESPACE}" \
    "$RELEASE_NAME"

kubectl delete "namespace/${NAMESPACE}" \
	--wait

############
# VERIFY INSTALL, UPGRADE, UNINSTALL WITH STATIC MANIFESTS
############

# 1. INSTALL THE LATEST PUBLISHED RELEASE WITH STATIC MANIFESTS

echo "Install cert-manager ${LATEST_RELEASE} using static manifests.."
kubectl apply \
	-f "https://github.com/jetstack/cert-manager/releases/download/${LATEST_RELEASE}/cert-manager.yaml" \
	--wait

kubectl wait \
	--for=condition=available \
	--timeout=180s deployment/cert-manager-webhook \
	--namespace "${NAMESPACE}"

# Wait for the cert-manager api to be available
kubectl cert-manager check api --wait=1m -v

# Create a cert-manager issuer and cert
kubectl apply -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml" --selector=test="first"

# Ensure cert becomes ready
kubectl wait --for=condition=Ready cert/test1 --timeout=180s

# 2. VERIFY UPGRADE TO THE LATEST BUILD FROM MASTER

echo "Install cert-manager ${CURRENT_VERSION} using static manifests.."

# Build the static manifests
bazel build //deploy/manifests

# TODO: refactor this functionality here and in
# devel/addon/certmanager/install.sh so it can be reused.
# Tag images with APP_VERSION for consistency with devel/addon/certmanager/install.sh.
export APP_VERSION="$(date +"%s")"
# Build cert-manager images.
bazel run --stamp=true \
 --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 \
 "//devel/addon/certmanager:bundle"

# Load all images into the cluster
load_image "quay.io/jetstack/cert-manager-controller:${APP_VERSION}" &
load_image "quay.io/jetstack/cert-manager-acmesolver:${APP_VERSION}" &
load_image "quay.io/jetstack/cert-manager-cainjector:${APP_VERSION}" &
load_image "quay.io/jetstack/cert-manager-webhook:${APP_VERSION}" &
wait

# Overwrite image tags in the static manifests and deploy.
ytt -f "${REPO_ROOT}/test/fixtures/upgrade/overlay/controller-ops.yaml" \
	-f "${REPO_ROOT}/test/fixtures/upgrade/overlay/cainjector-ops.yaml" \
	-f "${REPO_ROOT}/test/fixtures/upgrade/overlay/webhook-ops.yaml" \
	-f "${REPO_ROOT}/test/fixtures/upgrade/overlay/values.yaml" \
	-f "${REPO_ROOT}/bazel-bin/deploy/manifests/cert-manager.yaml" \
	--data-value app_version="${APP_VERSION}" \
	--ignore-unknown-comments | kubectl apply -f -

rollout_cmd="kubectl rollout status deployment/cert-manager-webhook --namespace ${NAMESPACE}"
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
kubectl cert-manager check api --wait=1m -v

# Test that the existing cert-manager resources can still be retrieved
kubectl get issuer/selfsigned-issuer cert/test1

# # Create another certificate
kubectl apply -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml" --selector=test="second"

# Ensure cert becomes ready
kubectl wait --for=condition=Ready cert/test2 --timeout=180s

# 3. UNINSTALL
kubectl delete \
	-f "${REPO_ROOT}/bazel-bin/deploy/manifests/cert-manager.yaml" \
	--wait \
