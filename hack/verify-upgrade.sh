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
export APP_VERSION="$(date +"%s")"

kube::version::last_published_release

LATEST_RELEASE="${KUBE_LAST_RELEASE}"

# Ensure helm, kind, kubectl, ytt are available
echo "Building the required tools.."
bazel build //hack/bin:helm //hack/bin:kind //hack/bin:ytt //hack/bin:kubectl //hack/bin:kubectl-cert_manager
bindir="$(bazel info bazel-bin)"
export PATH="${bindir}/hack/bin/:$PATH"

# Build images from latest master and load into the kind cluster. These will be
# used when upgrading with both kubectl and helm.
# Tag images with APP_VERSION for consistency with devel/addon/certmanager/install.sh.
echo "Building latest cert-manger images.."
APP_VERSION=${APP_VERSION} \
bazel run \
  --stamp=true \
  --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 \
  "//devel/addon/certmanager:bundle"

echo "Loading latest cert-manager images to cluster.."
load_image "quay.io/jetstack/cert-manager-controller:${APP_VERSION}" &
load_image "quay.io/jetstack/cert-manager-acmesolver:${APP_VERSION}" &
load_image "quay.io/jetstack/cert-manager-cainjector:${APP_VERSION}" &
load_image "quay.io/jetstack/cert-manager-webhook:${APP_VERSION}" &
load_image "quay.io/jetstack/cert-manager-ctl:${APP_VERSION}" &
wait

# Namespace to deploy into
NAMESPACE="${NAMESPACE:-cert-manager}"
# Release name to use with Helm
RELEASE_NAME="${RELEASE_NAME:-cert-manager}"
# cert-manager Helm chart
HELM_CHART="jetstack/cert-manager"

############
# VERIFY INSTALL, UPGRADE, UNINSTALL WITH HELM
############

echo "Testing upgrade from ${LATEST_RELEASE} to commit ${KUBE_GIT_COMMIT} with Helm.."

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
kubectl cert-manager check api --wait=2m -v

echo "Creating some cert-manager resources.."

# Create a cert-manager issuer and cert
kubectl apply -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml" --selector=test="first"

# Ensure cert becomes ready
kubectl wait --for=condition=Ready cert/test1 --timeout=180s

# 2. BUILD AND UPGRADE TO HELM CHART FROM THE CURRENT MASTER

bazel build //deploy/charts/cert-manager

echo "Upgrading cert-manager Helm release to commit ${KUBE_GIT_COMMIT}..."
helm upgrade \
    --install \
    --wait \
    --namespace "${NAMESPACE}" \
    --set installCRDs=true \
    --create-namespace \
    "$RELEASE_NAME" \
    "$REPO_ROOT/bazel-bin/deploy/charts/cert-manager/cert-manager.tgz"

# Wait for the cert-manager api to be available
kubectl cert-manager check api --wait=2m -v

# Test that the existing cert-manager resources can still be retrieved
kubectl get issuer/selfsigned-issuer cert/test1

echo "Creating some cert-manager resources.."

# # Create another certificate
kubectl apply -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml" --selector=test="second"

# Ensure cert becomes ready
kubectl wait --for=condition=Ready cert/test2 --timeout=180s

# 3. UNINSTALL HELM RELEASE
echo "Uninstalling the Helm release.."

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

echo "Testing cert-manager upgrade from ${LATEST_RELEASE} to commit ${KUBE_GIT_COMMIT} with static manifests.."

echo "Install cert-manager ${LATEST_RELEASE} using static manifests.."
kubectl apply \
	-f "https://github.com/cert-manager/cert-manager/releases/download/${LATEST_RELEASE}/cert-manager.yaml" \
	--wait

kubectl wait \
	--for=condition=available \
	--timeout=180s deployment/cert-manager-webhook \
	--namespace "${NAMESPACE}"

# Wait for the cert-manager api to be available
kubectl cert-manager check api --wait=2m -v

# Create a cert-manager issuer and cert
kubectl apply -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml" --selector=test="first"

# Ensure cert becomes ready
kubectl wait --for=condition=Ready cert/test1 --timeout=180s

# 2. VERIFY UPGRADE TO THE LATEST BUILD FROM MASTER

echo "Install cert-manager commit ${KUBE_GIT_COMMIT} using static manifests.."

# Build the static manifests
bazel build //deploy/manifests

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
kubectl cert-manager check api --wait=2m -v

# Test that the existing cert-manager resources can still be retrieved
kubectl get issuer/selfsigned-issuer cert/test1

echo "Creating some cert-manager resources.."

# # Create another certificate
kubectl apply -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml" --selector=test="second"

# Ensure cert becomes ready
kubectl wait --for=condition=Ready cert/test2 --timeout=180s

echo "Uninstalling cert-manager.."

# 3. UNINSTALL
kubectl delete \
	-f "${REPO_ROOT}/bazel-bin/deploy/manifests/cert-manager.yaml" \
	--wait \
