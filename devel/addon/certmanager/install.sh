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

set -o nounset
set -o errexit
set -o pipefail

# Namespace to deploy into
NAMESPACE="${NAMESPACE:-cert-manager}"
# Release name to use with Helm
RELEASE_NAME="${RELEASE_NAME:-cert-manager}"
# Default feature gates to enable
FEATURE_GATES="${FEATURE_GATES:-ExperimentalCertificateSigningRequestControllers=true,ExperimentalGatewayAPISupport=true,AdditionalCertificateOutputFormats=true,ServerSideApply=true}"

# As Feature Gates are added/removed, these lists should be updated.
declare -a FEATURE_GATES_CONTROLLER_ALL=(\
"AllAlpha","AllBeta","ValidateCAA","ExperimentalCertificateSigningRequestControllers",\
"ExperimentalGatewayAPISupport","AdditionalCertificateOutputFormats","ServerSideApply")
declare -a FEATURE_GATES_WEBHOOK_ALL=(\
"AllAlpha","AllBeta","AdditionalCertificateOutputFormats")
declare -a FEATURE_GATES_CAINJECTOR_ALL=(\
"AllAlpha","AllBeta")

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/../../lib/lib.sh"
SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")

FEATURE_GATES_CONTROLLER=$(registered_feature_gates_for $FEATURE_GATES_CONTROLLER_ALL "${FEATURE_GATES}")
FEATURE_GATES_WEBHOOK=$(registered_feature_gates_for $FEATURE_GATES_WEBHOOK_ALL "${FEATURE_GATES}")
FEATURE_GATES_CAINJECTOR=$(registered_feature_gates_for $FEATURE_GATES_CAINJECTOR_ALL "${FEATURE_GATES}")

# Require kubectl & helm available on PATH
check_tool kubectl
check_tool kubectl-cert_manager
check_tool helm

# Use the current timestamp as the APP_VERSION so a rolling update will be
# triggered on every call to this script.
export APP_VERSION="$(date +"%s")"
# Build a copy of the cert-manager release images using the :bazel image tag

ARCH="$(uname -m)"
if [ "$ARCH" == "arm64" ] ; then
    bazel run --stamp=true --platforms=@io_bazel_rules_go//go/toolchain:linux_arm64 "//devel/addon/certmanager:bundle"
else
    bazel run --stamp=true --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 "//devel/addon/certmanager:bundle"
fi

# Load all images into the cluster
load_image "quay.io/jetstack/cert-manager-controller:${APP_VERSION}" &
load_image "quay.io/jetstack/cert-manager-acmesolver:${APP_VERSION}" &
load_image "quay.io/jetstack/cert-manager-cainjector:${APP_VERSION}" &
load_image "quay.io/jetstack/cert-manager-webhook:${APP_VERSION}" &
load_image "quay.io/jetstack/cert-manager-ctl:${APP_VERSION}" &
wait

# Ensure the namespace exists, and if not create it
kubectl get namespace "${NAMESPACE}" || kubectl create namespace "${NAMESPACE}"

# Build the Helm chart package .tgz
bazel build //deploy/charts/cert-manager

# Upgrade or install cert-manager
# --wait & --wait-for-jobs flags should wait for resources and Jobs to complete
helm upgrade \
    --install \
    --wait \
    --namespace "${NAMESPACE}" \
    --set image.tag="${APP_VERSION}" \
    --set cainjector.image.tag="${APP_VERSION}" \
    --set webhook.image.tag="${APP_VERSION}" \
    --set startupapicheck.image.tag="${APP_VERSION}" \
    --set installCRDs=true \
    `# escape commas in --set by replacing , with \, (see https://github.com/helm/helm/issues/2952)` \
    --set featureGates="${FEATURE_GATES_CONTROLLER//,/\\,}" \
    --set "webhook.extraArgs={--feature-gates=${FEATURE_GATES_WEBHOOK//,/\\,}}" \
    --set "cainjector.extraArgs={--feature-gates=${FEATURE_GATES_CAINJECTOR//,/\\,}}"\
    --set "extraArgs={--dns01-recursive-nameservers=${SERVICE_IP_PREFIX}.16:53,--dns01-recursive-nameservers-only=true}" \
    "$RELEASE_NAME" \
    "$REPO_ROOT/bazel-bin/deploy/charts/cert-manager/cert-manager.tgz"

# Sanity check (fail if api is not yet available)
kubectl cert-manager check api
# Print the cert-manager client and server versions
kubectl cert-manager version -o yaml
