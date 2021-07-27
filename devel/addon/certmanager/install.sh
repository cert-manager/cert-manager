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
FEATURE_GATES="${FEATURE_GATES:-ExperimentalCertificateSigningRequestControllers=true}"

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/../../lib/lib.sh"
SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")

# Require kubectl & helm available on PATH
check_tool kubectl
check_tool kubectl-cert_manager
check_tool helm

# Use the current timestamp as the APP_VERSION so a rolling update will be
# triggered on every call to this script.
export APP_VERSION="$(date +"%s")"
# Build a copy of the cert-manager release images using the :bazel image tag
bazel run --stamp=true --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 "//devel/addon/certmanager:bundle"

# Load all images into the cluster
load_image "quay.io/jetstack/cert-manager-controller:${APP_VERSION}" &
load_image "quay.io/jetstack/cert-manager-acmesolver:${APP_VERSION}" &
load_image "quay.io/jetstack/cert-manager-cainjector:${APP_VERSION}" &
load_image "quay.io/jetstack/cert-manager-webhook:${APP_VERSION}" &
wait

# Ensure the namespace exists, and if not create it
kubectl get namespace "${NAMESPACE}" || kubectl create namespace "${NAMESPACE}"

# Build the Helm chart package .tgz
bazel build //deploy/charts/cert-manager

# Pre-compile the kubectl plugin, so it can quickly check the api status
bazel build //hack/bin:kubectl-cert_manager

# Upgrade or install cert-manager
helm upgrade \
    --install \
    --wait \
    --namespace "${NAMESPACE}" \
    --set-string image.tag="${APP_VERSION}" \
    --set-string cainjector.image.tag="${APP_VERSION}" \
    --set-string webhook.image.tag="${APP_VERSION}" \
    --set installCRDs=true \
    --set-string featureGates="${FEATURE_GATES:-}" \
    --set-string "extraArgs={--dns01-recursive-nameservers=${SERVICE_IP_PREFIX}.16:53,--dns01-recursive-nameservers-only=true,--controllers=*\,gateway-shim}" \
    "$RELEASE_NAME" \
    "$REPO_ROOT/bazel-bin/deploy/charts/cert-manager/cert-manager.tgz"

kubectl cert-manager check api --wait=1m -v
