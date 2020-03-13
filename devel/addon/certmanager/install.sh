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

# Namespace to deploy into
NAMESPACE="${NAMESPACE:-cert-manager}"
# Release name to use with Helm
RELEASE_NAME="${RELEASE_NAME:-cert-manager}"

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/../../lib/lib.sh"
SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")

# Require kubectl & helm available on PATH
check_tool kubectl
check_tool helm

# Use the current timestamp as the APP_VERSION so a rolling update will be
# triggered on every call to this script.
export APP_VERSION="$(date +"%s")"
# Build a copy of the cert-manager release images using the :bazel image tag
bazel run --stamp=true --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 "//devel/addon/certmanager:bundle"

# Load all images into the kind cluster
kind load docker-image --name "$KIND_CLUSTER_NAME" "quay.io/jetstack/cert-manager-controller:${APP_VERSION}" &
kind load docker-image --name "$KIND_CLUSTER_NAME" "quay.io/jetstack/cert-manager-acmesolver:${APP_VERSION}" &
kind load docker-image --name "$KIND_CLUSTER_NAME" "quay.io/jetstack/cert-manager-cainjector:${APP_VERSION}" &
kind load docker-image --name "$KIND_CLUSTER_NAME" "quay.io/jetstack/cert-manager-webhook:${APP_VERSION}" &

wait

# Ensure the pebble namespace exists
kubectl get namespace "${NAMESPACE}" || kubectl create namespace "${NAMESPACE}"

crdsmanifest="cert-manager.crds.yaml"
if [[ "$K8S_VERSION" =~ 1\.1[1-4] ]]; then
  crdsmanifest="cert-manager-legacy.crds.yaml"
fi
bazel build "//deploy/manifests:$crdsmanifest"

# Install a copy of the CRDs
kubectl apply -f "${REPO_ROOT}/bazel-bin/deploy/manifests/$crdsmanifest"

# Build the Helm chart package .tgz
bazel build //deploy/charts/cert-manager:package

# Upgrade or install Pebble
helm upgrade \
    --install \
    --wait \
    --namespace "${NAMESPACE}" \
    --set image.tag="${APP_VERSION}" \
    --set cainjector.image.tag="${APP_VERSION}" \
    --set webhook.image.tag="${APP_VERSION}" \
    --set 'extraArgs={--dns01-recursive-nameservers=10.0.0.16:53,--dns01-recursive-nameservers-only=true}' \
    "$RELEASE_NAME" \
    "$REPO_ROOT/bazel-bin/deploy/charts/cert-manager/cert-manager.tgz"
