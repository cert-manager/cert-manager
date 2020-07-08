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

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/../lib/lib.sh"
SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")

# Require kind & kubectl available on PATH
check_tool kind
check_tool kubectl

# Compute the details of the kind image to use
export KIND_IMAGE_SHA=""
export KIND_IMAGE_CONFIG=""
if [[ "$K8S_VERSION" =~ 1\.11 ]]; then
  # v1.11.10 @ sha256:e6f3dade95b7cb74081c5b9f3291aaaa6026a90a977e0b990778b6adc9ea6248
  KIND_IMAGE_SHA="sha256:e6f3dade95b7cb74081c5b9f3291aaaa6026a90a977e0b990778b6adc9ea6248"
  KIND_IMAGE_CONFIG="v1alpha2"
elif [[ "$K8S_VERSION" =~ 1\.12 ]]; then
  # v1.12.10@sha256:faeb82453af2f9373447bb63f50bae02b8020968e0889c7fa308e19b348916cb
  KIND_IMAGE_SHA="sha256:faeb82453af2f9373447bb63f50bae02b8020968e0889c7fa308e19b348916cb"
  KIND_IMAGE_CONFIG="v1alpha3"
elif [[ "$K8S_VERSION" =~ 1\.13 ]] ; then
  # v1.13.12@sha256:214476f1514e47fe3f6f54d0f9e24cfb1e4cda449529791286c7161b7f9c08e7
  KIND_IMAGE_SHA="sha256:214476f1514e47fe3f6f54d0f9e24cfb1e4cda449529791286c7161b7f9c08e7"
  KIND_IMAGE_CONFIG="v1beta1"
elif [[ "$K8S_VERSION" =~ 1\.14 ]] ; then
  # v1.14.10@sha256:6cd43ff41ae9f02bb46c8f455d5323819aec858b99534a290517ebc181b443c6
  KIND_IMAGE_SHA="sha256:6cd43ff41ae9f02bb46c8f455d5323819aec858b99534a290517ebc181b443c6"
  KIND_IMAGE_CONFIG="v1beta1"
elif [[ "$K8S_VERSION" =~ 1\.15 ]] ; then
  # v1.15.11@sha256:6cc31f3533deb138792db2c7d1ffc36f7456a06f1db5556ad3b6927641016f50
  KIND_IMAGE_SHA="sha256:6cc31f3533deb138792db2c7d1ffc36f7456a06f1db5556ad3b6927641016f50"
  KIND_IMAGE_CONFIG="v1beta2"
elif [[ "$K8S_VERSION" =~ 1\.16 ]] ; then
  # v1.16.9@sha256:7175872357bc85847ec4b1aba46ed1d12fa054c83ac7a8a11f5c268957fd5765
  KIND_IMAGE_SHA="sha256:7175872357bc85847ec4b1aba46ed1d12fa054c83ac7a8a11f5c268957fd5765"
  KIND_IMAGE_CONFIG="v1beta2"
elif [[ "$K8S_VERSION" =~ 1\.17 ]] ; then
  # v1.17.5@sha256:ab3f9e6ec5ad8840eeb1f76c89bb7948c77bbf76bcebe1a8b59790b8ae9a283a62
  KIND_IMAGE_SHA="sha256:ab3f9e6ec5ad8840eeb1f76c89bb7948c77bbf76bcebe1a8b59790b8ae9a283a62"
  KIND_IMAGE_CONFIG="v1beta2"
elif [[ "$K8S_VERSION" =~ 1\.18 ]] ; then
  # v1.18.2@sha256:7b27a6d0f2517ff88ba444025beae41491b016bc6af573ba467b70c5e8e0d85f
  KIND_IMAGE_SHA="sha256:7b27a6d0f2517ff88ba444025beae41491b016bc6af573ba467b70c5e8e0d85f"
  KIND_IMAGE_CONFIG="v1beta2"
elif [[ "$K8S_VERSION" =~ 1\.19 ]] ; then
  # munnerz/kind-nodev1.19.0-beta.2 @ sha256:6f7f88063041c7d005ce11ca663dee8320dfe87259c100b5152130481461033f
  KIND_IMAGE_SHA="sha256:6f7f88063041c7d005ce11ca663dee8320dfe87259c100b5152130481461033f"
  KIND_IMAGE_REPO="munnerz/kind-node"
  KIND_IMAGE_CONFIG="v1beta2"
else
  echo "Unrecognised Kubernetes version '${K8S_VERSION}'! Aborting..."
  exit 1
fi
export KIND_IMAGE="${KIND_IMAGE_REPO}@${KIND_IMAGE_SHA}"
echo "kind image details:"
echo "  repo:    ${KIND_IMAGE_REPO}"
echo "  sha256:  ${KIND_IMAGE_SHA}"
echo "  version: ${K8S_VERSION}"
echo "  config:  ${KIND_IMAGE_CONFIG}"

if kind get clusters | grep "^$KIND_CLUSTER_NAME\$" &>/dev/null; then
  echo "Existing cluster '$KIND_CLUSTER_NAME' found, skipping creating cluster..."
  exit 0
fi

# Create the kind cluster
kind create cluster \
  --config "${SCRIPT_ROOT}/config/${KIND_IMAGE_CONFIG}.yaml" \
  --image "${KIND_IMAGE}" \
  --name "${KIND_CLUSTER_NAME}"

# Get the current config
original_coredns_config=$(kubectl get -ogo-template='{{.data.Corefile}}' -n=kube-system configmap/coredns)
additional_coredns_config="$(printf 'example.com:53 {\n    forward . 10.0.0.16\n}\n')"
echo "Original CoreDNS config:"
echo "${original_coredns_config}"
# Patch it
fixed_coredns_config=$(
  printf '%s\n%s' "${original_coredns_config}" "${additional_coredns_config}"
)
echo "Patched CoreDNS config:"
echo "${fixed_coredns_config}"
kubectl create configmap -oyaml coredns --dry-run --from-literal=Corefile="${fixed_coredns_config}" | kubectl apply --namespace kube-system -f -
