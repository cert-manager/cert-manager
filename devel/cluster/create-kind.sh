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

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/../lib/lib.sh"
SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")

setup_tools

# Require kind & kubectl available on PATH
check_tool kubectl

# Specifies which Kind binary to use, allows to override for older version
KIND_BIN="${KIND}"

# Compute the details of the kind image to use
export KIND_IMAGE_SHA=""
if [[ "$K8S_VERSION" =~ 1\.16 ]] ; then
  # v1.16.9@sha256:7175872357bc85847ec4b1aba46ed1d12fa054c83ac7a8a11f5c268957fd5765
  KIND_IMAGE_SHA="sha256:83067ed51bf2a3395b24687094e283a7c7c865ccc12a8b1d7aa673ba0c5e8861"
elif [[ "$K8S_VERSION" =~ 1\.17 ]] ; then
  # v1.17.5@sha256:ab3f9e6ec5ad8840eeb1f76c89bb7948c77bbf76bcebe1a8b59790b8ae9a283a
  KIND_IMAGE_SHA="sha256:66f1d0d91a88b8a001811e2f1054af60eef3b669a9a74f9b6db871f2f1eeed00"
elif [[ "$K8S_VERSION" =~ 1\.18 ]] ; then
  # v1.18.2@sha256:7b27a6d0f2517ff88ba444025beae41491b016bc6af573ba467b70c5e8e0d85f
  KIND_IMAGE_SHA="sha256:7af1492e19b3192a79f606e43c35fb741e520d195f96399284515f077b3b622c"
elif [[ "$K8S_VERSION" =~ 1\.19 ]] ; then
  KIND_IMAGE_SHA="sha256:07db187ae84b4b7de440a73886f008cf903fcf5764ba8106a9fd5243d6f32729"
elif [[ "$K8S_VERSION" =~ 1\.20 ]] ; then
  KIND_IMAGE_SHA="sha256:cbeaf907fc78ac97ce7b625e4bf0de16e3ea725daf6b04f930bd14c67c671ff9"
elif [[ "$K8S_VERSION" =~ 1\.21 ]] ; then
  KIND_IMAGE_SHA="sha256:0fda882e43d425622f045b492f8bd83c2e0b4984fc03e2e05ec101ca1a685fb7"
elif [[ "$K8S_VERSION" =~ 1\.22 ]] ; then
  KIND_IMAGE_SHA="sha256:1dfd72d193bf7da64765fd2f2898f78663b9ba366c2aa74be1fd7498a1873166"
else
  echo "Unrecognised Kubernetes version '${K8S_VERSION}'! Aborting..."
  exit 1
fi
export KIND_IMAGE="${KIND_IMAGE_REPO}@${KIND_IMAGE_SHA}"
echo "kind image details:"
echo "  repo:    ${KIND_IMAGE_REPO}"
echo "  sha256:  ${KIND_IMAGE_SHA}"
echo "  version: ${K8S_VERSION}"

if $KIND_BIN get clusters | grep "^$KIND_CLUSTER_NAME\$" &>/dev/null; then
  echo "Existing cluster '$KIND_CLUSTER_NAME' found, skipping creating cluster..."
  exit 0
fi

# Create the kind cluster
$KIND_BIN create cluster \
  --config "${SCRIPT_ROOT}/config/v1beta2.yaml" \
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
