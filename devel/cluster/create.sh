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
  # v1.12.10 @ sha256:68a6581f64b54994b824708286fafc37f1227b7b54cbb8865182ce1e036ed1cc
  KIND_IMAGE_SHA="sha256:68a6581f64b54994b824708286fafc37f1227b7b54cbb8865182ce1e036ed1cc"
  KIND_IMAGE_CONFIG="v1alpha3"
elif [[ "$K8S_VERSION" =~ 1\.13 ]] ; then
  # v1.13.12 @sha256:5e8ae1a4e39f3d151d420ef912e18368745a2ede6d20ea87506920cd947a7e3a
  KIND_IMAGE_SHA="sha256:5e8ae1a4e39f3d151d420ef912e18368745a2ede6d20ea87506920cd947a7e3a"
  KIND_IMAGE_CONFIG="v1beta1"
elif [[ "$K8S_VERSION" =~ 1\.14 ]] ; then
  # v1.14.10 @ sha256:81ae5a3237c779efc4dda43cc81c696f88a194abcc4f8fa34f86cf674aa14977
  KIND_IMAGE_SHA="sha256:81ae5a3237c779efc4dda43cc81c696f88a194abcc4f8fa34f86cf674aa14977"
  KIND_IMAGE_CONFIG="v1beta1"
elif [[ "$K8S_VERSION" =~ 1\.15 ]] ; then
  # v1.15.7 @ sha256:e2df133f80ef633c53c0200114fce2ed5e1f6947477dbc83261a6a921169488d
  KIND_IMAGE_SHA="sha256:e2df133f80ef633c53c0200114fce2ed5e1f6947477dbc83261a6a921169488d"
  KIND_IMAGE_CONFIG="v1beta2"
elif [[ "$K8S_VERSION" =~ 1\.16 ]] ; then
  # v1.16.4 @ sha256:b91a2c2317a000f3a783489dfb755064177dbc3a0b2f4147d50f04825d016f55
  KIND_IMAGE_SHA="sha256:b91a2c2317a000f3a783489dfb755064177dbc3a0b2f4147d50f04825d016f55"
  KIND_IMAGE_CONFIG="v1beta2"
elif [[ "$K8S_VERSION" =~ 1\.17 ]] ; then
  # v1.17.0 @ sha256:9512edae126da271b66b990b6fff768fbb7cd786c7d39e86bdf55906352fdf62
  KIND_IMAGE_SHA="sha256:9512edae126da271b66b990b6fff768fbb7cd786c7d39e86bdf55906352fdf62"
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
