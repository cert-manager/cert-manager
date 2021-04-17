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

# Installs Istio using istioctl and the manifests located in manifests/
# Configure the cluster to target using the KUBECONFIG environment variable.
# Additional parameters can be configured by overriding the variables below.

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/../../lib/lib.sh"
SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")

check_tool kubectl
check_tool istioctl

# Namespace to deploy into
NAMESPACE="${NAMESPACE:-istio-system}"

SERVICE_IP_PREFIX="${SERVICE_IP_PREFIX:-10.0.0}"

istioctl install \
    --skip-confirmation \
    --set profile=default \
    --set values.global.jwtPolicy=first-party-jwt \
    --set components.ingressGateways[0].name="istio-ingressgateway" \
    --set components.ingressGateways[0].k8s.service.type="ClusterIP" \
    --set components.ingressGateways[0].k8s.service.clusterIP="${SERVICE_IP_PREFIX}.14"

kubectl --namespace "${NAMESPACE}" apply -f "${SCRIPT_ROOT}/manifests/gateway.yaml"
