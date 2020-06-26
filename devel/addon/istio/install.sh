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

# Installs Istio using istioctl and the manifests located in manifests/
# Configure the cluster to target using the KUBECONFIG environment variable.
# Additional parameters can be configured by overriding the variables below.

# Namespace to deploy into
NAMESPACE="${NAMESPACE:-istio-system}"
# Release name to use with Helm
RELEASE_NAME="${RELEASE_NAME:-istio-operator}"

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/../../lib/lib.sh"
SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")

check_tool kubectl
check_tool helm

helm repo add banzaicloud-stable https://kubernetes-charts.banzaicloud.com/

helm repo update

# Ensure the namespace exists
kubectl get namespace "${NAMESPACE}" || kubectl create namespace "${NAMESPACE}"

# TODO set imagePullPolicy to Never
helm upgrade --install --wait --namespace="${NAMESPACE}" "${RELEASE_NAME}" banzaicloud-stable/istio-operator

kubectl apply --namespace="${NAMESPACE}" -f "$SCRIPT_ROOT/manifests/istio_v1beta1_istio_minimal.yaml"

# Istio CRDs are installed by the operator, so this might not succeed on first run
while ! kubectl apply --namespace "${NAMESPACE}" -f "$SCRIPT_ROOT/manifests/"; do
  sleep 1
done
