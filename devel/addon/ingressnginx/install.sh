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
source "${SCRIPT_ROOT}/../../lib/lib.sh"
SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")

# Installs an instance of ingress-nginx using the 'stable' Helm chart.
# Configure the cluster to target using the KUBECONFIG environment variable.
# Additional parameters can be configured by overriding the variables below.

# Namespace to deploy into
NAMESPACE="${NAMESPACE:-ingress-nginx}"
if [[ "$IS_OPENSHIFT" == "true" ]] ; then
  # OpenShift needs bind to be in kube-system due to file ownership restrictions
  NAMESPACE="kube-system"
fi
# Release name to use with Helm
RELEASE_NAME="${RELEASE_NAME:-ingress-nginx}"

# Require helm available on PATH
check_tool kubectl
check_tool helm
require_image "quay.io/kubernetes-ingress-controller/nginx-ingress-controller:0.33.0" "//devel/addon/ingressnginx:bundle"
require_image "k8s.gcr.io/defaultbackend-amd64:bazel" "//devel/addon/ingressnginx:bundle"

# Ensure the ingress-nginx namespace exists
kubectl get namespace "${NAMESPACE}" || kubectl create namespace "${NAMESPACE}"

helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx

helm repo update

# Upgrade or install nginx-ingress
helm upgrade \
    --install \
    --wait \
    --version 2.9.0 \
    --namespace "${NAMESPACE}" \
    --set controller.image.tag=0.33.0 \
    --set controller.image.pullPolicy=Never \
    --set defaultBackend.image.tag=bazel \
    --set defaultBackend.image.pullPolicy=Never \
    --set "controller.service.clusterIP=${SERVICE_IP_PREFIX}.15"\
    --set controller.service.type=ClusterIP \
    --set controller.config.no-tls-redirect-locations="" \
    --set admissionWebhooks.enabled=false \
    --set controller.admissionWebhooks.enabled=false \
    --set controller.image.runAsUser="" \
    --set controller.defaultBackend.runAsUser="" \
    "$RELEASE_NAME" \
    ingress-nginx/ingress-nginx
