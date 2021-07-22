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
IMAGE_TAG=""

# Require helm, kubectl and jq available on PATH
check_tool kubectl
check_tool helm
bazel build //hack/bin:jq
bindir="$(bazel info bazel-bin)"
export PATH="${bindir}/hack/bin/:$PATH"

# We need to install different versions of Ingress depending on which version of
# Kubernetes we are running as the NGINX Ingress controller does not have a
# release where they would support both v1 and v1beta1 versions of networking API.
# If running the setup script locally against Kubernetes v1.22, make sure to pass K8S_VERSION
# K8S_VERSION=1.22 ./devel/setup-e2e-deps.sh for this to work.
# TODO: Remove this once we no longer need to test against Kubernetes below v1.19.

# This allows running ./devel/setup-e2e-deps.sh locally against Kubernetes v1.22
# without passing the K8S_VERSION env var.
k8s_version=$(kubectl version -ojson | jq  -r '.serverVersion | "\(.major).\(.minor)"')
if [[ $k8s_version =~ 1\.22 ]]; then
  IMAGE_TAG="v1.0.0-alpha.2"
else
  IMAGE_TAG="v0.48.1"
fi
require_image "k8s.gcr.io/ingress-nginx/controller:${IMAGE_TAG}" "//devel/addon/ingressnginx:bundle_${IMAGE_TAG}"

# Ensure the ingress-nginx namespace exists
kubectl get namespace "${NAMESPACE}" || kubectl create namespace "${NAMESPACE}"

helm repo add ingress-nginx https://kubernetes.github.io/ingress-nginx

helm repo update

# Upgrade or install nginx-ingress
helm upgrade \
    --install \
    --wait \
    --version 3.34.0 \
    --namespace "${NAMESPACE}" \
    --set controller.image.digest="" \
    --set controller.image.tag="${IMAGE_TAG}" \
    --set controller.image.pullPolicy=Never \
    --set "controller.service.clusterIP=${SERVICE_IP_PREFIX}.15"\
    --set controller.service.type=ClusterIP \
    --set controller.config.no-tls-redirect-locations="" \
    --set admissionWebhooks.enabled=false \
    --set controller.admissionWebhooks.enabled=false \
    "$RELEASE_NAME" \
    ingress-nginx/ingress-nginx
