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

# Installs an instance of Kyverno with its restrictive Pod security policies enabled.
# * https://kyverno.io/policies/pod-security/
#
# We create custom Kyverno policies using a kustomization of the upstream
# policies, as follows:
#  kustomize build . > policy.yaml

set -o nounset
set -o errexit
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/../../lib/lib.sh"

check_tool kubectl
check_tool helm

CHART_VERSION="v2.0.3"
IMAGE_TAG="v1.4.3"
PRE_IMAGE_TAG="v1.4.3"

require_image "ghcr.io/kyverno/kyverno:${IMAGE_TAG}" "//devel/addon/kyverno:bundle_${IMAGE_TAG}"
require_image "ghcr.io/kyverno/kyvernopre:${PRE_IMAGE_TAG}" "//devel/addon/kyverno:pre_bundle_${PRE_IMAGE_TAG}"


# Install latest version of Kyverno
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm upgrade \
  --install \
  --wait \
  --namespace kyverno \
  --create-namespace \
  --version "${CHART_VERSION}" \
  kyverno-crds \
  kyverno/kyverno-crds
helm upgrade \
  --install \
  --wait \
  --namespace kyverno \
  --create-namespace \
  --version "${CHART_VERSION}" \
  --set image.tag="${IMAGE_TAG}" \
  --set image.pullPolicy=Never \
  --set initImage.tag="${PRE_IMAGE_TAG}" \
  --set initImage.pullPolicy=Never \
  kyverno \
  kyverno/kyverno
# Install cert-manager specific Pod security policy
kubectl create ns cert-manager || true
kubectl apply -f ${SCRIPT_ROOT}/policy.yaml
