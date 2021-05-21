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

KYVERNO_VERSION="v1.3.6"

check_tool kubectl
check_tool helm

# Install latest version of Kyverno
helm repo add kyverno https://kyverno.github.io/kyverno/
helm repo update
helm upgrade --install --wait kyverno kyverno/kyverno --namespace kyverno --create-namespace --version "${KYVERNO_VERSION}"
# Install cert-manager specific Pod security policy
kubectl create ns cert-manager || true
kubectl apply -f ${SCRIPT_ROOT}/policy.yaml
