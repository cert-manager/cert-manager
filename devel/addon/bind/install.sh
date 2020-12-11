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

# Installs an instance of bind using the manifests located in manifests/
# Configure the cluster to target using the KUBECONFIG environment variable.
# Additional parameters can be configured by overriding the variables below.

# Namespace to deploy into
NAMESPACE="${NAMESPACE:-bind}"
if [[ "$IS_OPENSHIFT" == "true" ]] ; then
  # OpenShift needs bind to be in kube-system due to file ownership restrictions
  NAMESPACE="kube-system"
fi

SERVICE_IP_PREFIX="${SERVICE_IP_PREFIX:-10.0.0}"

check_tool kubectl
require_image "sameersbn/bind:bazel" "//devel/addon/bind:bundle"

# Ensure the bind namespace exists
kubectl get namespace "${NAMESPACE}" || kubectl create namespace "${NAMESPACE}"

# Upgrade or install bind
sed "s/{SERVICE_IP_PREFIX}/${SERVICE_IP_PREFIX}/g" $SCRIPT_ROOT/manifests/* | kubectl apply --namespace "${NAMESPACE}" -f -
