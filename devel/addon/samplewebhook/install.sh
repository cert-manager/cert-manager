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

# Installs an instance of the sample-webhook using the Helm chart located in
# chart/.
# Configure the cluster to target using the KUBECONFIG environment variable.
# Additional parameters can be configured by overriding the variables below.

# Namespace to deploy into
NAMESPACE="${NAMESPACE:-sample-webhook}"
# Release name to use with Helm
RELEASE_NAME="${RELEASE_NAME:-sample-webhook}"

# Require helm available on PATH
check_tool kubectl
check_tool helm
require_image "sample-webhook:bazel" "//devel/addon/samplewebhook:bundle"

# Ensure the pebble namespace exists
kubectl get namespace "${NAMESPACE}" || kubectl create namespace "${NAMESPACE}"

# Upgrade or install Pebble
helm upgrade \
    --install \
    --wait \
    --namespace "${NAMESPACE}" \
    "$RELEASE_NAME" \
    "$SCRIPT_ROOT/chart"
