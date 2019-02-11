#!/bin/bash

# Copyright 2019 The Jetstack cert-manager contributors.
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

# This script will provision an end-to-end testing environment using 'kind'
# (kubernetes-in-docker).
#
# It requires kubectl, docker and bazel to be installed.
# kubectl will be automatically installed if not found when on linux

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/lib/lib.sh"

cleanup() {
    # Ignore errors here
    "${SCRIPT_ROOT}/lib/cluster_destroy.sh" || true
}
trap cleanup EXIT

"${SCRIPT_ROOT}/lib/cluster_create.sh"

export KUBECONFIG="${HOME}/.kube/kind-config-${KIND_CLUSTER_NAME}"

echo "Testing kind apiserver connectivity"
# Ensure the apiserver is responding
"${KUBECTL}" get nodes

"${SCRIPT_ROOT}/lib/build_images.sh"

make e2e_test \
    KUBECONFIG=${KUBECONFIG} \
    KUBECTL=${KUBECTL}
