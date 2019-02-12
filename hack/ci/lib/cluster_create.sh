#!/bin/bash

# Copyright 2018 The Jetstack cert-manager contributors.
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

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/lib.sh"

# deploy_kind will deploy a kubernetes-in-docker cluster
deploy_kind() {
    # create the kind cluster
    kind create cluster \
        --name="${KIND_CLUSTER_NAME}" \
        --image="${KIND_IMAGE}" \
        --config "${REPO_ROOT}"/test/fixtures/kind-config.yaml

    export KUBECONFIG="${HOME}/.kube/kind-config-${KIND_CLUSTER_NAME}"

    # copy kubectl out of the kind container if kubectl is not installed on the
    # host machine. This will *only* work on Linux :this_is_fine:
    if ! which kubectl; then
        tmp_path=$(mktemp -d)
        export PATH="${tmp_path}:${PATH}"
        docker cp "${KIND_CONTAINER_NAME}":"$(docker exec "${KIND_CONTAINER_NAME}" which kubectl)" "${tmp_path}/kubectl"
    fi

    # Ensure the apiserver is responding
    kubectl get nodes
}

deploy_kind
