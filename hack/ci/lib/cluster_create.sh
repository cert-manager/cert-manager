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

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/lib.sh"

# deploy_kind will deploy a kubernetes-in-docker cluster
deploy_kind() {
    echo "Exporting kind image to docker daemon..."
    bazel run "${KIND_IMAGE_TARGET}"

    function kubeVersion() {
        echo $(docker run \
            --entrypoint="cat" \
            "${KIND_IMAGE}" \
            /kind/version)
    }

    # default to v1beta2
    # - if 1.13.x or 1.14.x use v1beta1
    # - if 1.12.x then use v1alpha3
    # - if 1.11.x then use v1alpha2
    vers="$(kubeVersion)"
    config="v1beta2"
    if [[ "$vers" =~ v1\.11\..+ ]]; then
        config="v1alpha2"
    fi
    if [[ "$vers" =~ v1\.12\..+ ]]; then
        config="v1alpha3"
    fi
    if [[ "$vers" =~ v1\.1[3-4]\..+ ]] ; then
        config="v1beta1"
    fi


    echo "Booting Kubernetes version: $vers"
    echo "Using kubeadm config api version '$config'"
    # create the kind cluster
    "${KIND}" create cluster \
        --name="${KIND_CLUSTER_NAME}" \
        --image="${KIND_IMAGE}" \
        --config "${REPO_ROOT}"/test/fixtures/kind/config-"$config".yaml
}

deploy_kind
