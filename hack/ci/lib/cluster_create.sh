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

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/lib.sh"

# build 'kind'
bazel build //hack/bin:kind
KIND="$(bazel info bazel-genfiles)/hack/bin/kind"

# deploy_kind will deploy a kubernetes-in-docker cluster
deploy_kind() {
    # default to v1alpha3, if 1.11.x then use v1alpha2
    vers="$(kubeVersion)"
    config="v1alpha3"
    if [[ "$vers" =~ v1\.11\..+ ]]; then
        config="v1alpha2"
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
