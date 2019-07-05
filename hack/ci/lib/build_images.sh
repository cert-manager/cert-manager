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

# build_images will build Docker images for all of cert-manager's components.
# It will transfer them to the 'kind' docker container so they are available
# in a testing environment.

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/lib.sh"

build_images() {
    # Build cert-manager binaries & docker image
    # Set --stamp=true when running a build to workaround issues introduced
    # in bazelbuild/rules_go#2110. For more information, see: https://github.com/bazelbuild/rules_go/pull/2110#issuecomment-508713878
    # We should be able to remove the `--stamp=true` arg once this has been fixed!
    APP_VERSION="${DOCKER_TAG}" \
    DOCKER_REPO="${DOCKER_REPO}" \
    DOCKER_TAG="${DOCKER_TAG}" \
    bazel run --platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 --stamp=true //test/e2e:images

    echo "All images built"

    for IMG in \
        "${DOCKER_REPO}"/cert-manager-controller:"${DOCKER_TAG}" \
        "${DOCKER_REPO}"/cert-manager-cainjector:"${DOCKER_TAG}" \
        "${DOCKER_REPO}"/cert-manager-acmesolver:"${DOCKER_TAG}" \
        "${DOCKER_REPO}"/cert-manager-webhook:"${DOCKER_TAG}" \
        "pebble:bazel" \
        "quay.io/kubernetes-ingress-controller/nginx-ingress-controller:0.23.0" \
        "k8s.gcr.io/defaultbackend:bazel" \
        "sample-webhook:bazel" \
        "vault:bazel" \
        "gcr.io/kubernetes-helm/tiller:bazel" \
    ; do
        echo "Loading image ${IMG} into kind container"
        "${KIND}" load docker-image --name "${KIND_CLUSTER_NAME}" "${IMG}" &
    done
    echo "Waiting for all images to be loaded..."
    wait
    echo "All images loaded!"
}

build_images
