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

# build_images will build Docker images for all of cert-manager's components.
# It will transfer them to the 'kind' docker container so they are available
# in a testing environment.

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/lib.sh"

build_images() {
    # Build cert-manager binaries & docker image
    APP_VERSION="${DOCKER_TAG}" \
    DOCKER_REPO="${DOCKER_REPO}" \
    DOCKER_TAG="${DOCKER_TAG}" \
    bazel run //:images

    local TMP_DIR=$(mktemp -d)
    local BUNDLE_FILE="${TMP_DIR}"/cmbundle.tar.gz

    # Create an archive of docker images
    docker save \
        "${DOCKER_REPO}"/cert-manager-controller:"${DOCKER_TAG}" \
        "${DOCKER_REPO}"/cert-manager-acmesolver:"${DOCKER_TAG}" \
        "${DOCKER_REPO}"/cert-manager-webhook:"${DOCKER_TAG}" \
        -o "${BUNDLE_FILE}"

    # Copy docker archive into the kind container
    docker cp "${BUNDLE_FILE}" "${KIND_CONTAINER_NAME}":/cmbundle.tar.gz

    # Import file into kind docker daemon
    docker exec "${KIND_CONTAINER_NAME}" docker load -i /cmbundle.tar.gz

    # Cleanup
    rm -Rf "${TMP_DIR}"
}

build_images