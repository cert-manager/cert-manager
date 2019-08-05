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
    # TODO: handle DOCKER_REPO
    "${BUILD_TOOL}" certmanager load --cluster-name="${KIND_CLUSTER_NAME}" --app-version="${DOCKER_TAG}" &
    "${BUILD_TOOL}" addon load --cluster-name="${KIND_CLUSTER_NAME}" &
    echo "Waiting for all images to be loaded..."
    wait
    echo "All images loaded!"
}

build_images
