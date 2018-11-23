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

# TODO: replace BASH_SOURCE with something more alt-shell friendly
_SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
REPO_ROOT="${_SCRIPT_ROOT}/../../.."

# This file contains common definitions that are re-used in other scripts

KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-cm-local-cluster}"
KIND_CONTAINER_NAME="kind-${KIND_CLUSTER_NAME}-control-plane"
KUBE_VERSION="${KUBE_VERSION:-1.12}"
# This image is built by running //test/e2e:kind-$KUBE_VERSION, or by calling
# buildDeps (as defined below).
KIND_IMAGE="${KIND_IMAGE:-test/e2e/kind:${KUBE_VERSION}}"

# DOCKER_REPO is the docker repo to use for cert-manager images, either when
# building or deploying cert-manager using these scripts.
export DOCKER_REPO="quay.io/jetstack"

# DOCKER_TAG is the docker tag to use for the cert-manager images.
# This defaults to 'build' so it doesn't conflict with images built for any
# other purpose
export DOCKER_TAG="build"
export APP_VERSION="${DOCKER_TAG}"

function kubeVersion() {
    echo $(docker run \
        --entrypoint="cat" \
        "${KIND_IMAGE}" \
        /kind/version)
}

export DEPS_BUILT=${DEPS_BUILT:-false}
function buildDeps() {
    if ! $DEPS_BUILT; then
        echo "Building e2e dependencies..."
        bazel build \
            //:images \
            //hack/bin:helm \
            //hack/bin:kind \
            //hack/bin:ginkgo \
            //test/e2e:e2e.test \
            "//test/e2e:kind-${KUBE_VERSION}"
        # Pre-export this to save cluster_* scripts having to export each time
        bazel run "//test/e2e:kind-${KUBE_VERSION}"

        export DEPS_BUILT=true
        GENFILES="$(bazel info bazel-genfiles)"
        export KIND="${GENFILES}/hack/bin/kind"
        export GINKGO="${GENFILES}/hack/bin/ginkgo"
        export HELM="${GENFILES}/hack/bin/helm"
        export E2E_TEST="${GENFILES}/test/e2e/e2e.test"

        # TODO: build kubectl here too
    fi
}
