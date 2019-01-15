#!/usr/bin/env bash

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

KIND="$2"
NAME="$1"
IMAGE="$3"
CONFIG="$4"
OUTPUT="$5"

# We set PATH to contain /usr/local/bin in order to access the 'docker' CLI
# binary when running 'kind cluster create' within Bazel.
# If different OS store the docker binary at a different path, this line will
# need to be updated.
export PATH="$PATH:/usr/local/bin"

KIND_KUBECONFIG=$("$KIND" get kubeconfig-path --name $NAME)
PERSISTENT_TMP="/tmp/certmanager/kind-$NAME"
PERSISTENT_KUBECONFIG="${PERSISTENT_TMP}/kubeconfig"

# Check if a kind container already exists
check_running() {
    CONTAINER_NAME="kind-$NAME-control-plane"
    set +e
    RUNNING=$(docker inspect "$CONTAINER_NAME" -f '{{json .State.Running}}')
    set -e
    if [ "$RUNNING" = "true" ]; then
        if [ -f "${PERSISTENT_KUBECONFIG}" ]; then
            # TODO: verify kubeconfig file works
            echo "Existing cluster $NAME already exists - verifying it is running..."
            export KUBECONFIG="${PERSISTENT_KUBECONFIG}"
            if ! kubectl get nodes; then
                echo "Existing cluster $NAME is not running. Destroying existing cluster."
                "${KIND}" delete cluster --name "${NAME}"
                return
            fi
            echo "Existing cluster $NAME is running. Re-using old kubeconfig."
            cp "${PERSISTENT_KUBECONFIG}" "$OUTPUT"
            # Exit the script altogether
            exit 0
        else
            echo "Existing cluster $NAME already running, but kubeconfig not found. Destroying existing cluster."
            "${KIND}" delete cluster --name "${NAME}"
            return
        fi
    fi
    if [ "$RUNNING" = "false" ]; then
        echo "Existing cluster $NAME already exists, but is not running. Destroying existing cluster."
        "${KIND}" delete cluster --name "${NAME}"
        return
    fi
}

check_running

mkdir -p "${PERSISTENT_TMP}"

# Run the 'kind cluster create' command to create a new cluster.
"${KIND}" create cluster \
    --name="${NAME}" \
    --image="${IMAGE}" \
    --config "${CONFIG}"

# Copy the output kubeconfig file to the output directory so other targets can
# depend on this target.
cp "$KIND_KUBECONFIG" "${PERSISTENT_KUBECONFIG}"
cp "$KIND_KUBECONFIG" "$OUTPUT"
