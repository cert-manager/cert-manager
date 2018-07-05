#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT=$(git rev-parse --show-toplevel)

IMAGE="${IMAGE:-munnerz/gen-apidocs-img}"
IMAGE_TAG="${IMAGE_TAG:-0.1}"

docker run \
    -v "${REPO_ROOT}:/go/src/github.com/jetstack/cert-manager" \
    --workdir "/go/src/github.com/jetstack/cert-manager" \
    "${IMAGE}:${IMAGE_TAG}" \
    ./hack/update-reference-docs.sh
