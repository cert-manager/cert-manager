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


function usage() {
    cat <<'EOF'
This script is entrypoint to release images automatically.
Note that this script expected
Usage: hack/release.sh
    -h      show this message and exit
Environments:
    REGISTRY                    container registry without repo name (default: quay.io/external_storage)
    VERSION                     if set, use given version as image tag
    DOCKER_CONFIG               optional docker config location
    CONFIRM                     set this to skip confirmation
    ALLOW_DIRTY                 by default, git repo must be clean, set this to skip this check (debug only)
    ALLOW_OVERWRITE             by default, if an existing image exists with the same tag then pushing will be aborted, set this to skip this check
    SKIP_REF_TAG                skip creating a commit ref docker tag
Examples:
1) Release to your own registry for testing
    git tag v2.2.3
    REGISTRY=quay.io/<yourname> ./hack/release.sh
2) Release canary version
    REGISTRY=quay.io/<yourname> VERSION=canary ./hack/release.sh
EOF
}

function info() {
    echo -e "\e[33minfo:\e[39m $@"
}

function green() {
    echo
    echo -e "\e[32m$@\e[39m"
    echo
}

function error() {
    echo -e "\e[31merror: $@\e[39m"
}

while getopts "h?" opt; do
    case "$opt" in
    h|\?)
        usage
        exit 0
        ;;
    esac
done

export CONFIRM=${CONFIRM:-}
export VERSION=${VERSION:-}
export DOCKER_REPO=${REGISTRY:-quay.io/jetstack}
export DOCKER_CONFIG=${DOCKER_CONFIG:-}
export ALLOW_DIRTY=${ALLOW_DIRTY:-}
export ALLOW_OVERWRITE=${ALLOW_OVERWRITE:-}
export CHART_PATH=${CHART_PATH:-deploy/charts/cert-manager}
# remove trailing `/` if present
export DOCKER_REPO=${DOCKER_REPO%/}
COMPONENTS=( acmesolver controller webhook ca-sync )
SKIP_REF_TAG=${SKIP_REF_TAG:-}
GIT_DIRTY=$(test -n "`git status --porcelain`" && echo "dirty" || echo "clean")
if [ -z "$ALLOW_DIRTY" -a "$GIT_DIRTY" != "clean" ]; then
    error "repo status is not clean, skipped"
    exit 1
fi
COMMIT_REF=$(git rev-parse --short HEAD)

docker_args=()
if [ -n "$DOCKER_CONFIG" ]; then
    if [ ! -d "$DOCKER_CONFIG" ]; then
        error "DOCKER_CONFIG '$DOCKER_CONFIG' does not exist or not a directory"
        exit 1
    fi
    if [ ! -f "$DOCKER_CONFIG/config.json" ]; then
        error "docker config json '$DOCKER_CONFIG/config.json' does not exist"
        exit 1
    fi
    docker_args+=(--config "$DOCKER_CONFIG")
fi

if [ -z "$VERSION" ]; then
    # our logic depends repo tags, make sure all tags are fetched
    info "fetching all tags from official upstream"
    git fetch --tags https://github.com/jetstack/cert-manager.git
    info "VERSION is not specified, detect automatically"
    # get version from tag
    VERSION=$(git describe --tags --abbrev=0 --exact-match 2>/dev/null || true)
    if [ -z "$VERSION" ]; then
        VERSION="$COMMIT_REF"
        SKIP_REF_TAG=1
        info "defaulting VERSION to current commit ref"
    fi
fi

if [ "$GIT_DIRTY" != "clean" ]; then
    VERSION="${VERSION}-dirty"
    COMMIT_REF="${COMMIT_REF}-dirty"
    info "appended '-dirty' suffix to version"
fi

info "releasing version $VERSION"
export APP_VERSION="$VERSION"

info "reading bazel workspace variables"
# export the bazel workspace vars
eval $(./hack/print-workspace-status.sh | tr ' ' '=' | sed 's/^/export /')

info "building release images"
bazel run //:images

green "Built release images. Publishing release ${VERSION}"

# quay.io/api/v1/repository/jetstack/cert-manager-controller/tag/v0.6.1/images
function allowed() {
    local image_name="$1"
    local image_tag="$2"
    if [ ! -z "${ALLOW_OVERWRITE}" ]; then
        return 0
    fi
    if [ "${STABLE_DOCKER_REPO:0:7}" != "quay.io" ]; then
        error "checking for existing tags is only supported with quay.io, set ALLOW_OVERWRITE=1 to skip check."
        exit 1
    fi

    local org="${STABLE_DOCKER_REPO:8}"
    info "checking if image quay.io/$org/$image_name:$image_tag already exists"
    resp=$(curl -so /dev/null -w '%{http_code}' -IL quay.io/api/v1/repository/$org/$image_name/tag/$image_tag/images)
    if [ "$resp" != "404" ]; then
        error "skipping image as tag already exists"
        return 1
    fi
    info "existing image quay.io/$org/$image_name:$image_tag not found"
}

function push() {
    local image_repo="$1"
    local image_name="$2"
    local image_tag="$3"

    if [ -z "${CONFIRM}" ]; then
        info "(would) push image $image_repo/$image_name:$image_tag"
        info "(would) push image $image_repo/$image_name:$COMMIT_REF"
        return 0
    fi

    if allowed "$image_name" "$image_tag"; then
        info "Pushing image $image_repo/$image_name:$image_tag"
        docker "${docker_args[@]}" push "$image_repo/$image_name:$image_tag"
    fi

    if [ -z "${SKIP_REF_TAG}" ]; then
        if allowed "$image_name" "${COMMIT_REF}"; then
            info "Pushing image ${docker_args[@]}" push "$image_repo/$image_name:${COMMIT_REF}"
            docker tag "$image_repo/$image_name:$image_tag"  "$image_repo/$image_name:${COMMIT_REF}"
            docker "${docker_args[@]}" push "$image_repo/$image_name:${COMMIT_REF}"
        fi
    fi
}

# Push docker images
# We use the docker CLI to push images as quay.io does not support the v2 API
for c in "${COMPONENTS[@]}"; do
    image_name="cert-manager-$c"
    image_repo="${STABLE_DOCKER_REPO}"
    image_tag="${STABLE_DOCKER_TAG}"

    # the amd64 images get pushed to a docker repo *without* the arch prefix
    # for compatibility reasons, so we have special handling to retag it here
    docker tag "${image_repo}/${image_name}-amd64:${image_tag}" "${image_repo}/${image_name}:${image_tag}"
    push "$image_repo" "$image_name" "$image_tag"

    # push arm64 and arm image targets
    for arch in arm64 arm; do
        push "$image_repo" "$image_name-$arch" "$image_tag"
    done
done

green "Published all images!"
