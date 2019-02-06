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
export CHART_PATH=${CHART_PATH:-deploy/charts/cert-manager}
# remove trailing `/` if present
export DOCKER_REPO=${DOCKER_REPO%/}
COMPONENTS=( acmesolver controller webhook )
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
    info "appended '-dirty' suffix to version"
fi

info "releasing version $VERSION"
export APP_VERSION="$VERSION"

info "reading bazel workspace variables"
# export the bazel workspace vars
eval $(./hack/print-workspace-status.sh | tr ' ' '=' | sed 's/^/export /')

info "building release images"
bazel run //:images

green "Built release images"

if [ ! "${CONFIRM}" ]; then
    green "Skipping publishing. Set CONFIRM=1 to publish release."
    exit 0
fi

green "Publishing release ${VERSION}"

# Push docker images
# We use the docker CLI to push images as quay.io does not support the v2 API
for c in "${COMPONENTS[@]}"; do
    info "Pushing image ${STABLE_DOCKER_REPO}/cert-manager-$c:${STABLE_DOCKER_TAG}"
    docker "${docker_args[@]}" push "${STABLE_DOCKER_REPO}/cert-manager-$c:${STABLE_DOCKER_TAG}"
    if [ -z "${SKIP_REF_TAG}" ]; then
        info "Pushing image ${docker_args[@]}" push "${STABLE_DOCKER_REPO}/cert-manager-$c:${COMMIT_REF}"
        docker tag "${STABLE_DOCKER_REPO}/cert-manager-$c:${STABLE_DOCKER_TAG}"  "${STABLE_DOCKER_REPO}/cert-manager-$c:${COMMIT_REF}"
        docker "${docker_args[@]}" push "${STABLE_DOCKER_REPO}/cert-manager-$c:${COMMIT_REF}"
    fi
done

echo
green "Published all images!"
