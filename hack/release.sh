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
set -o xtrace

function usage() {
    cat <<'EOF'
This script is entrypoint to release images automatically.
Note that this script expected
Usage: hack/release.sh
    -h      show this message and exit
Environments:
    REGISTRY                    container registry without repo name (default: quay.io/external_storage)
    VERSION                     if set, use given version as image tag
    CONFIRM                     set this to skip confirmation
    ALLOW_DIRTY                 by default, git repo must be clean, set this to skip this check (debug only)
    ALLOW_OVERWRITE             by default, if an existing image exists with the same tag then pushing will be aborted, set this to skip this check
    SKIP_REF_TAG                skip creating a commit ref docker tag
    CHART_PATH                  custom path to the Helm chart within the cert-manager repository (debug only) (default: deploy/charts/cert-manager)
    CHART_BUCKET                GCS bucket where the Helm chart should be published (default: jetstack-chart-museum)
    CHART_SERVICE_ACCOUNT       optional path to a JSON formatted Google Cloud service account used by gsutil to publish the chart
    SKIP_CHART                  skip publishing the Helm chart
Examples:
1) Release to your own registry for testing
    git tag v2.2.3
    REGISTRY=quay.io/<yourname> SKIP_CHART=1 ./hack/release.sh
2) Release canary version
    REGISTRY=quay.io/<yourname> VERSION=canary SKIP_CHART=1 ./hack/release.sh
EOF
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
DOCKER_REPO=${REGISTRY:-quay.io/jetstack}
# remove trailing `/` if present
export DOCKER_REPO=${DOCKER_REPO%/}

# TODO: implement
export ALLOW_OVERWRITE=${ALLOW_OVERWRITE:-}

# Helm chart packaging vars
export CHART_PATH=${CHART_PATH:-deploy/charts/cert-manager}
export CHART_BUCKET=${CHART_BUCKET:-jetstack-chart-museum}
export CHART_SERVICE_ACCOUNT=${CHART_SERVICE_ACCOUNT:-}
export SKIP_CHART="${SKIP_CHART:-}"
export SKIP_MANIFESTS="${SKIP_MANIFESTS:-}"

if [[ ! -z "${CONFIRM}" ]]; then
    PUBLISH="--publish"
fi

if [[ ! -z "${CHART_SERVICE_ACCOUNT}" ]]; then
    export GOOGLE_APPLICATION_CREDENTIALS="${CHART_SERVICE_ACCOUNT}"
    gcloud auth activate-service-account --key-file "${CHART_SERVICE_ACCOUNT}"
fi

if [[ -z "${SKIP_CHART}" ]]; then
    CHART="--chart"
fi

if [[ -z "${SKIP_MANIFESTS}" ]]; then
    MANIFESTS="--manifests"
fi

# TODO: enable --manifests too
bazel run //hack/release -- \
    --images \
    "${CHART:-}" \
    "${MANIFESTS:-}" \
    --docker-repo="${DOCKER_REPO}" \
    --helm.path="$(bazel info bazel-genfiles)/hack/bin/helm" \
    --chart.path="${CHART_PATH}" \
    --chart.bucket="${CHART_BUCKET}" \
    --app-version="${VERSION}" \
    --docker-repo="${DOCKER_REPO}" \
    --v=4 \
    "${PUBLISH:-}"
