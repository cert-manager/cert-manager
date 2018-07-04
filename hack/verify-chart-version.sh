#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

readonly REPO_ROOT=$(git rev-parse --show-toplevel)
readonly UPSTREAM_REPO="https://github.com/jetstack/cert-manager.git"

if [ -z "${PULL_BASE_REF:-}" ]; then
    echo "PULL_BASE_REF must be set to a target branch name"
    exit 1
fi

if [ -z "${REMOTE:-}" ]; then
    echo "+++ REMOTE not set - defaulting to 'upstream'"
    export REMOTE="upstream"
fi

if ! git remote get-url "${REMOTE}" > /dev/null 2>&1; then
    echo "+++ Remote '${REMOTE}' does not exist. Setting to ${UPSTREAM_REPO}"
    git remote add "${REMOTE}" "${UPSTREAM_REPO}"
fi

git fetch "${REMOTE}"

docker run --rm -v "${REPO_ROOT}:/workdir" --workdir /workdir \
   -e REMOTE="${REMOTE}" \
   -e TARGET_BRANCH="${PULL_BASE_REF}" \
   gcr.io/kubernetes-charts-ci/chart-testing:v1.0.2 \
   /workdir/test/chart/chart_test.sh \
   --no-install \
   --config test/chart/.testenv
