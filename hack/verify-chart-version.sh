#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail

readonly REPO_ROOT=$(git rev-parse --show-toplevel)

if [ -z "${PULL_BASE_REF:-}" ]; then
    echo "PULL_BASE_REF must be set to a target branch name"
    exit 1
fi

docker run --rm -v "${REPO_ROOT}:/workdir" --workdir /workdir -e TARGET_BRANCH="${PULL_BASE_REF}" \
   gcr.io/kubernetes-charts-ci/chart-testing:v1.0.2 \
   /workdir/test/chart/chart_test.sh \
   --no-install \
   --config test/chart/.testenv
