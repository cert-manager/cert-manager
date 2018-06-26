#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
REPO_ROOT="${SCRIPT_ROOT}/.."
pushd "${REPO_ROOT}"
echo "+++ Running dep ensure"
dep ensure -v "$@"
echo "+++ Cleaning up erroneous vendored testdata symlinks"
rm -Rf vendor/github.com/prometheus/procfs/fixtures \
       vendor/github.com/hashicorp/go-rootcerts/test-fixtures \
       vendor/github.com/json-iterator/go/skip_tests
popd
