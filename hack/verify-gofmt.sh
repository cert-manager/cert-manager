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

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")/..
# This script should be run via `bazel run //hack:update-deps`
runfiles="$(pwd)"
export PATH="${runfiles}/hack/bin:${PATH}"

_tmp="$(mktemp -d)"
cleanup() {
  rm -rf "${_tmp}"
}
trap "cleanup" EXIT SIGINT

# Create a fake GOPATH
export GOPATH="${_tmp}"
TMP_DIFFROOT="${GOPATH}/src/github.com/jetstack/cert-manager"
mkdir -p "$(dirname ${TMP_DIFFROOT})"
ln -s "$(pwd)" "${TMP_DIFFROOT}"
cd "${TMP_DIFFROOT}"

echo "+++ Running gofmt"
output=$(find . -name '*.go' | grep -v 'vendor/' | xargs gofmt -s -d)
if [ ! -z "${output}" ]; then
    echo "${output}"
    echo "Please run 'bazel run //hack:update-gofmt'"
    exit 1
fi
