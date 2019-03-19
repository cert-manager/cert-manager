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

RULE_NAME="reference-docs"

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")/..

_tmp="$(mktemp -d)"
DIFFROOT="${SCRIPT_ROOT}/"

cleanup() {
  rm -rf "${_tmp}"
}
trap "cleanup" EXIT SIGINT

# Create a fake GOPATH
export GOPATH="${_tmp}"
TMP_DIFFROOT="${GOPATH}/src/github.com/jetstack/cert-manager"

mkdir -p "${TMP_DIFFROOT}"
rsync -avvL "${DIFFROOT}"/ "${TMP_DIFFROOT}" >/dev/null

export runfiles="$(pwd)"
cd "${TMP_DIFFROOT}"
export BUILD_WORKSPACE_DIRECTORY="$(pwd)"
"hack/update-${RULE_NAME}.sh"

echo "diffing ${DIFFROOT} against freshly generated ${RULE_NAME}"
ret=0
diff --exclude=__main__ -Naupr "${DIFFROOT}/docs/generated/reference/output" "${TMP_DIFFROOT}/docs/generated/reference/output" || ret=$?
if [[ $ret -eq 0 ]]
then
  echo "${DIFFROOT} up to date."
else
  echo "${DIFFROOT} is out of date. Please run 'bazel run //hack:update-${RULE_NAME}'"
  exit 1
fi
