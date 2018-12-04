#!/usr/bin/env bash

# Copyright 2018 The Jetstack cert-manager contributors.
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

RULE_NAME="deploy-gen"

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
# remove __main__ directory copied to tmp
rm -Rf "${TMP_DIFFROOT}/__main__"

cd "${TMP_DIFFROOT}"
export BUILD_WORKSPACE_DIRECTORY="$(pwd)"
"hack/update-${RULE_NAME}.sh"

echo "diffing ${DIFFROOT} against freshly generated deploy-gen"
ret=0
diff --exclude=__main__ -Naupr "${DIFFROOT}/deploy/manifests" "${TMP_DIFFROOT}/deploy/manifests" || ret=$?
if [[ $ret -eq 0 ]]
then
  echo "${DIFFROOT} up to date."
else
  echo "${DIFFROOT} is out of date. Please run 'bazel run //hack:update-${RULE_NAME}'"
  exit 1
fi
