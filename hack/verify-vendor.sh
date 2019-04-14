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

REPO_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

# create a nice clean place to put our new licenses
# must be in the user dir (e.g. REPO_ROOT) in order for the docker volume mount
# to work with docker-machine on macs
mkdir -p "${REPO_ROOT}/_tmp"
_tmpdir="$(mktemp -d "${REPO_ROOT}/_tmp/cm-vendor.XXXXXX")"

if [[ -z ${KEEP_TMP:-} ]]; then
    KEEP_TMP=false
fi

function cleanup {
  # make go module dirs writeable
  chmod -R +w "${_tmpdir}"
  if [ "${KEEP_TMP}" == "true" ]; then
    echo "Leaving ${_tmpdir} for you to examine or copy. Please delete it manually when finished. (rm -rf ${_tmpdir})"
  else
    echo "Removing ${_tmpdir}"
    rm -rf "${_tmpdir}"
  fi
}
trap cleanup EXIT

# Copy the contents of the cert-manager directory into the nice clean place (which is NOT shaped like a GOPATH)
_cmtmp="${_tmpdir}"
mkdir -p "${_cmtmp}"
# should create ${_cmtmp}/cert-manager
git archive --format=tar --prefix=cert-manager/ "$(git write-tree)" | (cd "${_cmtmp}" && tar xf -)
_cmtmp="${_cmtmp}/cert-manager"
# Do all our work with an unset GOPATH
export GOPATH=

pushd "${_cmtmp}" > /dev/null 2>&1
  # Recreate the vendor tree using the nice clean set we just downloaded
  hack/update-vendor.sh
popd > /dev/null 2>&1

ret=0

pushd "${REPO_ROOT}" > /dev/null 2>&1
  # Test for diffs
  if ! _out="$(diff -Naupr --ignore-matching-lines='^\s*\"GoVersion\":' go.mod "${_cmtmp}/go.mod")"; then
    echo "Your go.mod file is different:" >&2
    echo "${_out}" >&2
    echo "Vendor Verify failed." >&2
    echo "If you're seeing this locally, run the below command to fix your go.mod:" >&2
    echo "hack/update-vendor.sh" >&2
    ret=1
  fi

  if ! _out="$(diff -Naupr -x "BUILD" -x "AUTHORS*" -x "CONTRIBUTORS*" vendor "${_cmtmp}/vendor")"; then
    echo "Your vendored results are different:" >&2
    echo "${_out}" >&2
    echo "Vendor Verify failed." >&2
    echo "${_out}" > vendordiff.patch
    echo "If you're seeing this locally, run the below command to fix your directories:" >&2
    echo "hack/update-vendor.sh" >&2
    ret=1
  fi
popd > /dev/null 2>&1

if [[ ${ret} -gt 0 ]]; then
  exit ${ret}
fi

echo "Vendor Verified."
