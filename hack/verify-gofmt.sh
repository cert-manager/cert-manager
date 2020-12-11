#!/usr/bin/env bash

# Copyright 2020 The cert-manager Authors.
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

if [[ -n "${TEST_WORKSPACE:-}" ]]; then # Running inside bazel
  echo "Validating go source file formatting..." >&2
elif ! command -v bazel &> /dev/null; then
  echo "Install bazel at https://bazel.build" >&2
  exit 1
else
  (
    set -o xtrace
    bazel test --test_output=streamed //hack:verify-gofmt
  )
  exit 0
fi

gofmt=$(realpath "$1")

export GO111MODULE=on

echo "+++ Running gofmt"
output=$(find . -name '*.go' | grep -v 'vendor/' | xargs "$gofmt" -s -d)
if [ ! -z "${output}" ]; then
    echo "${output}"
    echo "Please run 'bazel run //hack:update-gofmt'"
    exit 1
fi
