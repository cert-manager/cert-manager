#!/usr/bin/env bash
# Copyright 2016 The Kubernetes Authors.
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

SCRIPT_ROOT="$(cd "$(dirname "$0")" && pwd -P)"/..
cd "${SCRIPT_ROOT}"

bazel build //:kazel //:buildozer
export PATH="$(bazel info bazel-genfiles)/:$PATH"

gazelle_diff=$(bazel run //:gazelle-diff)

kazel_diff=$(kazel \
  -dry-run \
  -print-diff)

# TODO: check buildozer has run
# buildozer -types 'go_library,go_binary,go_test' 'add tags manual' '//vendor/...:*' || [[ $? -eq 3 ]]
# buildozer -types 'go_library,go_binary,go_test' 'add tags manual' '//docs/generated/...:*' || [[ $? -eq 3 ]]
# buildozer -types 'go_library,go_binary,go_test' 'add tags manual' '//test/e2e/...:*' || [[ $? -eq 3 ]]

if [[ -n "${gazelle_diff}" || -n "${kazel_diff}" ]]; then
  echo "${gazelle_diff}"
  echo "${kazel_diff}"
  echo
  echo "Run ./hack/update-bazel.sh"
  exit 1
fi

# Make sure there are no BUILD files outside vendor - we should only have
# BUILD.bazel files.
old_build_files=$(find . -name BUILD \( -type f -o -type l \) \
  -not -path './vendor/*' | sort)
if [[ -n "${old_build_files}" ]]; then
  echo "One or more BUILD files found in the tree:" >&2
  echo "${old_build_files}" >&2
  echo >&2
  echo "Only BUILD.bazel is allowed." >&2
  exit 1
fi
