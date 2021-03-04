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

set -o nounset
set -o errexit
set -o pipefail

if [[ -n "${TEST_WORKSPACE:-}" ]]; then # Running inside bazel
  echo "Checking generated clients for changes..." >&2
elif ! command -v bazel &>/dev/null; then
  echo "Install bazel at https://bazel.build" >&2
  exit 1
else
  (
    set -o xtrace
    bazel test --test_output=streamed //hack:verify-codegen
  )
  exit 0
fi

tmpfiles=$TEST_TMPDIR/files

(
  mkdir -p "$tmpfiles"
  rm -f bazel-*
  cp -aL "." "$tmpfiles"
  # clean up 'external' directory copied from test runfiles
  rm -rf "$tmpfiles"/external
  export BUILD_WORKSPACE_DIRECTORY=$tmpfiles
  export HOME=$(realpath "$TEST_TMPDIR/home")
  unset GOPATH
  go=$(realpath "$2")
  export PATH=$(dirname "$go"):$PATH
  "$@"
)

(
  # Remove the platform/binary for gazelle and kazel
  gazelle=$(dirname "$3")
  kazel=$(dirname "$4")
  rm -rf {.,"$tmpfiles"}/{"$gazelle","$kazel"}
)
# Avoid diff -N so we handle empty files correctly
# Ignoring Copyright to not trigger a CI fail every new year
diff=$(diff -upr \
  -I '^Copyright.*' \
  "./pkg" "$tmpfiles/pkg" 2>/dev/null || true)

if [[ -n "${diff}" ]]; then
  echo "${diff}" >&2
  echo >&2
  echo "ERROR: generated clients changed. Update with ./hack/update-codegen.sh" >&2
  exit 1
fi
echo "SUCCESS: generated clients up-to-date"
