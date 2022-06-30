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

# NB: This script requires bazel, and is no longer supported since we no longer support bazel
# It's preserved for now but might be removed in the future

# Update vendor and bazel rules to match go.mod
#
# Usage:
#   update-deps.sh [--patch|--minor] [packages]

set -o nounset
set -o errexit
set -o pipefail

if [[ -n "${BUILD_WORKSPACE_DIRECTORY:-}" ]]; then # Running inside bazel
  echo "Updating modules..." >&2
elif ! command -v bazel &>/dev/null; then
  echo "This script is preserved for legacy reasons and requires bazel. You shouldn't need to run this as part of your normal development workflow" >&2
  echo "If you need to run this script, install bazel from https://bazel.build" >&2
  exit 1
else
  (
    set -o xtrace
    bazel run //hack:update-deps -- "$@"
  )
  exit 0
fi

go=$(realpath "$1")
export PATH=$(dirname "$go"):$PATH
gazelle=$(realpath "$2")
kazel=$(realpath "$3")
update_bazel=(
  $(realpath "$4")
  "$gazelle"
  "$kazel"
)
update_deps_licenses=(
  $(realpath "$5")
  "$go"
)

shift 5

cd "$BUILD_WORKSPACE_DIRECTORY"
trap 'echo "FAILED" >&2' ERR

# Update hack/build/repos.bzl based of the go.mod file
"$gazelle" update-repos \
  --from_file=go.mod --to_macro=hack/build/repos.bzl%go_repositories \
  --build_file_generation=on --build_file_proto_mode=disable -prune=true

# `gazelle update-repos` adds extra unneeded entries to the
# go.sum file, run `go mod tidy` to remove them
"$go" mod tidy

# Update Bazel (changes in hack/build/repos.bzl might affect other bazel files)
"${update_bazel[@]}"

# Update LICENSES
"${update_deps_licenses[@]}"

echo "SUCCESS: updated modules"
