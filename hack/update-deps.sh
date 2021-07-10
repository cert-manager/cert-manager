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
  echo "Install bazel at https://bazel.build" >&2
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
jq=$(realpath "$4")
update_bazel=(
  $(realpath "$5")
  "$gazelle"
  "$kazel"
)
update_deps_licenses=(
  $(realpath "$6")
  "$go"
  "$jq"
)

shift 6

cd "$BUILD_WORKSPACE_DIRECTORY"
trap 'echo "FAILED" >&2' ERR

export GO111MODULE=on
export GOPROXY=https://proxy.golang.org
export GOSUMDB=sum.golang.org
mode="${1:-}"
shift || true
case "$mode" in
--minor)
    if [[ -z "$@" ]]; then
      "$go" get -u ./...
    else
      "$go" get -u "$@"
    fi
    ;;
--patch)
    if [[ -z "$@" ]]; then
      "$go" get -u=patch ./...
    else
      "$go" get -u=patch "$@"
    fi
    ;;
"")
    # Just validate, or maybe manual go.mod edit
    ;;
*)
    echo "Usage: $(basename "$0") [--patch|--minor] [packages]" >&2
    exit 1
    ;;
esac

rm -rf vendor
"$go" mod tidy
unset GOROOT

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
