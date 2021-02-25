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
  echo "Validating bazel rules..." >&2
elif ! command -v bazel &> /dev/null; then
  echo "Install bazel at https://bazel.build" >&2
  exit 1
else
  (
    set -o xtrace
    bazel test --test_output=streamed //hack:verify-bazel
  )
  exit 0
fi

gazelle=$(realpath "$1")
kazel=$(realpath "$2")

export GO111MODULE=on

# Because this script is called using Bazel with the @//:all-srcs target
# included, if a package that is depended upon is not present in :all-srcs then
# gazelle will attempt to use the go tool to resolve the dependency on that
# package.
# This can take a long time, and produces confusing results.
# By not setting up the go tool in the bazel test environment at all, we still
# get a confusing error message, but we fail fast and it is clear that
# something is wrong:
#    gazelle: finding module path for import github.com/cert-manager/cert-manager/test/unit/gen: exit status 1: build cache is required, but could not be located: GOCACHE is not defined and $HOME is not defined
echo "Running gazelle..."
gazelle_diff=$("$gazelle" fix --mode=diff --external=external || true)
echo "Running kazel..."
kazel_diff=$("$kazel" --dry-run --print-diff --cfg-path=./hack/build/.kazelcfg.json)

if [[ -n "${gazelle_diff}${kazel_diff}" ]]; then
  echo "Current rules (-) do not match expected (+):" >&2
  echo "${gazelle_diff}"
  echo "${kazel_diff}"
  echo
  echo "ERROR: bazel rules out of date. Fix with ./hack/update-bazel.sh" >&2
  exit 1
fi
