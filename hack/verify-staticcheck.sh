#!/usr/bin/env bash

# Copyright 2022 The cert-manager Authors.
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

# NB: This script requires bazel, and is no longer supported since we no longer support bazel
# We want to add something like this to make, but since this script was never part of any CI
# pipeline it's not a priority. The script is kept for backwards compatibility for now but may
# change or be removed in the future.

# See https://github.com/cert-manager/cert-manager/pull/3037#issue-440523030

# Currently only works on linux/amd64, darwin/amd64.

REPO_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )/../" > /dev/null && pwd )"

# See https://staticcheck.io/docs/checks
CHECKS=(
  "all"
  "-S1*"   # Omit code simplifications for now.
  "-ST1*"  # Mostly stylistic, redundant w/ golint
)
export IFS=','; checks="${CHECKS[*]}"; unset IFS

cd "${REPO_ROOT}"

all_packages=()
while IFS='' read -r line; do
  # Prepend './' to get staticcheck to treat these as paths, not packages.
  all_packages+=("./$line")
done < <( find -L .                       \
            \(                            \
              -not \(                     \
                \(                        \
                    -path ./_\* -o        \
                    -path ./.\* -o        \
                    -path ./vendor     \
                \) -prune                 \
              \)                          \
            \)                            \
            -type f                       \
            -name \*.go                   \
            | sed 's|/[^/]*$||'           \
            | sed 's|^./||'               \
            | LC_ALL=C sort -u            \
            | grep -vE "(third_party|generated|clientset_generated|hack|/_|bazel-)"
)

some_failed=false
while read -r error; do
  # Ignore compile errors caused by lack of files due to build tags.
  # TODO: Add verification for these directories.
  ignore_no_files="^-: build constraints exclude all Go files in .* \(compile\)"
  if [[ $error =~ $ignore_no_files ]]; then
    continue
  fi

  some_failed=true
  file="${error%%:*}"
  pkg="$(dirname "$file")"
  echo "$error"
done < <(bazel run //hack/bin:staticcheck -- -checks "${checks}" "${all_packages[@]}" 2>/dev/null || true)

if $some_failed; then
  echo
  echo "Staticcheck failures detected, please fix and re-run this command."
  exit 1
fi
