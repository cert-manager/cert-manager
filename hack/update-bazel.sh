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

if [[ -n "${BUILD_WORKSPACE_DIRECTORY:-}" ]]; then # Running inside bazel
  echo "Updating bazel rules..." >&2
elif ! command -v bazel &>/dev/null; then
  echo "Install bazel at https://bazel.build" >&2
  exit 1
else
  (
    set -o xtrace
    bazel run //hack:update-bazel
  )
  exit 0
fi

gazelle=$(realpath "$1")
kazel=$(realpath "$2")

cd "$BUILD_WORKSPACE_DIRECTORY"

if [[ ! -f go.mod ]]; then
    echo "No module defined, see https://github.com/golang/go/wiki/Modules#how-to-define-a-module" >&2
    exit 1
fi

set -o xtrace
"$gazelle" fix \
  --external=external \
  --go_naming_convention=go_default_library

"$kazel" --cfg-path=./hack/build/.kazelcfg.json
