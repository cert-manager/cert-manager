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

# Runs all hack/update-*.sh scripts

hack=$(dirname "${BASH_SOURCE[0]}")

"$hack"/update-bazel.sh
"$hack"/update-codegen.sh
"$hack"/update-crds.sh
"$hack"/update-deps.sh
# This is already run automatically by update-deps.sh
#"$hack"/update-deps-licenses.sh
"$hack"/update-gofmt.sh
"$hack"/update-helmgen.sh
