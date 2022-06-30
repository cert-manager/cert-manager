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
# It's preserved for now but might be removed in the future


hack=$(dirname "${BASH_SOURCE[0]}")

echo -e "\033[0;33mThis script is preserved for legacy reasons, and as such will also update bazel
You shouldn't need to run this script or install bazel for normal development.
Use 'make update-all' to do everything this script does without touching bazel\033[0m"

"$hack"/update-bazel.sh

make update-all
