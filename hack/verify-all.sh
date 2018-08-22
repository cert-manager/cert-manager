#!/bin/bash

# Copyright 2018 The Jetstack cert-manager contributors.
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

# The only argument this script should ever be called with is '--verify-only'

set -o errexit
set -o nounset
set -o pipefail

ROOT="$(cd "$(dirname "$0")" && pwd -P)"/..

echo "+++ Running go format checker"
${ROOT}/hack/verify-fmt.sh

echo "+++ Running bazel checker"
${ROOT}/hack/verify-bazel.sh

echo "+++ Running reference docs checker"
${ROOT}/hack/verify-reference-docs.sh

echo "+++ Running kubernetes codegen checker"
${ROOT}/hack/verify-codegen.sh

# This is run as a separate job that requires docker during CI
# echo "+++ Running helm chart version checker"
# ${ROOT}/hack/verify-chart-version.sh

echo "+++ Running static manifest checker"
${ROOT}/hack/verify-deploy-gen.sh

echo "+++ Running dep checker"
${ROOT}/hack/verify-deps.sh

echo "+++ Running bazel tests"
bazel test //hack/...
