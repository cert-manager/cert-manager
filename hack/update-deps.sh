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

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
REPO_ROOT="${SCRIPT_ROOT}/.."
pushd "${REPO_ROOT}"
echo "+++ Running dep ensure"
dep ensure -v "$@"
echo "+++ Cleaning up erroneous vendored testdata symlinks"
rm -Rf vendor/github.com/prometheus/procfs/fixtures \
       vendor/github.com/hashicorp/go-rootcerts/test-fixtures \
       vendor/github.com/json-iterator/go/skip_tests
popd
