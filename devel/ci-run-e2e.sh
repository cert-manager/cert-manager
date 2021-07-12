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

# This script will build an entirely new testing environment using kind.
# This is intended to be run in a CI environment and *not* for development.
# It is not optimised for quick, iterative development.

SCRIPT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"
export REPO_ROOT="${SCRIPT_ROOT}/.."
source "${SCRIPT_ROOT}/lib/lib.sh"

# Configure PATH to use bazel provided e2e tools
setup_tools

# Ensure a running Kubernetes cluster
"${SCRIPT_ROOT}/ci-cluster.sh"

echo "Ensuring all e2e test dependencies are installed..."
"${SCRIPT_ROOT}/setup-e2e-deps.sh"

echo "Running e2e test suite..."
FLAKE_ATTEMPTS=2 "${SCRIPT_ROOT}/run-e2e.sh" \
  "$@"

export_logs
