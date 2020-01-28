#!/usr/bin/env bash

# Copyright 2020 The Jetstack cert-manager contributors.
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

# This script will load end-to-end test dependencies into the kind cluster, as
# well as installing all 'global' components such as cert-manager itself,
# pebble, ingress-nginx etc.
# If you are running the *full* test suite, you should be sure to run this
# script beforehand.

SCRIPT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"
export REPO_ROOT="${SCRIPT_ROOT}/.."
source "${SCRIPT_ROOT}/lib/lib.sh"

# Configure PATH to use bazel provided e2e tools
setup_tools

echo "Installing cert-manager into the kind cluster..."
"${SCRIPT_ROOT}/addon/certmanager/install.sh"

echo "Installing sample-webhook into the kind cluster..."
"${SCRIPT_ROOT}/addon/samplewebhook/install.sh"

echo "Installing pebble into the kind cluster..."
"${SCRIPT_ROOT}/addon/pebble/install.sh"

echo "Installing ingress-nginx into the kind cluster..."
"${SCRIPT_ROOT}/addon/ingressnginx/install.sh"

echo "Loading vault into the kind cluster..."
"${SCRIPT_ROOT}/addon/vault/install.sh"
