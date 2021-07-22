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
#
# Installs an instance of the sample-external-issuer:
# * https://github.com/cert-manager/sample-external-issuer

set -o nounset
set -o errexit
set -o pipefail

SEI_VERSION="v0.1.1"

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/../../lib/lib.sh"

check_tool kubectl

kubectl apply -f "https://github.com/cert-manager/sample-external-issuer/releases/download/${SEI_VERSION}/install.yaml"
