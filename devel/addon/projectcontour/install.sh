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

# Install Contour as a gateway-API e2e test.

set -o nounset
set -o errexit
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/../../lib/lib.sh"

# Ensure ytt is available
bazel build //hack/bin:ytt
bindir="$(bazel info bazel-bin)"
export PATH="${bindir}/hack/bin/:$PATH"

check_tool kubectl
check_tool ytt

ytt --data-value gateway_ip="${GATEWAY_IP}" \
  --file "${SCRIPT_ROOT}/contour-gateway.yaml" \
  --file "${SCRIPT_ROOT}/gateway-resources.yaml" | kubectl apply -f -
