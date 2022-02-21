#!/usr/bin/env bash

# Copyright 2021 The cert-manager Authors.
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

# Install HAProxy as a gateway-API e2e test.

set -o nounset
set -o errexit
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/../../lib/lib.sh"

check_tool kubectl

kubectl apply -f "${SCRIPT_ROOT}/contour-gateway.yaml"

cat <<EOYAML | kubectl apply -f -
---
kind: GatewayClass
apiVersion: gateway.networking.k8s.io/v1alpha2
metadata:
  name: acmesolver
spec:
  controllerName: projectcontour.io/projectcontour/contour

---
kind: Gateway
apiVersion: gateway.networking.k8s.io/v1alpha2
metadata:
  name: acmesolver
  namespace: projectcontour
spec:
  gatewayClassName: acmesolver
  listeners:
    - name: http
      protocol: HTTP
      port: 80
      allowedRoutes:
        namespaces:
          from: All
EOYAML
