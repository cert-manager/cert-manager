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

check_tool helm
check_tool kubectl

helm repo add traefik --force-update https://helm.traefik.io/traefik

IMAGE_TAG="2.4.9"

require_image "traefik:${IMAGE_TAG}" "//devel/addon/traefik:bundle"

helm upgrade --install --create-namespace \
  --namespace traefik \
  --version 10.1.1 \
  --set additionalArguments='{--experimental.kubernetesgateway=true,--providers.kubernetesgateway=true}' \
  --set image.tag=${IMAGE_TAG} \
  --set "service.type=ClusterIP" \
  --set "service.spec.clusterIP=10.0.0.13" \
  traefik traefik/traefik

kubectl apply -f- <<EOF
apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: gateway-role
rules:
  - apiGroups:
      - ""
    resources:
      - services
      - endpoints
      - secrets
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - networking.x-k8s.io
    resources:
      - gatewayclasses
      - gateways
      - httproutes
    verbs:
      - get
      - list
      - watch
  - apiGroups:
      - networking.x-k8s.io
    resources:
      - gatewayclasses/status
      - gateways/status
      - httproutes/status
    verbs:
      - update
---
kind: ClusterRoleBinding
apiVersion: rbac.authorization.k8s.io/v1
metadata:
  name: gateway-controller
roleRef:
  apiGroup: rbac.authorization.k8s.io
  kind: ClusterRole
  name: gateway-role
subjects:
  - kind: ServiceAccount
    name: traefik
    namespace: traefik
EOF

cat <<EOYAML | kubectl apply -f -
apiVersion: networking.x-k8s.io/v1alpha1
kind: GatewayClass
metadata:
  name: traefik-acmesolver
spec:
  controller: traefik.io/gateway-controller
EOYAML

cat <<EOYAML | kubectl apply -f -
apiVersion: networking.x-k8s.io/v1alpha1
kind: Gateway
metadata:
  name: acmesolver
  namespace: traefik
spec:
  gatewayClassName: traefik-acmesolver
  listeners:
  - protocol: HTTP
    port: 80
    routes:
      kind: HTTPRoute
      selector:
        matchLabels:
          acme: solver
      namespaces:
        from: All
EOYAML
