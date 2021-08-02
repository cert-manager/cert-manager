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

helm upgrade --install --version 10.1.1 --create-namespace --namespace traefik traefik traefik/traefik --values=/dev/stdin <<EOF
image:
  tag: ${IMAGE_TAG}
service:
  type: ClusterIP
  spec:
    clusterIP: 10.0.0.13

additionalArguments:
  - --experimental.kubernetesgateway=true
  - --providers.kubernetesgateway=true
  - --providers.kubernetesgateway.namespaces=
  - --entrypoints.web.address=:80
  - --entrypoints.websecure.address=:443

logs:
  general:
    level: DEBUG

ports:
  web:
    port: 80
  websecure:
    port: 443

# We want to listen on port 80 since that's what ACME requires. By default, the
# chart uses 8000 to be able to runAsNonRoot.
# https://stackoverflow.com/questions/66138370
securityContext:
  capabilities:
    drop: [ALL]
    add: [NET_BIND_SERVICE]
  readOnlyRootFilesystem: true
  runAsGroup: 0
  runAsNonRoot: false
  runAsUser: 0
EOF

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
          acme: solver-traefik
      namespaces:
        from: All
EOYAML
