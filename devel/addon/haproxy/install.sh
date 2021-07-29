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

# Install HAProxy as a gateway-API e2e test

set -o nounset
set -o errexit
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/../../lib/lib.sh"

check_tool helm
check_tool kubectl

helm repo add haproxy-ingress https://haproxy-ingress.github.io/charts
helm repo update

export NAMESPACE="haproxy-ingress"
export VERSION="0.13.0-beta.2"

helm upgrade \
  --install \
  --wait \
  --create-namespace \
  --namespace "${NAMESPACE}" \
  --version "${VERSION}" \
  --set "controller.extraArgs.watch-gateway=true" \
  --set "controller.service.type=ClusterIP" \
  --set "controller.service.clusterIP=10.0.0.14" \
  haproxy-ingress haproxy-ingress/haproxy-ingress

cat <<EOYAML | kubectl apply -f -
apiVersion: networking.x-k8s.io/v1alpha1
kind: GatewayClass
metadata:
  name: haproxy-acmesolver
spec:
  controller: haproxy-ingress.github.io/controller
EOYAML

cat <<EOYAML | kubectl apply -f -
apiVersion: networking.x-k8s.io/v1alpha1
kind: Gateway
metadata:
  name: acmesolver
  namespace: haproxy-ingress
spec:
  gatewayClassName: haproxy-acmesolver
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

# Example of a cross namespace HTTPRoute
cat <<EOYAML | kubectl apply -f -
apiVersion: networking.x-k8s.io/v1alpha1
kind: HTTPRoute
metadata:
  labels:
    acme: solver
  name: test
  namespace: default
spec:
  hostnames:
  - blah.haproxy.http01.example.com
  rules:
  - forwardTo:
    - serviceName: echoserver
      port: 8080
EOYAML