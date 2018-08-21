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

## This file is a stop gap whilst we migrate the Makefile to better
## supprt prow for our testing
set -o errexit
set -o nounset
set -o pipefail

# Build images while we wait for services to start
make build APP_VERSION=build

# Wait for e2e service dependencies
echo "Waiting for minikube cluster to be ready..."

while true; do if kubectl get nodes; then break; fi; echo "Waiting 5s for kubernetes to be ready..."; sleep 5; done

echo "Installing helm with cluster-admin privileges..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: List
items:

### Tiller ###
# Create a ServiceAccount for tiller to use
- apiVersion: v1
  kind: ServiceAccount
  metadata:
    name: tiller
    namespace: kube-system
# Bind tiller to the cluster-admin role
- apiVersion: rbac.authorization.k8s.io/v1beta1
  kind: ClusterRoleBinding
  metadata:
    name: "tiller"
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: "cluster-admin"
  subjects:
  - apiGroup: ""
    kind: ServiceAccount
    name: tiller
    namespace: kube-system
EOF
helm init --service-account=tiller


echo "Exposing nginx-ingress service with a stable IP (10.0.0.15)"
# Setup service for nginx ingress controller. A DNS entry for *.certmanager.kubernetes.network has been setup to point to 10.0.0.15 for e2e tests
while true; do if kubectl get rc nginx-ingress-controller -n kube-system; then break; fi; echo "Waiting 5s for nginx-ingress-controller rc to be installed..."; sleep 5; done
kubectl expose -n kube-system --port 80 --target-port 80 --type ClusterIP rc nginx-ingress-controller --cluster-ip 10.0.0.15

echo "Waiting for Tiller to be ready..."
while true; do if timeout 5 helm version; then break; fi; echo "Waiting 5s for tiller to be ready..."; sleep 5; done

echo "Running e2e tests"
make e2e_test E2E_NGINX_CERTIFICATE_DOMAIN=certmanager.kubernetes.network
