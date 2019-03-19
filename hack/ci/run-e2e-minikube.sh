#!/bin/bash

# Copyright 2019 The Jetstack cert-manager contributors.
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

# This file is the entrypoint to our legacy minikube e2e testing environment
# for cert-manager. It is currently used to run e2e test jobs against a
# 1.9 or lower minikube built cluster.
# This script should not be used for anything except for our CI process.

set -o errexit
set -o nounset
set -o pipefail

# Build images while we wait for services to start
make images APP_VERSION=build

# Wait for e2e service dependencies
echo "Waiting for minikube cluster to be ready..."

while true; do if kubectl get nodes; then break; fi; echo "Waiting 5s for kubernetes to be ready..."; sleep 5; done

echo "Running e2e tests"
# Skip RBAC tests as they do not pass on Kubernetes <1.9
make e2e_test GINKGO_SKIP="RBAC"
