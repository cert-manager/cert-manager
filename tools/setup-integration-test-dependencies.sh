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

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(realpath $(dirname "${BASH_SOURCE}"))
REPO_ROOT=$(dirname "${SCRIPT_ROOT}}")

bazel build //deploy/manifests:templated_crds
bazel build //hack/bin:com_coreos_etcd
bazel build //hack/bin:io_kubernetes_kube-apiserver
bazel build //hack/bin:kubectl

echo "Integration test environment is set up, do not forget to set the following environment variables:"
echo export TEST_ASSET_ETCD=${REPO_ROOT}/bazel-bin/hack/bin/etcd
echo export TEST_ASSET_KUBE_APISERVER=${REPO_ROOT}/bazel-bin/hack/bin/kube-apiserver
echo export TEST_ASSET_KUBECTL=${REPO_ROOT}/bazel-bin/hack/bin/kubectl
echo export BAZEL_BIN_DIR=${REPO_ROOT}/bazel-bin/
exec "$@"
