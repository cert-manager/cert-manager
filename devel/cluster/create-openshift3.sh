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

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/../lib/lib.sh"
SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
OPENSHIFT_VERSION=${OPENSHIFT_VERSION:-"3.11"} # This is unlikely to change in the future as this is the last release in the OpenShift 3 series
TMP_DIR=$(mktemp -d)

# Require kind & kubectl available on PATH
check_tool kubectl
check_tool docker

if docker ps | grep "openshift/origin-node:v${OPENSHIFT_VERSION}" &>/dev/null; then
  echo "Existing OpenShift 3 cluster found, skipping creating cluster..."
  exit 0
fi

# Needed for `oc cluster up` as it places files in the current directory
cd "${TMP_DIR}"

# Let OpenShift generate all certificates and setup for the controller
docker run -v "${TMP_DIR}/openshift.local.clusterup/kube-apiserver/:/var/lib/origin/openshift.local.config/" \
    "openshift/origin-control-plane:v${OPENSHIFT_VERSION}" start master \
    --write-config=/var/lib/origin/openshift.local.config \
    --master=127.0.0.1 \
    --images='openshift/origin-${component}:v$OPENSHIFT_VERSION' \
    --dns=0.0.0.0:8053 \
    --public-master=https://127.0.0.1:8443 \
    --etcd-dir=/var/lib/etcd

# Let OpenShift generate all certificates and setup for the node
bazel run //hack/bin:oc3 adm create-node-config \
    --node-dir=/openshift.local.clusterup/node  \
    --certificate-authority=/openshift.local.clusterup/kube-apiserver/ca.crt  \
    --dns-bind-address=0.0.0.0:8053  \
    --hostnames=localhost  \
    --hostnames=127.0.0.1  \
    --images="openshift/origin-\$\{component\}:v${OPENSHIFT_VERSION}"  \
    --node=localhost  \
    --node-client-certificate-authority=/openshift.local.clusterup/kube-apiserver/ca.crt  \
    --signer-cert=/openshift.local.clusterup/kube-apiserver/ca.crt  \
    --signer-key=/openshift.local.clusterup/kube-apiserver/ca.key  \
    --signer-serial=/openshift.local.clusterup/kube-apiserver/ca.serial.txt  \
    --volume-dir=/var/lib/origin/cluster-up/openshift.local.clusterup/openshift.local.volumes

# Patch the node configuration to disable features that do not work with Docker in Docker
cat << EOF >>"${TMP_DIR}/openshift.local.clusterup/node/node-config.yaml"
kubeletArguments:
  cgroups-per-qos:
    - "false"
  cgroup-driver:
    - "systemd"
  enforce-node-allocatable:
    - ""
EOF

# Set up the cluster itself
bazel run //hack/bin:oc3 cluster up

# Replace kube-dns with our patched CoreDNS
kubectl apply -n=kube-kube-dns -f "${SCRIPT_ROOT}/config/openshift-coredns.yaml"
kubectl delete --namespace=kube-dns ds kube-dns
kubectl rollout status deploy/coredns
