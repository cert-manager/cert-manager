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

if [[ -n "${BUILD_WORKSPACE_DIRECTORY:-}" ]]; then # Running inside bazel
  echo "Updating modules..." >&2
elif ! command -v bazel &>/dev/null; then
  echo "Install bazel at https://bazel.build" >&2
  exit 1
else
  (
    set -o xtrace
    bazel run //devel/cluster:create-openshift3 -- "$@"
  )
  exit 0
fi

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
OPENSHIFT_VERSION=${OPENSHIFT_VERSION:-"3.11"} # This is unlikely to change in the future as this is the last release in the OpenShift 3 series
TMP_DIR=$(mktemp -d)
oc3=$(realpath "$1")
kubectl=$(realpath "$2")

if docker ps | grep "openshift/origin-node:v${OPENSHIFT_VERSION}" &>/dev/null; then
  echo "Existing OpenShift 3 cluster found, skipping creating cluster..."
  exit 0
fi

# Patch Docker daemon for OpenShift internal registry
mkdir /etc/docker/
cat << EOF >> /etc/docker/daemon.json
{
 "insecure-registries": [
    "172.30.0.0/16"
 ]
}
EOF

service docker restart

# Needed for `oc cluster up` as it places files in the current directory
cd "${TMP_DIR}"

mkdir -p "${TMP_DIR}/openshift.local.clusterup/kube-apiserver/"

# Let OpenShift generate all certificates and setup for the controller
docker run -v $(pwd)/openshift.local.clusterup/kube-apiserver/:/var/lib/origin/openshift.local.config/ \
    "openshift/origin-control-plane:v${OPENSHIFT_VERSION}" start master \
    --write-config=/var/lib/origin/openshift.local.config \
    --master=127.0.0.1 \
    --images='openshift/origin-${component}:v$OPENSHIFT_VERSION' \
    --dns=0.0.0.0:8053 \
    --public-master=https://127.0.0.1:8443 \
    --etcd-dir=/var/lib/etcd

# Let OpenShift generate all certificates and setup for the node
"$oc3" adm create-node-config \
    --node-dir="${TMP_DIR}/openshift.local.clusterup/node" \
    --certificate-authority="${TMP_DIR}/openshift.local.clusterup/kube-apiserver/ca.crt" \
    --dns-bind-address=0.0.0.0:8053 \
    --hostnames=localhost \
    --hostnames=127.0.0.1 \
    --images="openshift/origin-\$\{component\}:v${OPENSHIFT_VERSION}" \
    --node=localhost  \
    --node-client-certificate-authority="${TMP_DIR}/openshift.local.clusterup/kube-apiserver/ca.crt" \
    --signer-cert="${TMP_DIR}/openshift.local.clusterup/kube-apiserver/ca.crt" \
    --signer-key="${TMP_DIR}/openshift.local.clusterup/kube-apiserver/ca.key" \
    --signer-serial="${TMP_DIR}/openshift.local.clusterup/kube-apiserver/ca.serial.txt"\
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
"$oc3" cluster up

# Replace kube-dns with our patched CoreDNS
"$kubectl" apply -n=kube-kube-dns -f "${SCRIPT_ROOT}/config/openshift-coredns.yaml"
"$kubectl" delete --namespace=kube-dns ds kube-dns
"$kubectl" rollout status deploy/coredns
