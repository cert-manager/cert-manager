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

# This script will provision an end-to-end testing environment using 'kind'
# (kubernetes-in-docker).
#
# It requires 'kind', 'helm', 'kubectl' and 'docker' to be installed.
# kubectl will be automatically installed if not found when on linux

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
REPO_ROOT="${SCRIPT_ROOT}/../.."

KIND_CLUSTER_NAME="cm-e2e"
# TODO: can we rely on this being fixed as such?
KIND_CONTAINER_NAME="kind-${KIND_CLUSTER_NAME}-control-plane"
KIND_IMAGE=${KIND_IMAGE:-eu.gcr.io/jetstack-build-infra-images/kind:1.11.2-0}

# cleanup will call kind delete - it will absorb errors
cleanup() {
    # Ignore errors here
    kind delete --name="${KIND_CLUSTER_NAME}" || true
}
trap cleanup EXIT

# deploy_kind will deploy a kubernetes-in-docker cluster
deploy_kind() {
    # create the kind cluster
    kind create \
        --name="${KIND_CLUSTER_NAME}" \
        --image="${KIND_IMAGE}" \
        --config "${REPO_ROOT}"/test/fixtures/kind-config.yaml

    export KUBECONFIG="${HOME}/.kube/kind-config-${KIND_CLUSTER_NAME}"

    # copy kubectl out of the kind container if kubectl is not installed on the
    # host machine. This will *only* work on Linux :this_is_fine:
    if ! which kubectl; then
        tmp_path=$(mktemp -d)
        export PATH="${tmp_path}:${PATH}"
        docker cp "${KIND_CONTAINER_NAME}":"$(docker exec "${KIND_CONTAINER_NAME}" which kubectl)" "${tmp_path}/kubectl"
    fi

    # Ensure the apiserver is responding
    kubectl get nodes
}

# install_tiller will install tiller with the cluster-admin role bound to its
# service account
install_tiller() {
    # Install tiller with admin permissions
    kubectl create serviceaccount -n kube-system tiller
    # Bind the tiller service account to the cluster-admin role
    kubectl create clusterrolebinding tiller-binding --clusterrole=cluster-admin --serviceaccount kube-system:tiller
    # Deploy tiller
    helm init --service-account tiller --wait
}

# install_nginx will install nginx-ingress in the cluster and expose it on the
# fixed cluster IP of 10.0.0.15
install_nginx() {
    # Install nginx-ingress with fixed IP
    helm install stable/nginx-ingress \
        --name nginx-ingress \
        --namespace kube-system \
        --set controller.service.clusterIP=10.0.0.15 \
        --set controller.service.type=ClusterIP \
        --wait
}

# build_images will build cert-manager docker images and copy them across to the
# kind docker container running the cluster, so they are available to the
# cluster's docker daemon.
build_images() {
    # Build cert-manager binaries & docker image
    make build APP_VERSION=build

    local TMP_DIR=$(mktemp -d)
    local BUNDLE_FILE="${TMP_DIR}"/cmbundle.tar.gz
    docker save quay.io/jetstack/cert-manager-controller:build quay.io/jetstack/cert-manager-acmesolver:build quay.io/jetstack/cert-manager-webhook:build -o "${BUNDLE_FILE}"
    docker cp "${BUNDLE_FILE}" "${KIND_CONTAINER_NAME}":/cmbundle.tar.gz
    docker exec "${KIND_CONTAINER_NAME}" docker load -i /cmbundle.tar.gz
    rm -Rf "${TMP_DIR}"
}

deploy_kind
install_tiller
install_nginx
build_images

make e2e_test E2E_NGINX_CERTIFICATE_DOMAIN=certmanager.kubernetes.network KUBECONFIG=${KUBECONFIG}
