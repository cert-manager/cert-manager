#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

# Create a cluster. We do this as root as we are using the 'docker' driver.
sudo -E CHANGE_MINIKUBE_NONE_USER=true minikube start --vm-driver=none --extra-config=apiserver.Authorization.Mode=RBAC --kubernetes-version="${KUBERNETES_VERSION}"
sudo -E CHANGE_MINIKUBE_NONE_USER=true minikube addons enable ingress
