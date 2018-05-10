#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace

# Runs the e2e tests, producing JUnit-style XML test
# reports in ${WORKSPACE}/artifacts. This script is intended to be run from
# cert-manager-test container with a cert-manager repo mapped in. See
# github.com/jetstack/test-infra/scenarios/cert-manager_e2e.py

while true; do if kubectl get nodes; then break; fi; echo "Waiting 5s for kubernetes to be ready..."; sleep 5; done
while true; do if kubectl get namespace kube-system; then break; fi; echo "Waiting 5s for kube-system to exist"; sleep 5; done

echo "Installing helm with cluster-admin privileges..."
# Create a service account for tiller
kubectl create serviceaccount -n kube-system tiller
# Bind the tiller service account to the cluster-admin role
kubectl create clusterrolebinding tiller-binding --clusterrole=cluster-admin --serviceaccount kube-system:tiller
# Deploy tiller
helm init --service-account=tiller

while true; do if helm version; then break; fi; echo "Waiting 5s for tiller to be ready"; sleep 5; done

echo "Exposing nginx-ingress service with a stable IP (10.80.0.123)"
# Setup service for nginx ingress controller. A DNS entry for *.certmanager.kubernetes.network has been setup to point to 10.80.0.123 for e2e tests
helm repo update
helm install stable/nginx-ingress --wait --version 0.18.1 \
    --set controller.service.clusterIP=10.80.0.123

cd /go/src/github.com/jetstack/cert-manager
echo "Running e2e tests"
make e2e_test E2E_NGINX_CERTIFICATE_DOMAIN=certmanager.kubernetes.network
