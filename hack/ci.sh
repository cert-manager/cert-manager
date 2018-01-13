#!/bin/bash

## This file is a stop gap whilst we migrate the Makefile to better
## supprt prow for our testing

curl -L https://github.com/docker/compose/releases/download/1.18.0/docker-compose-`uname -s`-`uname -m` -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Build images while we wait for services to start
make build APP_VERSION=build

# Wait for e2e service dependencies
./hack/test/wait-minikube.sh

# Setup service for nginx ingress controller. A DNS entry for *.certmanager.kubernetes.network has been setup to point to 10.0.0.15 for e2e tests
while true; do if kubectl get rc nginx-ingress-controller -n kube-system; then break; fi; echo "Waiting 5s for nginx-ingress-controller rc to be installed..."; sleep 5; done
kubectl expose -n kube-system --port 80 --target-port 80 --type ClusterIP rc nginx-ingress-controller --cluster-ip 10.0.0.15

make e2e_test E2E_NGINX_CERTIFICATE_DOMAIN=certmanager.kubernetes.network BOULDER_IMAGE_REPO=gcr.io/jetstack-build-infra/boulder
