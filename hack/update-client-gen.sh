#!/bin/bash

# The only argument this script should ever be called with is '--verify-only'

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname ${BASH_SOURCE})/..
CODEGEN_PKG=${CODEGEN_PKG:-$(cd ${SCRIPT_ROOT}; ls -d -1 ./vendor/k8s.io/code-generator 2>/dev/null || echo ../code-generator)}

${CODEGEN_PKG}/generate-groups.sh "deepcopy,defaulter,client,informer,lister" \
  github.com/jetstack-experimental/cert-manager/pkg/client github.com/jetstack-experimental/cert-manager/pkg/apis \
  certmanager:v1alpha1 \
  --output-base "${GOPATH}/src/" \
  --go-header-file ${SCRIPT_ROOT}/hack/boilerplate.go.txt
