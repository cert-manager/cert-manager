#!/bin/bash

# The only argument this script should ever be called with is '--verify-only'

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname ${BASH_SOURCE})/..
CODEGEN_PKG=${CODEGEN_PKG:-$(cd ${SCRIPT_ROOT}; ls -d -1 ./vendor/k8s.io/code-generator 2>/dev/null || echo ../code-generator)}

${CODEGEN_PKG}/generate-groups.sh "deepcopy,defaulter,client,informer,lister" \
  github.com/jetstack/cert-manager/pkg/client github.com/jetstack/cert-manager/pkg/apis \
  certmanager:v1alpha1 \
  --output-base "${GOPATH}/src/" \
  --go-header-file ${SCRIPT_ROOT}/hack/boilerplate.go.txt

${GOPATH}/bin/informer-gen \
           --output-base "${GOPATH}/src/" \
           --input-dirs "k8s.io/api/core/v1" \
           --input-dirs "k8s.io/api/extensions/v1beta1" \
           --versioned-clientset-package "k8s.io/client-go/kubernetes" \
           --listers-package "k8s.io/client-go/listers" \
           --output-package "github.com/jetstack/cert-manager/third_party/k8s.io/client-go/informers" \
           --go-header-file ${SCRIPT_ROOT}/hack/boilerplate.go.txt \
           --single-directory
