#!/bin/bash

# The only argument this script should ever be called with is '--verify-only'

set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT=$(dirname "${BASH_SOURCE}")/..
BINDIR=${REPO_ROOT}/bin

# Generate defaults
${BINDIR}/defaulter-gen \
          --v 1 --logtostderr \
          --go-header-file "${GOPATH}/src/github.com/kubernetes/repo-infra/verify/boilerplate/boilerplate.go.txt" \
          --input-dirs "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1" \
          --extra-peer-dirs "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1" \
          --output-file-base "zz_generated.defaults"
# Generate deep copies
${BINDIR}/deepcopy-gen \
          --v 1 --logtostderr \
          --go-header-file "${GOPATH}/src/github.com/kubernetes/repo-infra/verify/boilerplate/boilerplate.go.txt" \
          --input-dirs "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1" \
          --output-file-base zz_generated.deepcopy
# Generate the versioned clientset (pkg/client/clientset_generated/clientset)
${BINDIR}/client-gen "$@" \
          --input-base "github.com/jetstack/cert-manager/pkg/apis/" \
          --input "certmanager/v1alpha1" \
          --clientset-path "github.com/jetstack/cert-manager/pkg/client" \
          --clientset-name "clientset" \
          --go-header-file "${GOPATH}/src/github.com/kubernetes/repo-infra/verify/boilerplate/boilerplate.go.txt"
# generate lister
${BINDIR}/lister-gen "$@" \
          --input-dirs="github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1" \
          --output-package "github.com/jetstack/cert-manager/pkg/client/listers" \
          --go-header-file "${GOPATH}/src/github.com/kubernetes/repo-infra/verify/boilerplate/boilerplate.go.txt"
# generate informer
${BINDIR}/informer-gen "$@" \
          --go-header-file "${GOPATH}/src/github.com/kubernetes/repo-infra/verify/boilerplate/boilerplate.go.txt" \
          --input-dirs "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1" \
          --versioned-clientset-package "github.com/jetstack/cert-manager/pkg/client/clientset" \
          --listers-package "github.com/jetstack/cert-manager/pkg/client/listers" \
          --output-package "github.com/jetstack/cert-manager/pkg/client/informers" \
          --single-directory
