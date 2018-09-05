#!/usr/bin/env bash

set -o errexit
set -o nounset
set -o pipefail
set -o xtrace


retry() {
  for i in {1..5}; do
    "$@" && return 0 || sleep $i
  done
  "$@"
}

# Runs the unit and integration tests, producing JUnit-style XML test
# reports in ${WORKSPACE}/artifacts. This script is intended to be run from
# cert-manager-test container with a cert-manager repo mapped in. See
# github.com/jetstack/test-infra/scenarios/cert-manager_verify.py

# TODO: actually utilise this and run integration tests that require etcd
export PATH=${GOPATH}/bin:${PWD}/third_party/etcd:/usr/local/go/bin:${PATH}

cd /go/src/github.com/jetstack/cert-manager

make verify
