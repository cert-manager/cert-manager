#!/usr/bin/env bash

# Copyright 2020 The cert-manager Authors.
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

# This script will build an entirely new testing environment using kind.
# This is intended to be run in a CI environment and *not* for development.
# It is not optimised for quick, iterative development.

SCRIPT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"
export REPO_ROOT="${SCRIPT_ROOT}/.."
source "${SCRIPT_ROOT}/lib/lib.sh"

# Configure PATH to use bazel provided e2e tools
setup_tools

export SERVICE_IP_PREFIX="10.0.0"
if [[ "$IS_OPENSHIFT" == "true" ]] ; then
  export SERVICE_IP_PREFIX="172.30.0"
fi

# When running in our CI environment the Docker network's subnet choice will
# cause issues with routing. This works this around till we have a way to
# properly patch this.
if ! docker network inspect kind ; then
  docker network create --driver=bridge --subnet=192.168.0.0/16 --gateway 192.168.0.1 kind
fi

# Wait for the network to be created so kind does not overwrite it.
while ! docker network inspect kind ; do
  sleep 100ms
done

echo "Ensuring a cluster exists..."
if [[ "$IS_OPENSHIFT" == "true" ]] ; then
  if [[ "$OPENSHIFT_VERSION" =~  3\..* ]] ; then
    "${SCRIPT_ROOT}/cluster/create-openshift3.sh"
  else
    echo "Unsupported OpenShift version: ${OPENSHIFT_VERSION}"
    exit 1
  fi
else
  trap "export_logs" ERR
  "${SCRIPT_ROOT}/cluster/create-kind.sh"
fi
