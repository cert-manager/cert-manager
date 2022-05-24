#!/usr/bin/env bash

# Copyright 2022 The cert-manager Authors.
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

LIB_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"
export REPO_ROOT="$LIB_ROOT/../.."

if ! kubectl cluster-info; then
	echo "Error: this script should only be run when a cluster has already been created"
	exit 1
fi

until kubectl cluster-info dump | grep service-cluster-ip-range; do
	echo "Waiting for kubectl cluster-info to be up to date..."
	sleep
done

export SERVICE_IP_PREFIX=$(kubectl cluster-info dump | grep ip-range | head -n1 | cut -d= -f2 | cut -d. -f1,2,3)
export DNS_SERVER="${SERVICE_IP_PREFIX}.16"
export INGRESS_IP="${SERVICE_IP_PREFIX}.15"
export GATEWAY_IP="${SERVICE_IP_PREFIX}.14"
