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

# ensure_cert_ready ensures that a cert becomes Ready within a minute, errors if
# not.
ensure_cert_ready() {
  if [[ $# == 0 ]]; then
    echo "Usage 'ensure_cert_ready CERT'"
    exit 2
  fi
  cert="$1"

  for i in 0..30; do
    conditionsLength=$(kubectl get certificate $cert -ojson | jq -r '.status.conditions' | jq length)
    # cert will not have a Ready condition at the start, especially not right
    # after upgrade as the controller pod will take a while to obtain leader
    # election lock.
    if [[ ! "$conditionsLength" = "0" ]]; then
      readyConditon=$(kubectl get certificate $cert -ojson | jq -r '.status.conditions[] | select(.type=="Ready")')
      if [[ ! -z "readyCondition" ]]; then
        isReady=$(kubectl get certificate $cert -ojson | jq -r '.status.conditions[] | select(.type=="Ready").status')
        if [ "$isReady" = "True" ]; then
          echo "Cert ${cert} is Ready"
          break
	fi
      fi
    elif [ i == "30" ]; then
	echo "Timed out waiting for cert ${cert} to become Ready"
	exit 1
    fi
    sleep 2
  done
}