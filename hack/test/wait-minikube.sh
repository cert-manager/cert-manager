#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

while true; do if kubectl get nodes; then break; fi; echo "Waiting 5s for kubernetes to be ready..."; sleep 5; done