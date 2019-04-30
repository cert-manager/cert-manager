#!/usr/bin/env bash

# +skip_license_check

# Copyright 2019 The Kubernetes Authors.
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

set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT=$(dirname "${BASH_SOURCE[0]}")/..

# Usage:
#   hack/pin-dependency.sh $MODULE $SHA-OR-TAG
#
# Example:
#   hack/pin-dependency.sh github.com/docker/docker 501cb131a7b7

# Explicitly opt into go modules, even though we're inside a GOPATH directory
export GO111MODULE=on
# Explicitly clear GOPATH, to ensure nothing this script calls makes use of that path info
export GOPATH=
# Explicitly clear GOFLAGS, since GOFLAGS=-mod=vendor breaks dependency resolution while rebuilding vendor
export GOFLAGS=
# Detect problematic GOPROXY settings that prevent lookup of dependencies
if [[ "${GOPROXY:-}" == "off" ]]; then
  echo "Cannot run hack/pin-dependency.sh with \$GOPROXY=off"
  exit 1
fi

dep="${1:-}"
sha="${2:-}"
if [[ -z "${dep}" || -z "${sha}" ]]; then
  echo "Usage:"
  echo "  hack/pin-dependency.sh \$MODULE \$SHA-OR-TAG"
  echo ""
  echo "Example:"
  echo "  hack/pin-dependency.sh github.com/docker/docker 501cb131a7b7"
  echo ""
  exit 1
fi

# Add the require directive
echo "Running: go get ${dep}@${sha}"
bazel run //hack/bin:go -- get -d "${dep}@${sha}"

# Find the resolved version
rev=$(go mod edit -json | jq -r ".Require[] | select(.Path == \"${dep}\") | .Version")
echo "Resolved to ${dep}@${rev}"

# Add the replace directive
echo "Running: go mod edit -replace ${dep}=${dep}@${rev}"
bazel run //hack/bin:go -- mod edit -replace "${dep}=${dep}@${rev}"

echo ""
echo "Run hack/update-vendor.sh to rebuild the vendor directory"
