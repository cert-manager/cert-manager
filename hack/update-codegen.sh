#!/bin/bash

# Copyright 2018 The Jetstack cert-manager contributors.
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

# This script should be run via `bazel run //hack:update-bazel`
REPO_ROOT=${BUILD_WORKSPACE_DIRECTORY:-"$(cd "$(dirname "$0")" && pwd -P)"/..}
runfiles="$(pwd)"
export PATH="${runfiles}/third_party/k8s.io/code-generator:${runfiles}/hack:${runfiles}/hack/bin:${PATH}"
cd "${REPO_ROOT}"

generate-groups.sh "deepcopy,client,informer,lister" \
  github.com/jetstack/cert-manager/pkg/client github.com/jetstack/cert-manager/pkg/apis \
  certmanager:v1alpha1 \
  --output-base "${GOPATH}/src/" \
  --go-header-file "${runfiles}/hack/boilerplate/boilerplate.go.txt"

OPENAPI_PATH_SEGMENT="docs/generated/reference/openapi"
OPENAPI_OUTPUT_DIR="${REPO_ROOT}/${OPENAPI_PATH_SEGMENT}"
# Create all required directories
mkdir -p "${OPENAPI_OUTPUT_DIR}"
if [ ! -f "${OPENAPI_OUTPUT_DIR}/openapi_generated.go" ]; then
    # Create a placeholder .go file to prevent issues with openapi-gen
    echo "package openapi" > "${OPENAPI_OUTPUT_DIR}/openapi_generated.go"
fi

echo "+++ Generating openapi_generated.go into 'github.com/jetstack/cert-manager/${OPENAPI_PATH_SEGMENT}'"
# Generate Golang types for OpenAPI spec
openapi-gen \
        --input-dirs github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1,k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/apimachinery/pkg/runtime,k8s.io/apimachinery/pkg/version \
        --go-header-file "${runfiles}/hack/boilerplate/boilerplate.go.txt" \
        --output-package "github.com/jetstack/cert-manager/${OPENAPI_PATH_SEGMENT}"

update-bazel.sh
