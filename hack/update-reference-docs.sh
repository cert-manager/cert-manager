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

## This script will generate a reference documentation site into ./docs/generated/reference/reference/api-docs
## It requires a number of tools be installed:
##
## * openapi-gen
## * gen-apidocs
##

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")/..

REFERENCE_PATH="docs/generated/reference"
REFERENCE_ROOT=$(cd "${SCRIPT_ROOT}/${REFERENCE_PATH}" 2> /dev/null && pwd -P)
OUTPUT_DIR="${REFERENCE_ROOT}/output/reference/api-docs"

## cleanup removes files that are leftover from running various tools and not required
## for the actual output
cleanup() {
    pushd "${REFERENCE_ROOT}"
    echo "+++ Cleaning up temporary docsgen files"
    # Clean up old temporary files
    rm -Rf "openapi-spec" "includes" "manifest.json"
    popd
}

# Ensure we start with a clean set of directories
trap cleanup EXIT
cleanup
echo "+++ Removing old output"
rm -Rf "${OUTPUT_DIR}"

echo "+++ Creating temporary output directories"

# Create all required directories
mkdir -p "${REFERENCE_ROOT}/openapi"
# Create a placeholder .go file to prevent issues with openapi-gen
echo "package openapi" > "${REFERENCE_ROOT}/openapi/openapi_generated.go"
echo "+++ Generating openapi_generated.go into 'github.com/jetstack/cert-manager/${REFERENCE_PATH}/openapi'"
# Generate Golang types for OpenAPI spec
bazel run //:openapi-gen -- \
        --input-dirs github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1,k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/apimachinery/pkg/runtime,k8s.io/apimachinery/pkg/version \
        --output-package "github.com/jetstack/cert-manager/docs/generated/reference/openapi" \
        --go-header-file "$(pwd)/hack/boilerplate/boilerplate.go.txt"

"${SCRIPT_ROOT}"/hack/update-bazel.sh

# Generate swagger.json from the Golang generated openapi spec
mkdir -p "${REFERENCE_ROOT}/openapi-spec"
echo "+++ Running 'swagger-gen' to generate swagger.json"
bazel run "//docs/generated/reference/swagger-gen" > "${REFERENCE_ROOT}/openapi-spec/swagger.json"

# Generate Markdown docs to be used as input for brodocs
# This generates the manifest.json file, as well as the *.md files in includes/
echo "+++ Running gen-apidocs"
bazel run //vendor/github.com/kubernetes-incubator/reference-docs/gen-apidocs -- \
    --copyright "<a href=\"https://jetstack.io\">Copyright 2018 Jetstack Ltd.</a>" \
    --title "Cert-manager API Reference" \
    --config-dir "${REFERENCE_ROOT}"

# Run brodocs to generate a HTML site from the generated markdown and manifest json
echo "+++ Running brodocs"
mkdir -p "${OUTPUT_DIR}"
BAZEL_BRODOCS_RUNFILES="bazel-bin/hack/brodocs/brodocs.runfiles"
BAZEL_BRODOCS_NODE_MODULES="${BAZEL_BRODOCS_RUNFILES}/brodocs_modules/node_modules"
BAZEL_BRODOCS_PATH="${BAZEL_BRODOCS_RUNFILES}/__main__/external/brodocs"
bazel run //hack/brodocs -- \
    "${REFERENCE_ROOT}/manifest.json" \
    "${REFERENCE_ROOT}/includes" \
    "${OUTPUT_DIR}"

# Copy across supporting files from the brodocs repo
cp "${BAZEL_BRODOCS_PATH}"/stylesheet.css \
   "${BAZEL_BRODOCS_PATH}"/scroll.js \
   "${BAZEL_BRODOCS_PATH}"/actions.js \
   "${BAZEL_BRODOCS_PATH}"/tabvisibility.js \
   "${OUTPUT_DIR}/"

mkdir -p "${OUTPUT_DIR}/node_modules/jquery/dist"
cp "${BAZEL_BRODOCS_NODE_MODULES}/jquery/dist/jquery.min.js" "${OUTPUT_DIR}/node_modules/jquery/dist/"

mkdir -p "${OUTPUT_DIR}/node_modules/bootstrap/dist/css"
cp "${BAZEL_BRODOCS_NODE_MODULES}/bootstrap/dist/css/bootstrap.min.css" "${OUTPUT_DIR}/node_modules/bootstrap/dist/css/"

mkdir -p "${OUTPUT_DIR}/node_modules/font-awesome/css"
cp "${BAZEL_BRODOCS_NODE_MODULES}/font-awesome/css/"* "${OUTPUT_DIR}/node_modules/font-awesome/css/"

mkdir -p "${OUTPUT_DIR}/node_modules/font-awesome/fonts"
cp "${BAZEL_BRODOCS_NODE_MODULES}/font-awesome/fonts/"* "${OUTPUT_DIR}/node_modules/font-awesome/fonts/"

mkdir -p "${OUTPUT_DIR}/node_modules/highlight.js/styles"
cp "${BAZEL_BRODOCS_NODE_MODULES}/highlight.js/styles/default.css" "${OUTPUT_DIR}/node_modules/highlight.js/styles/"

mkdir -p "${OUTPUT_DIR}/node_modules/jquery.scrollto"
cp "${BAZEL_BRODOCS_NODE_MODULES}/jquery.scrollto/jquery.scrollTo.min.js" "${OUTPUT_DIR}/node_modules/jquery.scrollto/"
