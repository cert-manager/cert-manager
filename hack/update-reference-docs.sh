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
    find "${OUTPUT_DIR}" \
        \( -type l -o -type f \) \
        -not -name bootstrap.min.css \
        -not -name font-awesome.min.css \
        -not -name highlight.js \
        -not -name stylesheet.css \
        -not -name index.html \
        -not -name scroll.js \
        -not -name tabvisibility.js \
        -not -name default.css \
        -not -name navData.js \
        -not -name jquery.min.js \
        -not -name jquery.scrollTo.min.js \
        -not -name fontawesome-webfont.ttf \
        -not -name fontawesome-webfont.woff \
        -not -name fontawesome-webfont.woff2 \
        -exec rm -Rf {} \; || true
    find "${OUTPUT_DIR}" \
        -type d \
        -depth \
        -exec rmdir {} \; > /dev/null 2>&1
    rm -Rf "openapi-spec" "openapi" "includes" "manifest.json"

    popd
}

trap cleanup EXIT

mkdir -p "${OUTPUT_DIR}"

cleanup
echo "+++ Removing old output"
rm -Rf "${OUTPUT_DIR}"

echo "+++ Creating temporary directories"

# Create all required directories
mkdir -p "${REFERENCE_ROOT}/openapi-spec"
mkdir -p "${REFERENCE_ROOT}/openapi"
mkdir -p "${OUTPUT_DIR}"
# Create a placeholder .go file to prevent issues with openapi-gen
echo "package openapi" > "${REFERENCE_ROOT}/openapi/openapi_generated.go"

echo "+++ Building openapi-gen"
OPENAPI_GEN="$(mktemp)"
go build -o "${OPENAPI_GEN}" ./vendor/k8s.io/code-generator/cmd/openapi-gen

echo "+++ Generating openapi_generated.go into 'github.com/jetstack/cert-manager/${REFERENCE_PATH}/openapi'"
# Generate Golang types for OpenAPI spec
${OPENAPI_GEN} \
        --input-dirs github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1,k8s.io/apimachinery/pkg/apis/meta/v1,k8s.io/apimachinery/pkg/runtime,k8s.io/apimachinery/pkg/version \
        --output-package "github.com/jetstack/cert-manager/${REFERENCE_PATH}/openapi"

echo "+++ Running './${REFERENCE_PATH}/main.go'"
# Generate swagger.json
go run "./${REFERENCE_PATH}/main.go"

echo "+++ Running gen-apidocs"
# Generate Markdown docs
gen-apidocs \
    --copyright "<a href=\"https://jetstack.io\">Copyright 2018 Jetstack Ltd.</a>" \
    --title "Cert-manager API Reference" \
    --config-dir ./docs/generated/reference/

echo "+++ Running brodocs"
INCLUDES_DIR="${REFERENCE_ROOT}/includes" \
OUTPUT_DIR="${OUTPUT_DIR}" \
MANIFEST_PATH="${REFERENCE_ROOT}/manifest.json" \
runbrodocs.sh
