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

# This script should be run via `bazel run //hack:update-reference-docs`
REPO_ROOT=${BUILD_WORKSPACE_DIRECTORY:-"$(cd "$(dirname "$0")" && pwd -P)"/..}
runfiles="${runfiles:-$(pwd)}"
export PATH="${runfiles}/hack/bin:${runfiles}/hack/brodocs:${PATH}"
cd "${REPO_ROOT}"

REFERENCE_PATH="docs/generated/reference"
REFERENCE_ROOT=$(cd "${REPO_ROOT}/${REFERENCE_PATH}" 2> /dev/null && pwd -P)
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

# Generate swagger.json from the Golang generated openapi spec
echo "+++ Running 'swagger-gen' to generate swagger.json"
mkdir -p "${REFERENCE_ROOT}/openapi-spec"
# Generate swagger.json
# TODO: can we output to a tmpfile instead of in the repo?
swagger-gen > "${REFERENCE_ROOT}/openapi-spec/swagger.json"

echo "+++ Running gen-apidocs"
# Generate Markdown docs
gen-apidocs \
    --copyright "<a href=\"https://jetstack.io\">Copyright 2018 Jetstack Ltd.</a>" \
    --title "Cert-manager API Reference" \
    --config-dir "${REFERENCE_ROOT}"

echo "+++ Running brodocs"
mkdir -p "${OUTPUT_DIR}"

# Running a bazel-built target from the 'bazel run' context has some nuances
# which cause runfiles to not be visible properly.
# We fudge the vars used by the runfiles loader snippet to point to the correct
# runfiles.
# We depend on brodocs itself, and include all its dependencies as a dependency
# of this target.
BRODOCS_RUNFILES="${runfiles}/.."
RUNFILES_DIR="${BRODOCS_RUNFILES}" brodocs \
    "${REFERENCE_ROOT}/manifest.json" \
    "${REFERENCE_ROOT}/includes" \
    "${OUTPUT_DIR}"

BAZEL_BRODOCS_PATH="${BRODOCS_RUNFILES}/brodocs"
BAZEL_BRODOCS_NODE_MODULES="${BRODOCS_RUNFILES}/brodocs_modules/node_modules"

# Copy across support files for docs.
# These commands had to be manually written after inspecting the required output.
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
