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
#
# Installs an instance of the sample-external-issuer:
# * https://github.com/cert-manager/sample-external-issuer

set -o nounset
set -o errexit
set -o pipefail

SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")
source "${SCRIPT_ROOT}/../../lib/lib.sh"
SCRIPT_ROOT=$(dirname "${BASH_SOURCE}")

setup_tools

repo_dir="$(mktemp -d)"

function cleanup {
    rm -rf "${repo_dir}"
}

trap cleanup EXIT

git clone https://github.com/cert-manager/sample-external-issuer "${repo_dir}"

# TODO: Move this image to quay.io
# https://github.com/cert-manager/cert-manager/issues/3531
img="ghcr.io/wallrj/sample-external-issuer/controller:v0.0.0-30-gf333b9e"

require_image "${img}" "//devel/addon/sample-external-issuer:bundle"

make -C "${repo_dir}" "IMG=${img}" deploy
