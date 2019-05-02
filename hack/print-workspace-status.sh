#!/bin/bash

# Copyright 2019 The Jetstack cert-manager contributors.
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

# The only argument this script should ever be called with is '--verify-only'

set -o errexit
set -o nounset
set -o pipefail

SCRIPT_ROOT=$(dirname ${BASH_SOURCE})/../..

# AppVersion is set as the AppVersion to be compiled into the controller binary.
# It's used as the default version of the 'acmesolver' image to use for ACME
# challenge requests, and any other future provider that requires additional
# image dependencies will use this same tag.
if [ -z "${APP_VERSION:-}" ]; then
    APP_VERSION=canary
fi
APP_GIT_COMMIT=${APP_GIT_COMMIT:-$(git rev-parse HEAD)}
GIT_STATE=""
if [ ! -z "$(git status --porcelain)" ]; then
    GIT_STATE="dirty"
fi

# TODO: properly configure this file
cat <<EOF
STABLE_DOCKER_REPO ${DOCKER_REPO:-quay.io/jetstack}
STABLE_DOCKER_TAG ${DOCKER_TAG:-$APP_VERSION}
STABLE_APP_GIT_COMMIT ${APP_GIT_COMMIT}
STABLE_APP_GIT_STATE ${GIT_STATE}
STABLE_APP_VERSION ${APP_VERSION}
EOF
