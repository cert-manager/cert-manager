#!/usr/bin/env bash

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

set -o errexit
set -o nounset
set -o pipefail

## Sample bash script demonstrating how to use the release tool.

### Build a local copy of all amd64 image components using a custom repo name

bazel run //hack/release -- \
    --docker-repo index.docker.io/mydockerhubuser \
    --images \
    --images.goarch amd64 \

### Build a local copy of the controller image for amd64

bazel run //hack/release -- \
    --images \
    --images.goarch amd64 \
    --images.components controller
