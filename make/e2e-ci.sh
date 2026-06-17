#!/usr/bin/env bash

# Copyright 2022 The cert-manager Authors.
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

trap 'make kind-logs' EXIT

# Note: We set CI here, even though it should be set by Prow, which is the cert-manager CI test runner
# See the list of defined variables here: https://docs.prow.k8s.io/docs/jobs/#job-environment-variables
# We explicitly set CI here because it helps with local testing
# (i.e. "I want to run the exact same e2e test that will be run in CI")
# and because it allows us to be explicit about where it's getting set when we call "make e2e-ci"

make --no-print-directory e2e FLAKE_ATTEMPTS=2 CI=true K8S_VERSION="$K8S_VERSION"
