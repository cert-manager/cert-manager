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

set -o nounset
set -o errexit
set -o pipefail

# This script will run the end-to-end test suite against an already configured
# kind cluster.
# If a cluster does not already exist, create one with 'cluster/create-kind.sh'.

SCRIPT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"
export REPO_ROOT="${SCRIPT_ROOT}/.."
source "${SCRIPT_ROOT}/lib/lib.sh"

GINKGO_SKIP=${GINKGO_SKIP:-}
GINKGO_FOCUS=${GINKGO_FOCUS:-}

# Skip Gateway tests for Kubernetes below v1.19
if [[ "$K8S_VERSION" =~ 1\.16 ]] || [[ "$K8S_VERSION" =~ 1\.17 ]] || [[ "$K8S_VERSION" =~ 1\.18 ]]; then
	echo "Kubernetes version ${K8S_VERSION}, skipping Gateway tests..."
	if [[ -z "$GINKGO_SKIP" ]]; then
		GINKGO_SKIP="Gateway"
	else
	# duplicates are ok
	GINKGO_SKIP="${GINKGO_SKIP}|Gateway"
	fi
fi

# GINKGO_FOCUS can be set to a regex matching ginkgo specs to run.
# Example- 'export GINKGO_FOCUS='Gateway' (runs only test cases with 'Gateway' in name).
if [[ -n "$GINKGO_FOCUS" ]]; then GINKGO_FOCUS="--ginkgo.focus=${GINKGO_FOCUS}"; fi

# GINKGO_SKIP can be set to a regex matching ginkgo specs to skip. Example-
# 'export GINKGO_SKIP="Venafi Cloud"' (skips all suites with 'Venafi Cloud' in the name).
if  [[ -n "$GINKGO_SKIP" ]]; then GINKGO_SKIP="--ginkgo.skip=${GINKGO_SKIP}"; fi

# Default feature gates to enable
FEATURE_GATES="${FEATURE_GATES:-AdditionalCertificateOutputFormats=true,ExperimentalCertificateSigningRequestControllers=true,ExperimentalGatewayAPISupport=true}"

# Configure PATH to use bazel provided e2e tools
setup_tools

# Ensure bazel is installed
check_bazel

# Create output directory for JUnit output
mkdir -p "${REPO_ROOT}/_artifacts"

# Build the e2e test binary
bazel build //test/e2e:e2e.test

# Run e2e tests
ginkgo -nodes 10 -flakeAttempts ${FLAKE_ATTEMPTS:-1} \
	$(bazel info bazel-genfiles)/test/e2e/e2e.test \
	-- \
	--repo-root="${REPO_ROOT}" \
	--report-dir="${ARTIFACTS:-$REPO_ROOT/_artifacts}" \
	--acme-dns-server="$DNS_SERVER" \
	--acme-ingress-ip="$INGRESS_IP" \
	--feature-gates="${FEATURE_GATES}" \
	${GINKGO_SKIP:+"$GINKGO_SKIP"} \
	${GINKGO_FOCUS:+"$GINKGO_FOCUS"} \
	"$@"
