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

# Set DOCKER_REPO to customise the image docker repo, e.g. "quay.io/jetstack"
DOCKER_REPO :=
APP_VERSION := canary
HACK_DIR ?= hack

SKIP_GLOBALS := false
# Skip Venafi tests whilst there are issues with the TPP server
GINKGO_SKIP := Venafi
GINKGO_FOCUS :=

## e2e test vars
KUBECTL ?= kubectl
KUBECONFIG ?= $$HOME/.kube/config
FLAKE_ATTEMPTS ?= 1

# Get a list of all binaries to be built
CMDS := $(shell find ./cmd/ -maxdepth 1 -type d -exec basename {} \; | grep -v cmd)

.PHONY: help build verify push $(CMDS) e2e_test images images_push \
	verify_deps verify_chart

help:
	# This Makefile provides common wrappers around Bazel invocations.
	#
	### Verify targets
	#
	# verify             - runs all test targets (bazel test //...)
	# verify_deps        - ensure go module files are up to date (hack/update-deps.sh)
	# verify_chart       - runs Helm chart linter
	#
	### Generate targets
	#
	# generate           - regenerate all generated files
	#
	### Build targets
	#
	# controller         - build a binary of the 'controller'
	# cainjector         - build a binary of the 'cainjector'
	# webhook            - build a binary of the 'webhook'
	# acmesolver         - build a binary of the 'acmesolver'
	# e2e_test           - builds and runs end-to-end tests.
	#                      NOTE: you probably want to execute ./hack/ci/run-e2e-kind.sh instead of this target
	# images             - builds docker images for all of the components, saving them in your Docker daemon
	# images_push        - pushes docker images to the target registry
	#
	# Image targets can be run with optional args DOCKER_REPO and DOCKER_TAG:
	#
	#     make images DOCKER_REPO=quay.io/yourusername APP_VERSION=v0.11.0-dev.my-feature
	#

# Alias targets
###############

build: images
push: docker_push

verify:
	bazel test //...

# TODO: remove this rule in favour of calling hack/verify-deps directly
verify_deps:
	./hack/verify-deps.sh
	# verify-deps-licenses.sh is implicitly checked by the verify-deps script

# requires docker
verify_chart:
	$(HACK_DIR)/verify-chart-version.sh

# Go targets
############
$(CMDS):
	bazel build \
		//cmd/$@

e2e_test:
	mkdir -p "$$(pwd)/_artifacts"
	bazel build //hack/bin:helm //test/e2e:e2e.test
	# Run e2e tests
	KUBECONFIG=$(KUBECONFIG) \
		bazel run @com_github_onsi_ginkgo//ginkgo -- \
			-nodes 10 \
			-flakeAttempts $(FLAKE_ATTEMPTS) \
			$$(bazel info bazel-genfiles)/test/e2e/e2e.test \
			-- \
			--helm-binary-path=$$(bazel info bazel-genfiles)/hack/bin/helm \
			--repo-root="$$(pwd)" \
			--report-dir="$${ARTIFACTS:-./_artifacts}" \
			--ginkgo.skip="$(GINKGO_SKIP)" \
			--ginkgo.focus="$(GINKGO_FOCUS)" \
			--skip-globals=$(SKIP_GLOBALS) \
			--kubectl-path="$(KUBECTL)"

# Generate targets
##################
generate:
	./hack/update-all.sh

# Docker targets
################
images:
	bazel run //hack/release -- \
		--repo-root "$$(pwd)" \
		--images \
		--images.export=true \
		--images.goarch="amd64" \
		--app-version="$(APP_VERSION)" \
		--docker-repo="$(DOCKER_REPO)"

images_push: images
	bazel run //hack/release -- \
		--repo-root "$$(pwd)" \
		--images \
		--publish \
		--app-version="$(APP_VERSION)" \
		--docker-repo="$(DOCKER_REPO)"
