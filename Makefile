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

GINKGO_SKIP :=

## e2e test vars
KUBECTL ?= kubectl
KUBECONFIG ?= $$HOME/.kube/config

# Get a list of all binaries to be built
CMDS := $(shell find ./cmd/ -maxdepth 1 -type d -exec basename {} \; | grep -v cmd)

.PHONY: help build verify push $(CMDS) e2e_test images images_push \
	verify_lint verify_unit verify_deps verify_codegen verify_docs verify_chart \

help:
	# This Makefile provides common wrappers around Bazel invocations.
	#
	### Verify targets
	#
	# verify_lint        - run 'lint' targets
	# verify_unit        - run unit tests
	# verify_deps        - verifiy vendor/ and Gopkg.lock is up to date
	# verify_codegen     - verify generated code, including 'static deploy manifests', is up to date
	# verify_docs        - verify the generated reference docs for API types is up to date
	# verify_chart       - runs Helm chart linter (e.g. ensuring version has been bumped etc)
	#
	### Generate targets
	#
	# generate           - regenerate all generated files
	#
	### Build targets
	#
	# controller         - build a binary of the 'controller'
	# injectorcontroller - build a binary of the 'injectorcontroller'
	# webhook            - build a binary of the 'webhook'
	# acmesolver         - build a binary of the 'acmesolver'
	# e2e_test           - builds and runs end-to-end tests.
	#                      NOTE: you probably want to execute ./hack/ci/run-e2e-kind.sh instead of this target
	# images             - builds docker images for all of the components, saving them in your Docker daemon
	# images_push        - pushes docker images to the target registry
	#
	# Image targets can be run with optional args DOCKER_REPO and DOCKER_TAG:
	#
	#     make images DOCKER_REPO=quay.io/yourusername DOCKER_TAG=experimental-tag
	#

# Alias targets
###############

build: images
verify: verify_lint verify_codegen verify_deps verify_unit verify_docs
push: docker_push

verify_lint:
	bazel test \
		//hack:verify-boilerplate \
		//hack:verify-links \
		//hack:verify-errexit \
		//hack:verify-gofmt

verify_unit:
	bazel test \
		$$(bazel query 'kind("go._*test", "...")' \
			| grep -v //vendor/ \
			| grep -v //test/e2e \
		)

verify_deps:
	bazel test \
		//hack:verify-deps

verify_codegen:
	bazel test \
		//hack:verify-codegen \
		//hack:verify-deploy-gen

verify_docs:
	bazel test \
		//hack:verify-reference-docs

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
		bazel run //vendor/github.com/onsi/ginkgo/ginkgo -- \
			-nodes 20 \
			$$(bazel info bazel-genfiles)/test/e2e/e2e.test \
			-- \
			--helm-binary-path=$$(bazel info bazel-genfiles)/hack/bin/helm \
			--repo-root="$$(pwd)" \
			--report-dir="$${ARTIFACTS:-./_artifacts}" \
			--ginkgo.skip="$(GINKGO_SKIP)" \
			--kubectl-path="$(KUBECTL)"

# Generate targets
##################

generate:
	bazel run //hack:update-bazel
	bazel run //hack:update-gofmt
	bazel run //hack:update-codegen
	bazel run //hack:update-deploy-gen
	bazel run //hack:update-reference-docs
	bazel run //hack:update-deps

# Docker targets
################

BAZEL_IMAGE_ENV := APP_VERSION=$(APP_VERSION) DOCKER_REPO=$(DOCKER_REPO) DOCKER_TAG=$(APP_VERSION)
images:
	$(BAZEL_IMAGE_ENV) \
		bazel run //:images

images_push: images
	# we do not use the :push target as Quay.io does not support v2.2
	# manifests for Docker images, and rules_docker only supports 2.2+
	# https://github.com/moby/buildkit/issues/409#issuecomment-394757219
	# source the bazel workspace environment
	eval $$($(BAZEL_IMAGE_ENV) ./hack/print-workspace-status.sh | tr ' ' '='); \
	docker tag "$${STABLE_DOCKER_REPO}/cert-manager-acmesolver-amd64:$${STABLE_DOCKER_TAG}" "$${STABLE_DOCKER_REPO}/cert-manager-acmesolver:$${STABLE_DOCKER_TAG}"; \
	docker tag "$${STABLE_DOCKER_REPO}/cert-manager-controller-amd64:$${STABLE_DOCKER_TAG}" "$${STABLE_DOCKER_REPO}/cert-manager-controller:$${STABLE_DOCKER_TAG}"; \
	docker tag "$${STABLE_DOCKER_REPO}/cert-manager-injectorcontroller-amd64:$${STABLE_DOCKER_TAG}" "$${STABLE_DOCKER_REPO}/cert-manager-injectorcontroller:$${STABLE_DOCKER_TAG}"; \
	docker tag "$${STABLE_DOCKER_REPO}/cert-manager-webhook-amd64:$${STABLE_DOCKER_TAG}" "$${STABLE_DOCKER_REPO}/cert-manager-webhook:$${STABLE_DOCKER_TAG}"; \
	docker push "$${STABLE_DOCKER_REPO}/cert-manager-acmesolver:$${STABLE_DOCKER_TAG}"; \
	docker push "$${STABLE_DOCKER_REPO}/cert-manager-controller:$${STABLE_DOCKER_TAG}"; \
	docker push "$${STABLE_DOCKER_REPO}/cert-manager-injectorcontroller:$${STABLE_DOCKER_TAG}"; \
	docker push "$${STABLE_DOCKER_REPO}/cert-manager-webhook:$${STABLE_DOCKER_TAG}"; \
	docker push "$${STABLE_DOCKER_REPO}/cert-manager-acmesolver-arm64:$${STABLE_DOCKER_TAG}"; \
	docker push "$${STABLE_DOCKER_REPO}/cert-manager-controller-arm64:$${STABLE_DOCKER_TAG}"; \
	docker push "$${STABLE_DOCKER_REPO}/cert-manager-injectorcontroller-arm64:$${STABLE_DOCKER_TAG}"; \
	docker push "$${STABLE_DOCKER_REPO}/cert-manager-webhook-arm64:$${STABLE_DOCKER_TAG}";
	docker push "$${STABLE_DOCKER_REPO}/cert-manager-acmesolver-arm:$${STABLE_DOCKER_TAG}"; \
	docker push "$${STABLE_DOCKER_REPO}/cert-manager-controller-arm:$${STABLE_DOCKER_TAG}"; \
	docker push "$${STABLE_DOCKER_REPO}/cert-manager-injectorcontroller-arm:$${STABLE_DOCKER_TAG}"; \
	docker push "$${STABLE_DOCKER_REPO}/cert-manager-webhook-arm:$${STABLE_DOCKER_TAG}";
