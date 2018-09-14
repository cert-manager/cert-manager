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

# Set DOCKER_REPO to customise the image docker repo, e.g. "quay.io/jetstack"
DOCKER_REPO :=
APP_VERSION := canary
HACK_DIR ?= hack

## e2e test vars
# Domain name to use in e2e tests. This is important for ACME HTTP01 e2e tests,
# which require a domain that resolves to the ingress controller to be used for
# e2e tests.
E2E_NGINX_CERTIFICATE_DOMAIN=
KUBECONFIG ?= $$HOME/.kube/config
PEBBLE_IMAGE_REPO=quay.io/munnerz/pebble

# Get a list of all binaries to be built
CMDS := $(shell find ./cmd/ -maxdepth 1 -type d -exec basename {} \; | grep -v cmd)

.PHONY: help build verify push $(CMDS) e2e_test images images_push \
	verify_lint verify_unit verify_deps verify_codegen verify_docs verify_chart \

help:
	# This Makefile provides common wrappers around Bazel invocations.
	#
	### Verify targets
	#
	# verify_lint       - run 'lint' targets
	# verify_unit       - run unit tests
	# verify_deps       - verifiy vendor/ and Gopkg.lock is up to date
	# verify_codegen    - verify generated code, including 'static deploy manifests', is up to date
	# verify_docs       - verify the generated reference docs for API types is up to date
	# verify_chart      - runs Helm chart linter (e.g. ensuring version has been bumped etc)
	#
	### Generate targets
	#
	# generate          - regenerate all generated files
	#
	### Build targets
	#
	# controller        - build a binary of the 'controller'
	# webhook           - build a binary of the 'webhook'
	# acmesolver        - build a binary of the 'acmesolver'
	# e2e_test          - builds and runs end-to-end tests.
	#                     NOTE: you probably want to execute ./hack/ci/run-e2e-kind.sh instead of this target
	# images            - builds docker images for all of the components, saving them in your Docker daemon
	# images_push       - pushes docker images to the target registry
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
	bazel build //test/e2e
	# Run e2e tests
	KUBECONFIG=$(KUBECONFIG) CERTMANAGERCONFIG=$(KUBECONFIG) \
		bazel-genfiles/test/e2e/e2e \
			-acme-nginx-certificate-domain=$(E2E_NGINX_CERTIFICATE_DOMAIN) \
			-cloudflare-email=$${CLOUDFLARE_E2E_EMAIL} \
			-cloudflare-api-key=$${CLOUDFLARE_E2E_API_TOKEN} \
			-acme-cloudflare-domain=$${CLOUDFLARE_E2E_DOMAIN} \
			-pebble-image-repo=$(PEBBLE_IMAGE_REPO) \
			-report-dir="$${ARTIFACTS:-./_artifacts}"

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

images_push:
	$(BAZEL_IMAGE_ENV) \
		bazel run //:images.push
