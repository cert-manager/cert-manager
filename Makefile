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

PACKAGE_NAME := github.com/jetstack/cert-manager
REGISTRY := quay.io/jetstack
APP_NAME := cert-manager
IMAGE_TAGS := canary
BUILD_TAG := build
HACK_DIR ?= hack

# Domain name to use in e2e tests. This is important for ACME HTTP01 e2e tests,
# which require a domain that resolves to the ingress controller to be used for
# e2e tests.
E2E_NGINX_CERTIFICATE_DOMAIN=

PEBBLE_IMAGE_REPO=quay.io/munnerz/pebble

# AppVersion is set as the AppVersion to be compiled into the controller binary.
# It's used as the default version of the 'acmesolver' image to use for ACME
# challenge requests, and any other future provider that requires additional
# image dependencies will use this same tag.
ifeq ($(APP_VERSION),)
APP_VERSION := canary
endif

# Go build flags
GIT_COMMIT := $(shell git rev-parse HEAD)
GOLDFLAGS := -ldflags "-X $(PACKAGE_NAME)/pkg/util.AppGitState=${GIT_STATE} -X $(PACKAGE_NAME)/pkg/util.AppGitCommit=${GIT_COMMIT} -X $(PACKAGE_NAME)/pkg/util.AppVersion=${APP_VERSION}"

.PHONY: verify build docker_build push generate generate_verify deploy_verify \
	$(CMDS) go_test go_fmt e2e_test go_verify hack_verify hack_verify_pr \
	$(DOCKER_BUILD_TARGETS) $(DOCKER_PUSH_TARGETS)

# Alias targets
###############

build: docker_build
verify: hack_verify go_verify
push: build docker_push

# Code generation
#################
# This target runs all required generators against our API types.
generate:
	$(HACK_DIR)/update-codegen.sh

# Hack targets
##############
hack_verify:
	$(HACK_DIR)/verify-all.sh

verify_pr:
	$(HACK_DIR)/verify-chart-version.sh

# Go targets
#################
go_verify: go_test

# Get a list of all binaries to be built
CMDS := $(shell find ./cmd/ -maxdepth 1 -type d -exec basename {} \; | grep -v cmd)
$(CMDS):
	# TODO: handle ldflags
	bazel build //cmd/$@:$@

go_test:
	bazel test //...

go_fmt:
	@set -e; \
	GO_FMT=$$(git ls-files *.go | grep -v 'vendor/' | xargs gofmt -d); \
	if [ -n "$${GO_FMT}" ] ; then \
		echo "Please run go fmt"; \
		echo "$$GO_FMT"; \
		exit 1; \
	fi

e2e_test:
	# Build the e2e tests
	bazel build //test/e2e:go_default_test

	mkdir -p "$$(pwd)/_artifacts"

	# Run e2e tests
	# TODO: make these paths configurable
	KUBECONFIG=$$HOME/.kube/config CERTMANAGERCONFIG=$$HOME/.kube/config \
		$(BAZEL_OUT)/test/e2e/go_default_test
			-acme-nginx-certificate-domain=$(E2E_NGINX_CERTIFICATE_DOMAIN) \
			-cloudflare-email=$${CLOUDFLARE_E2E_EMAIL} \
			-cloudflare-api-key=$${CLOUDFLARE_E2E_API_TOKEN} \
			-acme-cloudflare-domain=$${CLOUDFLARE_E2E_DOMAIN} \
			-pebble-image-repo=$(PEBBLE_IMAGE_REPO) \
			-report-dir=./_artifacts

# Docker targets
################
docker_build:
	bazel run //:images

# docker_build_controller, docker_build_apiserver etc
DOCKER_BUILD_TARGETS := $(addprefix docker_build_, $(CMDS))
$(DOCKER_BUILD_TARGETS):
	$(eval DOCKER_BUILD_CMD := $(subst docker_build_,,$@))
	# TODO: set proper tag
	bazel build //cmd/$(DOCKER_BUILD_CMD):image

# docker_push_controller, docker_push_apiserver etc
DOCKER_PUSH_TARGETS := $(addprefix docker_push_, $(CMDS))
docker_push: $(DOCKER_PUSH_TARGETS)
$(DOCKER_PUSH_TARGETS):
	$(eval DOCKER_PUSH_CMD := $(subst docker_push_,,$@))
	bazel run //:$(DOCKER_PUSH_CMD)
