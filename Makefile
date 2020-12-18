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

# Set DOCKER_REGISTRY to customise the image docker repo, e.g. "quay.io/jetstack"
DOCKER_REGISTRY :=
APP_VERSION :=
HACK_DIR ?= hack

# Get a list of all binaries to be built
CMDS := $(shell find ./cmd/ -maxdepth 1 -type d -exec basename {} \; | grep -v cmd)

.PHONY: help build verify push $(CMDS) images images_push \
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
	# images             - builds docker images for all of the components, saving them in your Docker daemon
	# images_push        - pushes docker images to the target registry
	#
	# Image targets can be run with optional args DOCKER_REGISTRY and APP_VERSION:
	#
	#     make images DOCKER_REGISTRY=quay.io/yourusername APP_VERSION=v0.11.0-dev.my-feature
	#

# Alias targets
###############

build: ctl images
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

# Generate targets
##################
generate:
	./hack/update-all.sh

# Docker targets
################
images:
	APP_VERSION=$(APP_VERSION) \
	DOCKER_REGISTRY=$(DOCKER_REPO) \
	bazel run \
		--stamp \
		--platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 \
		//build:server-images

ctl:
	bazel build //cmd/ctl
