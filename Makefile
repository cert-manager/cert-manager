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
CMDS := $(shell find ./cmd/ -maxdepth 1 -mindepth 1 -type d -exec basename {} \;)

.PHONY: help
help:
	# This Makefile provides common wrappers around Bazel invocations.
	#
	### Verify targets
	#
	# verify             - runs all test targets (bazel test //...)
	# verify_deps        - ensure go module files are up to date (hack/update-deps.sh)
	# verify_chart       - runs Helm chart linter
	# verify_upgrade     - verifies upgrade from latest published release to current master with both Helm charts and static manifests
	#
	### Generate targets
	#
	# generate           - regenerate all generated files
	#
	### Build targets
	#
	# clean              - removes the entire output base tree and stop the Bazel server
	# controller         - build a binary of the 'controller'
	# cainjector         - build a binary of the 'cainjector'
	# webhook            - build a binary of the 'webhook'
	# acmesolver         - build a binary of the 'acmesolver'
	# ctl                - build a binary of the cert-manager kubectl plugin
	# images             - builds docker images for all of the components, saving them in your Docker daemon
	# images_push        - pushes docker images to the target registry
	# crds               - runs the update-crds script to ensure that generated CRDs are up to date
	# cluster            - creates a Kubernetes cluster for testing in CI (KIND by default)
	#
	# Image targets can be run with optional args DOCKER_REGISTRY and APP_VERSION:
	#
	# make images DOCKER_REGISTRY=quay.io/yourusername APP_VERSION=v0.11.0-dev.my-feature
	#
	# Images can be pushed with optional args DOCKER_REGISTRY and APP_VERSION:
	#
	# make images_push DOCKER_REGISTRY=quay.io/yourusername APP_VERSION=v0.11.0-dev.my-feature

# Alias targets
###############

.PHONY: clean
clean:
	bazel clean --expunge

.PHONY: build
build: ctl images

.PHONY: verify
verify:
	bazel test //...

# TODO: remove this rule in favour of calling hack/verify-deps directly
.PHONY: verify_deps
verify_deps:
	./hack/verify-deps.sh
	# verify-deps-licenses.sh is implicitly checked by the verify-deps script

# requires docker
.PHONY: verify_chart
verify_chart:
	$(HACK_DIR)/verify-chart-version.sh

.PHONY: verify_upgrade
verify_upgrade:
	$(HACK_DIR)/verify-upgrade.sh

.PHONY: crds
crds:
	bazel run //hack:update-crds

.PHONY: cluster
cluster:
	./devel/ci-cluster.sh

# Go targets
############
.PHONY: $(CMDS)
$(CMDS):
	bazel build //cmd/$@

# Generate targets
##################
.PHONY: generate
generate:
	./hack/update-all.sh

# Docker targets
################
.PHONY: images
images:
	APP_VERSION=$(APP_VERSION) \
	DOCKER_REGISTRY=$(DOCKER_REGISTRY) \
	bazel run \
		--stamp \
		--platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 \
		--@io_bazel_rules_go//go/config:pure \
		//build:server-images

.PHONY: images_push
images_push:
	APP_VERSION=$(APP_VERSION) \
	DOCKER_REGISTRY=$(DOCKER_REGISTRY) \
	bazel run \
		--stamp \
		--platforms=@io_bazel_rules_go//go/toolchain:linux_amd64 \
		--@io_bazel_rules_go//go/config:pure \
		//:images.push
