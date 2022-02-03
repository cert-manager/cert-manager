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

# STANDARD OPTIONS
###############

# Set DOCKER_REGISTRY to customise the image docker repo, e.g. "quay.io/jetstack"
DOCKER_REGISTRY :=
# Set APP_VERSION to customize the image tag, eg "v0.0.5-dev"
APP_VERSION :=
# Set the target platform to build for. Defaults to linux/amd64
PLATFORM := @io_bazel_rules_go//go/toolchain:linux_amd64

# OPTIONS YOU PROBABLY DON'T NEED TO MODIFY UNLESS DOING SOMETHING VERY SPECIFIC.
###############

# Set an alternative base image https://github.com/cert-manager/cert-manager/blob/master/build/BUILD.bazel#L42
BASE_IMAGE := static
BAZEL_IMAGES_FLAGS := --define image_type=$(BASE_IMAGE)
# Ensure non cgo by default
# https://github.com/bazelbuild/rules_go/blob/master/go/modes.rst#building-pure-go-binaries
CGO_ENABLED := 0
ifeq ($(CGO_ENABLED),0)
	BAZEL_IMAGES_FLAGS += --@io_bazel_rules_go//go/config:pure
endif

# Where the hack scripts live
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
	# clean              - removes the entire output base tree, stops the Bazel server and removes test artifacts
	# build              - build a binary of the cert-manager CLI and build docker images for all components
	# controller         - build a binary of the 'controller'
	# cainjector         - build a binary of the 'cainjector'
	# webhook            - build a binary of the 'webhook'
	# acmesolver         - build a binary of the 'acmesolver'
	# ctl                - build a binary of the cert-manager CLI
	# images             - builds docker images for all of the components, saving them in your Docker daemon
	# images_push        - pushes docker images to the target registry
	# crds               - runs the update-crds script to ensure that generated CRDs are up to date
	# cluster            - creates a Kubernetes cluster for testing in CI but doesn't install addons (KIND by default)
	# release_tars       - build the release tar files.
	# update_kind_images - updates the digests of the kind images used for testing + CI across various K8S versions
	#
	# All image targets can be run with optional args DOCKER_REGISTRY, APP_VERSION, PLATFORM:
	#
	# make images DOCKER_REGISTRY=quay.io/yourusername APP_VERSION=v0.11.0-dev.my-feature PLATFORM=@io_bazel_rules_go//go/toolchain:linux_arm64
	#
	# make images_push DOCKER_REGISTRY=quay.io/yourusername APP_VERSION=v0.11.0-dev.my-feature

# Alias targets
###############

.PHONY: clean
clean:
	bazel clean --expunge
	rm -rf \
		$(CURDIR)/_artifacts

.PHONY: build
build: ctl images

.PHONY: verify
verify:
	bazel test //...

# TODO: remove this rule in favour of calling hack/verify-deps directly
.PHONY: verify_deps
verify_deps:
	$(HACK_DIR)/verify-deps.sh
	# verify-deps-licenses.sh is implicitly checked by the verify-deps script

# requires docker
.PHONY: verify_chart
verify_chart:
	bazel build //deploy/charts/cert-manager
	$(HACK_DIR)/verify-chart-version.sh bazel-bin/deploy/charts/cert-manager/cert-manager.tgz

.PHONY: verify_upgrade
verify_upgrade:
	$(HACK_DIR)/verify-upgrade.sh

.PHONY: crds
crds:
	bazel run //hack:update-crds

.PHONY: cluster
cluster:
	# NB: don't use this on a development environment; this is specifically for CI. the docker network that this
	# script creates can wreak havoc on in-cluster DNS by interfering with access to your local network!
	./devel/ci-cluster.sh

.PHONY: update_kind_images
update_kind_images: devel/cluster/kind_cluster_node_versions.sh

# has to be PHONY since it relies on remote data
.PHONY: devel/cluster/kind_cluster_node_versions.sh
devel/cluster/kind_cluster_node_versions.sh:
	./hack/latest-kind-images.sh > $@

# Go targets
############
.PHONY: $(CMDS)
$(CMDS):
	bazel build //cmd/$@

# Generate targets
##################
.PHONY: generate
generate:
	$(HACK_DIR)/update-all.sh

# Docker targets
################
.PHONY: images
images:
	APP_VERSION=$(APP_VERSION) \
	DOCKER_REGISTRY=$(DOCKER_REGISTRY) \
	bazel run \
		--stamp \
		--platforms=$(PLATFORM) \
		$(BAZEL_IMAGES_FLAGS) \
		//build:server-images

.PHONY: images_push
images_push:
	APP_VERSION=$(APP_VERSION) \
	DOCKER_REGISTRY=$(DOCKER_REGISTRY) \
	bazel run \
		--stamp \
		--platforms=$(PLATFORM) \
		$(BAZEL_IMAGES_FLAGS) \
		//:images.push

# Release targets
################

.PHONY: release_tars
release_tars:
	DOCKER_REGISTRY=$(DOCKER_REGISTRY) \
	bazel build \
		--stamp \
		--platforms=$(PLATFORM) \
		//build/release-tars
