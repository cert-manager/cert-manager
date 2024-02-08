# Copyright 2023 The cert-manager Authors.
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

# For details on some of these "prelude" settings, see:
# https://clarkgrubb.com/makefile-style-guide

MAKEFLAGS += --warn-undefined-variables --no-builtin-rules
SHELL := /usr/bin/env bash
.SHELLFLAGS := -uo pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
.SUFFIXES:

bin_dir := _bin

include make/util.mk

# SOURCES contains all go files except those in $(bin_dir), the old bindir `bin`, or in
# the make dir.
# NB: we skip `bin/` since users might have a `bin` directory left over in repos they were
# using before the bin dir was renamed
SOURCES := $(call get-sources,cat -) go.mod go.sum

## GOBUILDPROCS is passed to GOMAXPROCS when running go build; if you're running
## make in parallel using "-jN" then you'll probably want to reduce the value
## of GOBUILDPROCS or else you could end up running N parallel invocations of
## go build, each of which will spin up as many threads as are available on your
## system.
## @category Build
GOBUILDPROCS ?=

include make/git.mk

## By default, we don't link Go binaries to the libc. In some case, you might
## want to build libc-linked binaries, in which case you can set this to "1".
## @category Build
CGO_ENABLED ?= 0

## This flag is passed to `go build` to enable Go experiments. It's empty by default
## @category Build
GOEXPERIMENT ?=  # empty by default

## Extra flags passed to 'go' when building. For example, use GOFLAGS=-v to turn on the
## verbose output.
## @category Build
GOFLAGS := -trimpath

## Extra linking flags passed to 'go' via '-ldflags' when building.
## @category Build
GOLDFLAGS := -w -s \
	-X github.com/cert-manager/cert-manager/pkg/util.AppVersion=$(RELEASE_VERSION) \
    -X github.com/cert-manager/cert-manager/pkg/util.AppGitCommit=$(GITCOMMIT)

include make/tools.mk
include make/ci.mk
include make/test.mk
include make/base_images.mk
include make/server.mk
include make/containers.mk
include make/release.mk
include make/manifests.mk
include make/licenses.mk
include make/e2e-setup.mk
include make/scan.mk
include make/ko.mk
include make/help.mk

.PHONY: clean
## Remove the kind cluster and everything that was built. The downloaded images
## and tools are kept intact to avoid re-downloading everything. To really wipe
## out everything, use `make clean-all` instead.
##
## @category Development
clean: | $(NEEDS_KIND)
	@$(eval KIND_CLUSTER_NAME ?= kind)
	$(KIND) delete cluster --name=$(shell cat $(bin_dir)/scratch/kind-exists 2>/dev/null || echo $(KIND_CLUSTER_NAME)) -q 2>/dev/null || true
	rm -rf $(filter-out $(bin_dir)/downloaded,$(wildcard $(bin_dir)/*))
	rm -rf bazel-bin bazel-cert-manager bazel-out bazel-testlogs

.PHONY: clean-all
clean-all: clean
	rm -rf $(bin_dir)/

# FORCE is a helper target to force a file to be rebuilt whenever its
# target is invoked.
FORCE:
