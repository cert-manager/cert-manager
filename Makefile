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

# For details on some of these "prelude" settings, see:
# https://clarkgrubb.com/makefile-style-guide
MAKEFLAGS += --warn-undefined-variables --no-builtin-rules
SHELL := /bin/bash
.SHELLFLAGS := -uo pipefail -c
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
.SUFFIXES:

SOURCES := $(shell find . -type f -name "*.go")

GOFLAGS := -ldflags '-w -s' -trimpath

## GOBUILDPROCS is passed to GOMAXPROCS when running go build; if you're running
## make in parallel using "-jN" then you'll probably want to reduce the value
## of GOBUILDPROCS or else you could end up running N parallel invocations of
## go build, each of which will spin up as many threads as are available on your
## system.
GOBUILDPROCS ?=

include make/git.mk
include make/tools.mk
include make/ci.mk
include make/test.mk
include make/base_images.mk
include make/cmctl.mk
include make/server.mk
include make/containers.mk
include make/release.mk
include make/manifests.mk
include make/licenses.mk
include make/e2e-setup.mk
include make/help.mk

.PHONY: clean
## Remove the kind cluster and everything that was built. The downloaded images
## and tools are kept intact to avoid re-downloading everything. To really wipe
## out everything, run the command:
##
##     rm -rf bin
##
## @category Development
clean:
	@$(eval KIND_CLUSTER_NAME ?= kind)
	bin/tools/kind delete cluster --name=$(shell cat bin/scratch/kind-exists 2>/dev/null || echo $(KIND_CLUSTER_NAME)) -q 2>/dev/null || true
	rm -rf $(filter-out bin/downloaded,$(wildcard bin/*))
