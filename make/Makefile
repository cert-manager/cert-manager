# Copyright 2021 The cert-manager Authors.
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

MAKEFLAGS += --warn-undefined-variables

SHELL := /usr/bin/env bash
.SHELLFLAGS := -uo pipefail -c

# For details on some of these "prelude" settings, see: https://clarkgrubb.com/makefile-style-guide
.DEFAULT_GOAL := help
.DELETE_ON_ERROR:
.SUFFIXES:

SOURCES := $(shell find . -type f -name "*.go")

GOFLAGS := -ldflags '-w -s' -trimpath

# GOBUILDPROCS is passed to GOMAXPROCS when running go build; if you're running make in parallel
# using "-jN" then you'll probably want to reduce the value of GOBUILDPROCS or else you could end
# up running N parallel invocations of go build, each of which will spin up as many threads as are
# available on your system.
GOBUILDPROCS ?=

# Set this as an environment variable to enable signing commands using cmrel
# Format should be:
# projects/<project>/locations/<location>/keyRings/<keyring>/cryptoKeys/<keyname>/cryptoKeyVersions/<keyversion>
CMREL_KEY ?=

HOST_OS = $(shell $(GO) env GOOS)
HOST_ARCH = $(shell $(GO) env GOARCH)

include make/git.mk
include make/tools.mk
include make/ci.mk
include make/test.mk
include make/base_images.mk
include make/cmctl.mk
include make/server.mk
include make/containers.mk
include make/release_containers.mk
include make/manifests.mk
include make/licenses.mk

.PHONY: all
all: binaries helm-chart static-manifests all-containers  ## Build all artifacts which might be run or used locally, except for anything signed.

.PHONY: all-signed
all-signed: all  ## Build `all` followed by signed artifacts which require a key to be configured.
	$(MAKE) -f make/Makefile signed-artifacts

.PHONY: binaries
binaries: server-binaries cmctl kubectl-cert_manager ## Build all binaries for all server and client platforms

.PHONY: signed-artifacts
signed-artifacts: helm-chart-signature  ## Shorthand to create all artifacts which can be signed (and which therefore require signing keys to be configured)

.PHONY: staged-release
staged-release: all-signed release-manifests release-containers ## Creates a full release ready to be staged, including containers bundled for distribution. Requires signing keys to be configured.
	$(MAKE) -f make/Makefile bin/release/metadata.json

# Takes all metadata files in bin/metadata and combines them into one
bin/release/metadata.json: $(wildcard bin/metadata/*.json) | bin/release
	jq -n \
		--arg releaseVersion "$(RELEASE_VERSION)" \
		--arg gitCommitRef "$(GITCOMMIT)" \
		'.releaseVersion = $$releaseVersion | .gitCommitRef = $$gitCommitRef | .artifacts += [inputs]' $^ > $@

.PHONY: clean
clean:  ## Remove the bin directory, cleaning all built artifacts and locally installed tools
	rm -rf bin

bin:
	@mkdir -p $@

bin/scratch:
	@mkdir -p $@

bin/release:
	@mkdir -p $@

bin/metadata:
	@mkdir -p $@

# Set this as an environment variable to enable signing commands using cosign
# Format should be any accepted by cosign; for GCP, use:
# gcpkms://projects/<project>/locations/<location>/keyRings/<keyring>/cryptoKeys/<keyname>/versions/<keyversion>
# CMREL_KEY ?= ""
# Example of how we can generate a SHA256SUMS file and sign it using cosign
#bin/SHA256SUMS: $(wildcard ...)
#	@# The patsubst means "all dependencies, but with "bin/" trimmed off the beginning
#	@# We cd into bin so that SHA256SUMS file doesn't have a prefix of `bin` on everything
#	cd $(dir $@) && sha256sum $(patsubst bin/%,%,$^) > $(notdir $@)
#
#bin/SHA256SUMS.sig: bin/SHA256SUMS | bin/tools/cosign
#	$(COSIGN) sign-blob --key $(COSIGN_KEY) $< > $@

# This target allows us to set all the modified times for all files in bin to the same time, which
# is similar to what bazel does. We might not want this, and it's not currently used.
.PHONY: forcetime
forcetime: | bin
	find bin | xargs touch -d "2000-01-01 00:00:00" -

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)
