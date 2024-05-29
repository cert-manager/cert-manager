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

repo_name := github.com/cert-manager/cert-manager

include make/util.mk

# SOURCES contains all go files except those in $(bin_dir), the old bindir `bin`, or in
# the make dir.
# NB: we skip `bin/` since users might have a `bin` directory left over in repos they were
# using before the bin dir was renamed
SOURCES := $(call get-sources,cat -) go.mod go.sum

# SOURCE_DIRS contains all the directories that contain go files
SOURCE_DIRS := $(call get-sources,cut -d'/' -f2 | sort | uniq | tr '\n' ' ')

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
	-X github.com/cert-manager/cert-manager/pkg/util.AppVersion=$(VERSION) \
    -X github.com/cert-manager/cert-manager/pkg/util.AppGitCommit=$(GITCOMMIT)

golangci_lint_config := .golangci.yaml

repository_base_no_dependabot := 1

GINKGO_VERSION ?= $(shell awk '/ginkgo\/v2/ {print $$2}' test/e2e/go.mod)
