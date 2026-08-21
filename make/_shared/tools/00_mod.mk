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

ifndef bin_dir
$(error bin_dir is not set)
endif

##########################################

default_shared_dir := $(CURDIR)/$(bin_dir)
# If $(HOME) is set and $(CI) is not, use the $(HOME)/.cache
# folder to store downloaded binaries.
ifneq ($(shell printenv HOME),)
ifeq ($(shell printenv CI),)
default_shared_dir := $(HOME)/.cache/makefile-modules
endif
endif

export DOWNLOAD_DIR ?= $(default_shared_dir)/downloaded
export GOVENDOR_DIR ?= $(default_shared_dir)/go_vendor

# https://go.dev/dl/
# renovate: datasource=golang-version packageName=go
VENDORED_GO_VERSION := 1.27.0

$(bin_dir)/tools $(DOWNLOAD_DIR)/tools:
	@mkdir -p $@

checkhash_script := $(dir $(lastword $(MAKEFILE_LIST)))/util/checkhash.sh
lock_script := $(dir $(lastword $(MAKEFILE_LIST)))/util/lock.sh

# GNU make executes recipe lines containing "$(MAKE)" even under -n/-q/-t
# (they are treated as recursive make invocations). The verify-at-link recipes
# below are such lines, so they guard on this variable to avoid hashing cached
# binaries, or deleting mismatched ones, during a dry run. The single-letter
# flags are the first word of MAKEFLAGS once long options (e.g.
# --warn-undefined-variables, which contains an "n") are filtered out.
dry_run := $(strip $(foreach flag,n q t,$(findstring $(flag),$(firstword -$(filter-out --%,$(MAKEFLAGS))))))

# $outfile is a variable in the lock script
# Escape the dollar sign so it's passed literally to the shell script, not expanded by make
outfile := $$outfile

# Helper function to iterate over key=value pairs and call a function for each pair
# Usage: $(call for_each_kv,function_name,list_of_key=value_pairs)
# For each item, splits on "=" and calls function_name with key as $1 and value as $2
for_each_kv = $(foreach item,$2,$(eval $(call $1,$(word 1,$(subst =, ,$(item))),$(word 2,$(subst =, ,$(item))))))

# To make sure we use the right version of each tool, we put symlink in
# $(bin_dir)/tools, and the actual binaries are in $(bin_dir)/downloaded. When bumping
# the version of the tools, this symlink gets updated.

# Let's have $(bin_dir)/tools in front of the PATH so that we don't inadvertently
# pick up the wrong binary somewhere. Watch out, $(shell echo $$PATH) will
# still print the original PATH, since GNU make does not honor exported
# variables: https://stackoverflow.com/questions/54726457
export PATH := $(CURDIR)/$(bin_dir)/tools:$(PATH)

CTR ?= docker
.PHONY: __require-ctr
ifneq ($(shell command -v $(CTR) >/dev/null || echo notfound),)
__require-ctr:
	@:$(error "$(CTR) (or set CTR to a docker-compatible tool)")
endif
NEEDS_CTR = __require-ctr

tools :=
# https://github.com/helm/helm/releases
# renovate: datasource=github-releases packageName=helm/helm
tools += helm=v4.2.4
# https://github.com/helm-unittest/helm-unittest/releases
# renovate: datasource=github-releases packageName=helm-unittest/helm-unittest
tools += helm-unittest=v1.1.2
# https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl
# renovate: datasource=github-releases packageName=kubernetes/kubernetes
tools += kubectl=v1.36.3
# https://github.com/kubernetes-sigs/kind/releases
# renovate: datasource=github-releases packageName=kubernetes-sigs/kind
tools += kind=v0.32.0
# https://www.vaultproject.io/downloads
# renovate: datasource=github-releases packageName=hashicorp/vault
tools += vault=v2.0.4
# https://github.com/Azure/azure-workload-identity/releases
# renovate: datasource=github-releases packageName=Azure/azure-workload-identity
tools += azwi=v1.6.1
# https://github.com/kyverno/kyverno/releases
# renovate: datasource=github-releases packageName=kyverno/kyverno
tools += kyverno=v1.19.0
# https://github.com/mikefarah/yq/releases
# renovate: datasource=github-releases packageName=mikefarah/yq
tools += yq=v4.53.6
# https://github.com/ko-build/ko/releases
# renovate: datasource=github-releases packageName=ko-build/ko
tools += ko=0.19.1
# https://github.com/protocolbuffers/protobuf/releases
# renovate: datasource=github-releases packageName=protocolbuffers/protobuf
tools += protoc=v35.1
# https://github.com/aquasecurity/trivy/releases
# renovate: datasource=github-releases packageName=aquasecurity/trivy
tools += trivy=v0.74.0
# https://github.com/vmware-tanzu/carvel-ytt/releases
# renovate: datasource=github-releases packageName=vmware-tanzu/carvel-ytt
tools += ytt=v0.55.2
# https://github.com/rclone/rclone/releases
# renovate: datasource=github-releases packageName=rclone/rclone
tools += rclone=v1.75.0
# https://github.com/istio/istio/releases
# renovate: datasource=github-releases packageName=istio/istio
tools += istioctl=1.30.3

### go packages
# https://pkg.go.dev/sigs.k8s.io/controller-tools/cmd/controller-gen?tab=versions
# renovate: datasource=go packageName=sigs.k8s.io/controller-tools
tools += controller-gen=v0.21.0
# https://pkg.go.dev/golang.org/x/tools/cmd/goimports?tab=versions
# renovate: datasource=go packageName=golang.org/x/tools
tools += goimports=v0.49.0
# https://pkg.go.dev/github.com/google/go-licenses/v2?tab=versions
# renovate: datasource=go packageName=github.com/inteon/go-licenses/v2
tools += go-licenses=v2.0.0-20250821024731-e4be79958780
# https://pkg.go.dev/gotest.tools/gotestsum?tab=versions
# renovate: datasource=github-releases packageName=gotestyourself/gotestsum
tools += gotestsum=v1.13.0
# https://pkg.go.dev/sigs.k8s.io/kustomize/kustomize/v5?tab=versions
# renovate: datasource=go packageName=sigs.k8s.io/kustomize/kustomize/v5
tools += kustomize=v5.8.1
# https://pkg.go.dev/github.com/itchyny/gojq?tab=versions
# renovate: datasource=go packageName=github.com/itchyny/gojq
tools += gojq=v0.12.19
# https://pkg.go.dev/github.com/google/go-containerregistry/pkg/crane?tab=versions
# renovate: datasource=go packageName=github.com/google/go-containerregistry
tools += crane=v0.21.9
# https://pkg.go.dev/google.golang.org/protobuf/cmd/protoc-gen-go?tab=versions
# renovate: datasource=go packageName=google.golang.org/protobuf
tools += protoc-gen-go=v1.36.12
# https://pkg.go.dev/github.com/sigstore/cosign/v2/cmd/cosign?tab=versions
# renovate: datasource=go packageName=github.com/sigstore/cosign/v2
tools += cosign=v2.6.5
# https://pkg.go.dev/github.com/cert-manager/boilersuite?tab=versions
# renovate: datasource=go packageName=github.com/cert-manager/boilersuite
tools += boilersuite=v0.2.0
# https://pkg.go.dev/github.com/princjef/gomarkdoc/cmd/gomarkdoc?tab=versions
# renovate: datasource=go packageName=github.com/princjef/gomarkdoc
tools += gomarkdoc=v1.1.0
# https://pkg.go.dev/oras.land/oras/cmd/oras?tab=versions
# renovate: datasource=go packageName=oras.land/oras
tools += oras=v1.3.3
# https://pkg.go.dev/github.com/onsi/ginkgo/v2/ginkgo?tab=versions
# The gingko version should be kept in sync with the version used in code.
# If there is no go.mod file (which is only the case for the makefile-modules
# repo), then we default to a version that we know exists. We have to do this
# because otherwise the awk failure renders the whole makefile unusable.
detected_ginkgo_version := $(shell [[ -f go.mod ]] && awk '/ginkgo\/v2/ {print $$2}' go.mod || echo "v2.23.4")
tools += ginkgo=$(detected_ginkgo_version)
# https://pkg.go.dev/github.com/cert-manager/klone?tab=versions
# renovate: datasource=go packageName=github.com/cert-manager/klone
tools += klone=v0.3.0
# https://pkg.go.dev/github.com/goreleaser/goreleaser/v2?tab=versions
# renovate: datasource=go packageName=github.com/goreleaser/goreleaser/v2
tools += goreleaser=v2.17.1
# https://pkg.go.dev/github.com/anchore/syft/cmd/syft?tab=versions
# renovate: datasource=go packageName=github.com/anchore/syft
tools += syft=v1.51.0
# https://github.com/cert-manager/helm-tool/releases
# renovate: datasource=github-releases packageName=cert-manager/helm-tool
tools += helm-tool=v0.6.0
# https://github.com/cert-manager/image-tool/releases
# renovate: datasource=github-releases packageName=cert-manager/image-tool
tools += image-tool=v0.2.0
# https://github.com/cert-manager/cmctl/releases
# renovate: datasource=github-releases packageName=cert-manager/cmctl
tools += cmctl=v2.5.0
# https://pkg.go.dev/github.com/cert-manager/release/cmd/cmrel?tab=versions
# renovate: datasource=go packageName=github.com/cert-manager/release
tools += cmrel=v1.12.15-0.20241121151736-e3cbe5171488
# https://pkg.go.dev/github.com/golangci/golangci-lint/v2/cmd/golangci-lint?tab=versions
# renovate: datasource=go packageName=github.com/golangci/golangci-lint/v2
tools += golangci-lint=v2.13.0
# https://pkg.go.dev/golang.org/x/vuln?tab=versions
# renovate: datasource=go packageName=golang.org/x/vuln
tools += govulncheck=v1.7.0
# https://github.com/operator-framework/operator-sdk/releases
# renovate: datasource=github-releases packageName=operator-framework/operator-sdk
tools += operator-sdk=v1.42.3
# https://pkg.go.dev/github.com/cli/cli/v2?tab=versions
# renovate: datasource=go packageName=github.com/cli/cli/v2
tools += gh=v2.97.0
# https://github.com/redhat-openshift-ecosystem/openshift-preflight/releases
# renovate: datasource=github-releases packageName=redhat-openshift-ecosystem/openshift-preflight
tools += preflight=1.20.0
# https://github.com/daixiang0/gci/releases
# renovate: datasource=github-releases packageName=daixiang0/gci
tools += gci=v0.14.0
# https://github.com/google/yamlfmt/releases
# renovate: datasource=github-releases packageName=google/yamlfmt
tools += yamlfmt=v0.21.0
# https://github.com/yannh/kubeconform/releases
# renovate: datasource=github-releases packageName=yannh/kubeconform
tools += kubeconform=v0.8.0
# https://github.com/suzuki-shunsuke/pinact/releases
# renovate: datasource=github-releases packageName=suzuki-shunsuke/pinact
tools += pinact=v4.1.1

# FIXME(erikgb): cert-manager needs the ability to override the version set here
# https://pkg.go.dev/k8s.io/code-generator/cmd?tab=versions
# renovate: datasource=go packageName=k8s.io/code-generator
K8S_CODEGEN_VERSION ?= v0.36.3
tools += client-gen=$(K8S_CODEGEN_VERSION)
tools += deepcopy-gen=$(K8S_CODEGEN_VERSION)
tools += informer-gen=$(K8S_CODEGEN_VERSION)
tools += lister-gen=$(K8S_CODEGEN_VERSION)
tools += applyconfiguration-gen=$(K8S_CODEGEN_VERSION)
tools += defaulter-gen=$(K8S_CODEGEN_VERSION)
tools += conversion-gen=$(K8S_CODEGEN_VERSION)
# https://github.com/kubernetes/kube-openapi
# renovate: datasource=go packageName=k8s.io/kube-openapi
tools += openapi-gen=v0.0.0-20260721132016-d427ff9ee9ad

# https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/master/envtest-releases.yaml
# FIXME: Find a way to configure Renovate to suggest upgrades
KUBEBUILDER_ASSETS_VERSION := v1.36.2
tools += etcd=$(KUBEBUILDER_ASSETS_VERSION)
tools += kube-apiserver=$(KUBEBUILDER_ASSETS_VERSION)

# Additional tools can be defined to reuse the tooling in this file
ADDITIONAL_TOOLS ?=
tools += $(ADDITIONAL_TOOLS)

# Print the go version which can be used in GH actions
.PHONY: print-go-version
print-go-version:
	@echo result=$(VENDORED_GO_VERSION)

# When switching branches which use different versions of the tools, we
# need a way to re-trigger the symlinking from $(bin_dir)/downloaded to $(bin_dir)/tools.
# This pattern rule creates a version stamp file that tracks the tool version.
# If the version changes (or file doesn't exist), update the stamp file to trigger rebuild.
$(bin_dir)/scratch/%_VERSION: FORCE | $(bin_dir)/scratch
	@test "$($*_VERSION)" == "$(shell cat $@ 2>/dev/null)" || echo $($*_VERSION) > $@

# --silent = don't print output like progress meters
# --show-error = but do print errors when they happen
# --fail = exit with a nonzero error code without the response from the server when there's an HTTP error
# --location = follow redirects from the server
# --retry = the number of times to retry a failed attempt to connect
# --retry-connrefused = retry even if the initial connection was refused
CURL := curl --silent --show-error --fail --location --retry 10 --retry-connrefused

# LN is expected to be an atomic action, meaning that two Make processes
# can run the "link $(XXX_DOWNLOAD_PATH) to $(bin_dir)/tools/xxx" operation
# simultaneously without issues (both will perform the action and the second
# time the link will be overwritten).
#
# -s = Create a symbolic link
# -f = Force the creation of the link (replace existing links)
# -n = If destination already exists, replace it, don't use it as a directory to create a new link inside
LN := ln -fsn

# Mapping of lowercase to uppercase letters for the uc (uppercase) function
upper_map := a:A b:B c:C d:D e:E f:F g:G h:H i:I j:J k:K l:L m:M n:N o:O p:P q:Q r:R s:S t:T u:U v:V w:W x:X y:Y z:Z
# Function to convert a string to uppercase (e.g., "helm" -> "HELM")
# Works by iterating through upper_map and substituting each lowercase letter with uppercase
# Used to create variable names like HELM_VERSION from tool names like "helm"
uc = $(strip \
		$(eval __upper := $1) \
		$(foreach p,$(upper_map), \
			$(eval __upper := $(subst $(word 1,$(subst :, ,$p)),$(word 2,$(subst :, ,$p)),$(__upper))) \
		) \
	)$(__upper)

tool_names :=

# for each item `xxx` in the tools variable:
# - a $(XXX_VERSION) variable is generated
#     -> this variable contains the version of the tool
# - a $(NEEDS_XXX) variable is generated
#     -> this variable contains the target name for the tool,
#        which is the relative path of the binary, this target
#        should be used when adding the tool as a dependency to
#        your target, you can't use $(XXX) as a dependency because
#        make does not support an absolute path as a dependency
# - a $(XXX) variable is generated
#     -> this variable contains the absolute path of the binary,
#        the absolute path should be used when executing the binary
#        in targets or in scripts, because it is agnostic to the
#        working directory
# - a $(XXX_DOWNLOAD_PATH) variable is generated
#     -> this variable contains the path of the versioned binary in
#        $(DOWNLOAD_DIR), which the unversioned target links to. Tools
#        that are built from source override it in the go_dependency
#        template below
# - an unversioned target $(bin_dir)/tools/xxx is generated that
#   creates a link to the corresponding versioned target:
#   $(XXX_DOWNLOAD_PATH)
define tool_defs
tool_names += $1

$(call uc,$1)_VERSION ?= $2
NEEDS_$(call uc,$1) := $$(bin_dir)/tools/$1
$(call uc,$1) := $$(CURDIR)/$$(bin_dir)/tools/$1
$(call uc,$1)_DOWNLOAD_PATH := $$(DOWNLOAD_DIR)/tools/$1@$$($(call uc,$1)_VERSION)_$$(HOST_OS)_$$(HOST_ARCH)
endef

# For each tool in the tools list (e.g., "helm=v4.0.1"), split on "=" and call tool_defs
# with the tool name as first arg and version as second arg
$(foreach tool,$(tools),$(eval $(call tool_defs,$(word 1,$(subst =, ,$(tool))),$(word 2,$(subst =, ,$(tool))))))

######
# Go #
######

# $(NEEDS_GO) is a target that is set as an order-only prerequisite in
# any target that calls $(GO), e.g.:
#
#     $(bin_dir)/tools/crane: $(NEEDS_GO)
#         $(GO) build -o $(bin_dir)/tools/crane
#
# $(NEEDS_GO) is empty most of the time, except when running "make vendor-go"
# or when "make vendor-go" was previously run, in which case $(NEEDS_GO) is set
# to $(bin_dir)/tools/go, since $(bin_dir)/tools/go is a prerequisite of
# any target depending on Go when "make vendor-go" was run.

# Auto-detect if Go vendoring should be enabled:
# - Set if "vendor-go" is in the make command goals, OR
# - Set if $(bin_dir)/tools/go already exists (vendoring was previously run)
detected_vendoring := $(findstring vendor-go,$(MAKECMDGOALS))$(shell [ -f $(bin_dir)/tools/go ] && echo yes)
export VENDOR_GO ?= $(detected_vendoring)

ifeq ($(VENDOR_GO),)
.PHONY: __require-go
ifneq ($(shell command -v go >/dev/null || echo notfound),)
__require-go:
	@:$(error "$(GO) (or run 'make vendor-go')")
endif
GO := go
NEEDS_GO = __require-go
# The version of the Go toolchain that builds the go_dependencies tools, e.g.
# "go1.27.0". When vendoring is disabled this is the system Go, which may
# differ from VENDORED_GO_VERSION.
# GOTOOLCHAIN=local: never trigger a toolchain download while parsing this
# file, and match the go$(VENDORED_GO_VERSION) form used when Go is vendored.
# The awk pass keeps the value safe to embed in a target name: a devel
# toolchain reports a multi-word GOVERSION, which would word-split the
# generated rules.
GO_TOOLCHAIN_VERSION := $(shell GOTOOLCHAIN=local go env GOVERSION 2>/dev/null | awk '{gsub(/[^A-Za-z0-9._-]/,"-"); print}')
ifeq ($(GO_TOOLCHAIN_VERSION),)
# Non-fatal so that targets which need no Go, e.g. "make help", still work
# with no Go installed. Nothing can be built in that state anyway.
GO_TOOLCHAIN_VERSION := unknown
endif
else
export GOROOT := $(CURDIR)/$(bin_dir)/tools/goroot
export PATH := $(CURDIR)/$(bin_dir)/tools/goroot/bin:$(PATH)
GO := $(CURDIR)/$(bin_dir)/tools/go
NEEDS_GO := $(bin_dir)/tools/go
MAKE := $(MAKE) vendor-go
GO_TOOLCHAIN_VERSION := go$(VENDORED_GO_VERSION)
endif

.PHONY: vendor-go
## By default, this Makefile uses the system's Go. You can use a "vendored"
## version of Go that will get downloaded by running this command once. To
## disable vendoring, run "make unvendor-go". When vendoring is enabled,
## you will want to set the following:
##
##     export PATH="$PWD/$(bin_dir)/tools:$PATH"
##     export GOROOT="$PWD/$(bin_dir)/tools/goroot"
## @category [shared] Tools
vendor-go: $(bin_dir)/tools/go

.PHONY: unvendor-go
unvendor-go: $(bin_dir)/tools/go
	rm -rf $(bin_dir)/tools/go $(bin_dir)/tools/goroot

.PHONY: which-go
## Print the version and path of go which will be used for building and
## testing in Makefile commands. Vendored go will have a path in ./bin
## @category [shared] Tools
which-go: | $(NEEDS_GO)
	@$(GO) version
	@echo "go binary used for above version information: $(GO)"

$(bin_dir)/tools/go: $(bin_dir)/scratch/VENDORED_GO_VERSION | $(bin_dir)/tools/goroot $(bin_dir)/tools
	@# Create symlink to the go binary inside the goroot
	@cd $(dir $@) && $(LN) ./goroot/bin/go $(notdir $@)
	@touch $@ # making sure the target of the symlink is newer than *_VERSION

# The "_" in "_bin" prevents "go mod tidy" from trying to tidy the vendored goroot.
$(bin_dir)/tools/goroot: $(bin_dir)/scratch/VENDORED_GO_VERSION | $(GOVENDOR_DIR)/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH)/goroot $(bin_dir)/tools
	@# Create relative symlink from $(bin_dir)/tools/goroot to $(GOVENDOR_DIR)/...
	@# patsubst converts the absolute path to relative (e.g., ../../go_vendor/go@1.25.4_darwin_arm64/goroot)
	@cd $(dir $@) && $(LN) $(patsubst $(bin_dir)/%,../%,$(word 1,$|)) $(notdir $@)
	@touch $@ # making sure the target of the symlink is newer than *_VERSION

# Extract the tar to the $(GOVENDOR_DIR) directory, this directory is not cached across CI runs.
$(GOVENDOR_DIR)/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH)/goroot: | $(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz
	@# The tarball lives in the persisted download cache but this directory does
	@# not, so extraction happens long after the download-time hash check:
	@# re-verify the cached tarball first, healing a mismatch like tool_link_defs
	@# does for tool binaries. A poisoned Go toolchain would otherwise undermine
	@# the go.sum/GOSUMDB verification that the go-installed tools rely on.
	@# firstword strips the "vendor-go" goal appended to MAKE when vendoring.
	@if [ -z "$(dry_run)" ] && [ -z "$${LEARN_FILE:-}" ] && ! $(checkhash_script) $| $(go_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM) >/dev/null 2>&1; then \
		echo "[verify] cache integrity check failed for the vendored Go tarball, re-downloading" >&2; \
		rm -f $|; \
		$(firstword $(MAKE)) --no-print-directory $| || exit 1; \
		$(checkhash_script) $| $(go_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
	fi
	@# 1. Use lock script to prevent concurrent extraction
	@# 2. Extract tar.gz to temp directory (creates "go" folder inside)
	@# 3. Rename the extracted "go" directory to final location
	@source $(lock_script) $@; \
		mkdir -p $(outfile).dir; \
		tar xzf $| -C $(outfile).dir; \
		mv $(outfile).dir/go $(outfile); \
		rm -rf $(outfile).dir

###################
# go dependencies #
###################

go_dependencies :=
go_dependencies += ginkgo=github.com/onsi/ginkgo/v2/ginkgo
go_dependencies += controller-gen=sigs.k8s.io/controller-tools/cmd/controller-gen
go_dependencies += goimports=golang.org/x/tools/cmd/goimports
# FIXME: Switch back to github.com/google/go-licenses once
# https://github.com/google/go-licenses/pull/327 is merged.
# Remember to also update the Go package in the Renovate marker over the version (above).
go_dependencies += go-licenses=github.com/inteon/go-licenses/v2
go_dependencies += gotestsum=gotest.tools/gotestsum
go_dependencies += kustomize=sigs.k8s.io/kustomize/kustomize/v5
go_dependencies += gojq=github.com/itchyny/gojq/cmd/gojq
go_dependencies += crane=github.com/google/go-containerregistry/cmd/crane
go_dependencies += protoc-gen-go=google.golang.org/protobuf/cmd/protoc-gen-go
go_dependencies += cosign=github.com/sigstore/cosign/v2/cmd/cosign
go_dependencies += boilersuite=github.com/cert-manager/boilersuite
go_dependencies += gomarkdoc=github.com/princjef/gomarkdoc/cmd/gomarkdoc
go_dependencies += oras=oras.land/oras/cmd/oras
go_dependencies += klone=github.com/cert-manager/klone
go_dependencies += goreleaser=github.com/goreleaser/goreleaser/v2
go_dependencies += syft=github.com/anchore/syft/cmd/syft
go_dependencies += client-gen=k8s.io/code-generator/cmd/client-gen
go_dependencies += deepcopy-gen=k8s.io/code-generator/cmd/deepcopy-gen
go_dependencies += informer-gen=k8s.io/code-generator/cmd/informer-gen
go_dependencies += lister-gen=k8s.io/code-generator/cmd/lister-gen
go_dependencies += applyconfiguration-gen=k8s.io/code-generator/cmd/applyconfiguration-gen
go_dependencies += defaulter-gen=k8s.io/code-generator/cmd/defaulter-gen
go_dependencies += conversion-gen=k8s.io/code-generator/cmd/conversion-gen
go_dependencies += openapi-gen=k8s.io/kube-openapi/cmd/openapi-gen
go_dependencies += helm-tool=github.com/cert-manager/helm-tool
go_dependencies += image-tool=github.com/cert-manager/image-tool
go_dependencies += cmctl=github.com/cert-manager/cmctl/v2
go_dependencies += cmrel=github.com/cert-manager/release/cmd/cmrel
go_dependencies += golangci-lint=github.com/golangci/golangci-lint/v2/cmd/golangci-lint
go_dependencies += govulncheck=golang.org/x/vuln/cmd/govulncheck
go_dependencies += gh=github.com/cli/cli/v2/cmd/gh
go_dependencies += gci=github.com/daixiang0/gci
go_dependencies += yamlfmt=github.com/google/yamlfmt/cmd/yamlfmt
go_dependencies += kubeconform=github.com/yannh/kubeconform/cmd/kubeconform
go_dependencies += pinact=github.com/suzuki-shunsuke/pinact/v4/cmd/pinact

#################
# go build tags #
#################

go_tags :=

# Additional Go dependencies can be defined to re-use the tooling in this file
ADDITIONAL_GO_DEPENDENCIES ?=
ADDITIONAL_GO_TAGS ?=
go_dependencies += $(ADDITIONAL_GO_DEPENDENCIES)
go_tags += $(ADDITIONAL_GO_TAGS)

go_tags_init = go_tags_$1 :=
$(call for_each_kv,go_tags_init,$(go_dependencies))

go_tags_defs = go_tags_$1 += $2
$(call for_each_kv,go_tags_defs,$(go_tags))

go_tool_names :=

# Template for building Go-based tools from source using "go install"
define go_dependency
go_tool_names += $1

# Go-installed tools have no reviewed hash: they are built locally from source
# and anchored by go.sum/GOSUMDB, not by a SHA-256 in this file. Define the hash
# variables as empty so the verify-at-link check (see tool_link_defs) skips them
# and "make --warn-undefined-variables" stays quiet.
$1_linux_amd64_SHA256SUM :=
$1_linux_arm64_SHA256SUM :=
$1_darwin_amd64_SHA256SUM :=
$1_darwin_arm64_SHA256SUM :=

# The binary is keyed on the Go toolchain version as well as the tool version,
# because a tool built by an older Go cannot always parse a newer standard
# library. Without this, a cached binary is never rebuilt after a Go upgrade:
# the download directory is persisted between CI runs, so the stale binary is
# restored and reused indefinitely.
$(call uc,$1)_DOWNLOAD_PATH := $$(DOWNLOAD_DIR)/tools/$1@$$($(call uc,$1)_VERSION)_$$(GO_TOOLCHAIN_VERSION)_$$(HOST_OS)_$$(HOST_ARCH)

$$($(call uc,$1)_DOWNLOAD_PATH): | $$(NEEDS_GO) $$(DOWNLOAD_DIR)/tools
	@# 1. Use lock script to prevent concurrent builds of the same tool
	@# 2. Install to temp dir using GOBIN, with GOWORK=off to ignore workspace files
	@# 3. Move the binary to final location
	@source $$(lock_script) $$@; \
		mkdir -p $$(outfile).dir; \
		GOWORK=off GOBIN=$$(outfile).dir $$(GO) install --tags "$(strip $(go_tags_$1))" $2@$($(call uc,$1)_VERSION); \
		mv $$(outfile).dir/$1 $$(outfile); \
		rm -rf $$(outfile).dir
endef
$(call for_each_kv,go_dependency,$(go_dependencies))

# Create the symlink from $(bin_dir)/tools/xxx to the versioned binary in
# $(DOWNLOAD_DIR). This runs after the go_dependency template above, so that the
# tools built from source link to their Go-version-specific binary.
#
# The versioned binary is a normal (not order-only) prerequisite: rebuilding it
# makes it newer than the symlink, which forces the symlink to be re-pointed.
# In the steady state the symlink resolves to that same binary, so their
# modification times are equal and nothing is remade. The stamp files catch
# version changes that mtimes cannot, e.g. reverting to an older, already-cached
# tool or Go version. The GO_TOOLCHAIN_VERSION stamp is produced by the generic
# %_VERSION pattern rule above, which stamps the value of the make variable of
# the same name.
#
# Cache integrity: $(DOWNLOAD_DIR) is persisted between CI runs, and for some
# repositories it is a node-local directory shared with less-trusted jobs that
# could overwrite a cached binary in place. The hash is otherwise only verified
# when a tool is *downloaded*, so a binary swapped in the cache after the fact
# would be linked and executed unverified. To close that gap the symlink is a
# .PHONY target: on every build, before linking, the cached binary is re-hashed
# against the reviewed SHA-256 in this file (the trust anchor). A mismatch
# deletes the binary, re-downloads it and verifies the replacement, failing the
# build if it still does not match. The check runs at link time, not at exec
# time, so it detects a poisoned cache and narrows -- but does not close -- the
# window in which a concurrent writer to the cache could swap a binary between
# verification and use.
#
# Each *_SHA256SUM variable must therefore hold the hash of the file stored at
# the tool's download path: for tools downloaded as archives that is the
# EXTRACTED BINARY, not the archive. This matters when adding tools through
# ADDITIONAL_TOOLS in a consuming repository.
#
# Tools built from source with "go install" have no reviewed hash here; their
# integrity comes from go.sum/GOSUMDB when they are built, and their staleness
# is handled by keying the download path on the Go toolchain version (see
# go_dependency).
define tool_link_defs
.PHONY: $$(bin_dir)/tools/$1
$$(bin_dir)/tools/$1: $$(bin_dir)/scratch/$(call uc,$1)_VERSION $(if $(filter $1,$(go_tool_names)),$$(bin_dir)/scratch/GO_TOOLCHAIN_VERSION) $$($(call uc,$1)_DOWNLOAD_PATH) | $$(bin_dir)/tools
	@# Re-verify the cached binary against the reviewed hash before trusting it.
	@# $1_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM is empty for go-installed tools, which
	@# are skipped here: they are anchored by go.sum at build time, not by a hash.
	@# firstword strips the "vendor-go" goal appended to MAKE when vendoring.
	@expected="$$($1_$$(HOST_OS)_$$(HOST_ARCH)_SHA256SUM)"; \
		if [ -z "$$(dry_run)" ] && [ -z "$$$${LEARN_FILE:-}" ] && [ -n "$$$$expected" ] && ! $$(checkhash_script) "$$($(call uc,$1)_DOWNLOAD_PATH)" "$$$$expected" >/dev/null 2>&1; then \
			echo "[verify] cache integrity check failed for $1, re-downloading" >&2; \
			rm -f "$$($(call uc,$1)_DOWNLOAD_PATH)"; \
			$$(firstword $$(MAKE)) --no-print-directory "$$($(call uc,$1)_DOWNLOAD_PATH)" || exit 1; \
			$$(checkhash_script) "$$($(call uc,$1)_DOWNLOAD_PATH)" "$$$$expected" || { echo "[verify] $1 still does not match its reviewed hash after re-download; $1_$$(HOST_OS)_$$(HOST_ARCH)_SHA256SUM must be the hash of the stored binary, not the archive" >&2; exit 1; }; \
		fi
	@# The link is absolute in practice: DOWNLOAD_DIR defaults to a path outside
	@# $(bin_dir). The patsubst makes it relative only when DOWNLOAD_DIR is
	@# overridden to live under $(bin_dir).
	@cd $$(dir $$@) && $$(LN) $$(patsubst $$(bin_dir)/%,../%,$$($(call uc,$1)_DOWNLOAD_PATH)) $$(notdir $$@)
endef
$(foreach tool_name,$(tool_names),$(eval $(call tool_link_defs,$(tool_name))))

##################
# File downloads #
##################

go_linux_amd64_SHA256SUM=675c26c449cbb18fc24b74650de1eabbae6e16f64326fd85a283fb3b58280685
go_linux_arm64_SHA256SUM=51798d2c42d0e1c6ed7fd9f48728b4193abac9e8aad6dbac2fe96a81f5909bda
go_darwin_amd64_SHA256SUM=d3314e25496e4381d71a5c51d2907e7af655d199f6780b549f015bd85fef4986
go_darwin_arm64_SHA256SUM=90493b3bbd5e10f91d12153198bf1994fd756399b4fec93b49b0c6e2acdeeb3e

.PRECIOUS: $(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz
$(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz: | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://go.dev/dl/go$(VENDORED_GO_VERSION).$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile); \
		$(checkhash_script) $(outfile) $(go_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)

helm_linux_amd64_SHA256SUM=92e191314f44aac173711bb0247c38c727f3ddf65ad16a01c0861d509a63a9e1
helm_linux_arm64_SHA256SUM=0690653ac2aad19150f0c22383ceb8aaf4fd96666fcfabb9d4641fbf757e0490
helm_darwin_amd64_SHA256SUM=e906367827b7f793311a49985f60aea0a58de5757012df6be92814e01fd2f910
helm_darwin_arm64_SHA256SUM=66f6b8881392bfa15c6c1dceef980426a28709c8122d5dc8a7a29697cad7334c

.PRECIOUS: $(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://get.helm.sh/helm-$(HELM_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile).tar.gz; \
		tar xfO $(outfile).tar.gz $(HOST_OS)-$(HOST_ARCH)/helm > $(outfile); \
		chmod +x $(outfile); \
		$(checkhash_script) $(outfile) $(helm_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		rm -f $(outfile).tar.gz

helm-unittest_linux_amd64_SHA256SUM=820eb13d0cb270f4c53fe7d55cc26692cc934b638575602759b17420450a314f
helm-unittest_linux_arm64_SHA256SUM=5b69447b04f1e469efd641df2ed101eecc9fe9197178e0610ad22f3a6fc74095
helm-unittest_darwin_amd64_SHA256SUM=7151ec08b58480ac2b49c515fb741b0ed81788e5f75b086df2f994f24d3082a7
helm-unittest_darwin_arm64_SHA256SUM=f804feda430c3b0931e3141c1ebea578fdc78687922750a11b1b45293cde699a

# helm-unittest uses "macos" instead of "darwin" in release filenames
helm_unittest_os := $(HOST_OS)
ifeq ($(HOST_OS),darwin)
helm_unittest_os := macos
endif

.PRECIOUS: $(DOWNLOAD_DIR)/tools/helm-unittest@$(HELM-UNITTEST_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/helm-unittest@$(HELM-UNITTEST_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/helm-unittest/helm-unittest/releases/download/$(HELM-UNITTEST_VERSION)/helm-unittest-$(helm_unittest_os)-$(HOST_ARCH)-$(HELM-UNITTEST_VERSION:v%=%).tgz -o $(outfile).tgz; \
		tar xfO $(outfile).tgz untt-$(helm_unittest_os)-$(HOST_ARCH) > $(outfile); \
		chmod +x $(outfile); \
		$(checkhash_script) $(outfile) $(helm-unittest_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		rm -f $(outfile).tgz

kubectl_linux_amd64_SHA256SUM=ebbd080e7c2e275093b55915722043257eb24004363e20acb3c4d71919f88336
kubectl_linux_arm64_SHA256SUM=3d86f24401c41ae5a46ac50eef8865fe891d3647d324a0836f6c63757a126e62
kubectl_darwin_amd64_SHA256SUM=158b3b46cf74e8b6bd9b1d7cd30f665e3efb2bc1ec3c843ec925bcfdd2930de0
kubectl_darwin_arm64_SHA256SUM=fc8582acde13869a606730a79379d6515f30c68afcced0b5ac8789d5d002b7d6

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kubectl@$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kubectl@$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://dl.k8s.io/release/$(KUBECTL_VERSION)/bin/$(HOST_OS)/$(HOST_ARCH)/kubectl -o $(outfile); \
		$(checkhash_script) $(outfile) $(kubectl_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

kind_linux_amd64_SHA256SUM=50030de23cf40a18505f20426f6a8506bedf13c6e509244bd1fa9463721b0f54
kind_linux_arm64_SHA256SUM=b92cd615e97585de8ddade28ed5cd7feb4248d717c233eea5b03c37298900f5d
kind_darwin_amd64_SHA256SUM=295ac6d0d634c9819c9907df45e3017d1f13166bd13c3404c45e79f7faa47498
kind_darwin_arm64_SHA256SUM=dca67911095a110c2b5c36e26df6cac860c602033e456c0db47be498cdef1ebb

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kind@$(KIND_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kind@$(KIND_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/kubernetes-sigs/kind/releases/download/$(KIND_VERSION)/kind-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(kind_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

vault_linux_amd64_SHA256SUM=920ec883c5d4d07180dfbdacc4300b4afccd4007ba4e59a95833bdd4eab0a6c2
vault_linux_arm64_SHA256SUM=d2ae57f1c38fa45aba4ee3e3d8e062b22864e06a28a6abf4728a0187df7fb860
vault_darwin_amd64_SHA256SUM=39c522ac900fe84a7284925e33de90803388cc596317088e230e937f6cce2035
vault_darwin_arm64_SHA256SUM=2fe08ee36538b69eb65761d5099ad146e7c47326053b77355742dbdfb6657d99

.PRECIOUS: $(DOWNLOAD_DIR)/tools/vault@$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/vault@$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://releases.hashicorp.com/vault/$(VAULT_VERSION:v%=%)/vault_$(VAULT_VERSION:v%=%)_$(HOST_OS)_$(HOST_ARCH).zip -o $(outfile).zip; \
		unzip -p $(outfile).zip vault > $(outfile); \
		chmod +x $(outfile); \
		$(checkhash_script) $(outfile) $(vault_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		rm -f $(outfile).zip

azwi_linux_amd64_SHA256SUM=73f0edeaa103196e37527b6c1d0082587b2f04096adaa3108f74f77c94dc9577
azwi_linux_arm64_SHA256SUM=ccb6dba0073acff2ed98deeee9c78187b75789ac825a55db003830c98ba374d0
azwi_darwin_amd64_SHA256SUM=15e8ce88ae1c8a5477021c78a060e52491da20196bea56484881bb0e192a3dc9
azwi_darwin_arm64_SHA256SUM=72e528da6e71cfcf3209386edb83a80617a4bcb24554559f7388d0e9b4987223

.PRECIOUS: $(DOWNLOAD_DIR)/tools/azwi@$(AZWI_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/azwi@$(AZWI_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/Azure/azure-workload-identity/releases/download/$(AZWI_VERSION)/azwi-$(AZWI_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile).tar.gz; \
		tar xfO $(outfile).tar.gz azwi > $(outfile) && chmod 775 $(outfile); \
		$(checkhash_script) $(outfile) $(azwi_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		rm -f $(outfile).tar.gz

kubebuilder_tools_linux_amd64_SHA256SUM=5e99f4eef3d6f9d4dd063730299f708c98da8801f2f14d8fc762cb354f30c332
kubebuilder_tools_linux_arm64_SHA256SUM=d5eebb129f149a68f8b7bbd7b4c8e51a19f280b3bda1743c94de27f82da78d2e
kubebuilder_tools_darwin_amd64_SHA256SUM=bcc9e95d9e5195bd7224be291c07938f6878c7788ae2faeb344a54cee0a122c6
kubebuilder_tools_darwin_arm64_SHA256SUM=f344e7c70961b100471eeea4d2555006f282a6a27bece7f42fbede77b29b886e

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz
$(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz: | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-$(KUBEBUILDER_ASSETS_VERSION)/envtest-$(KUBEBUILDER_ASSETS_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile); \
		$(checkhash_script) $(outfile) $(kubebuilder_tools_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)

# etcd and kube-apiserver are extracted from the kubebuilder_tools tarball above.
# The tarball's hash is verified when it is downloaded, but the extracted
# binaries are cached individually and restored independently, so they carry
# their own reviewed hashes here for the verify-at-link check (see
# tool_link_defs). Run "make learn-tools-shas" after bumping
# KUBEBUILDER_ASSETS_VERSION to refresh these.
#
# If an extracted binary does not match its reviewed hash, the cached tarball
# is deleted along with it: the tarball is the input the binary was extracted
# from, so keeping it would make every retry re-extract the same bad bytes and
# fail forever until someone cleared the cache by hand.
etcd_linux_amd64_SHA256SUM=b8956dc9f7479b1f15c46d03edae5dd9db508932840f91a9818e67717fcb1850
etcd_linux_arm64_SHA256SUM=6bb34361b70e114bd0a57f1ac899cade84ba951be23c50ed822005bc4243caeb
etcd_darwin_amd64_SHA256SUM=4f5d3debf9fc20b5d9e7c5f8da03d9b3229cdfcbb10698881678aff7b9065528
etcd_darwin_arm64_SHA256SUM=14444022aa4dc681988b1189e4a9b9741641bdad8a9d25399857f525428f1bc8

kube-apiserver_linux_amd64_SHA256SUM=6770be17296ef36b656ad84e52b043007fb9a47ba0445c224097323291b1b33b
kube-apiserver_linux_arm64_SHA256SUM=265e3918c0659ce714fba07b6cc0634edafa4db6dd5891cc8dc3352b028af0f5
kube-apiserver_darwin_amd64_SHA256SUM=5dc17b40bb1c3682e0125a10defc8841cefb1f4842066f5c2d25043c92e3623f
kube-apiserver_darwin_arm64_SHA256SUM=d4f7ab96140f55048669dde973fc84c04d89e85e9ff5429eba0b3b3f8e122b43

$(DOWNLOAD_DIR)/tools/etcd@$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH): $(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz | $(DOWNLOAD_DIR)/tools
	@# Extract specific file from tarball using tar's -O flag (output to stdout)
	@source $(lock_script) $@; \
		{ tar xfO $< controller-tools/envtest/etcd > $(outfile) && chmod 775 $(outfile) && $(checkhash_script) $(outfile) $(etcd_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); } || { echo "[verify] deleting the cached kubebuilder_tools tarball; re-run make to re-download it" >&2; rm -f $<; exit 1; }

$(DOWNLOAD_DIR)/tools/kube-apiserver@$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH): $(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz | $(DOWNLOAD_DIR)/tools
	@# Extract specific file from tarball using tar's -O flag (output to stdout)
	@source $(lock_script) $@; \
		{ tar xfO $< controller-tools/envtest/kube-apiserver > $(outfile) && chmod 775 $(outfile) && $(checkhash_script) $(outfile) $(kube-apiserver_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); } || { echo "[verify] deleting the cached kubebuilder_tools tarball; re-run make to re-download it" >&2; rm -f $<; exit 1; }

kyverno_linux_amd64_SHA256SUM=74d71bdd5300378e7fa6c88c8ac0b065e26341560ac6b9bf54b1e44ed7edadc5
kyverno_linux_arm64_SHA256SUM=b68fb455650040cd85e1cacec4a46fdc630d7c3a105a21f41e6b42154d66e93b
kyverno_darwin_amd64_SHA256SUM=88bf68c14db7336b3ba0d37d9b7ec54f27c00c46e571fec89641b822e8054dd0
kyverno_darwin_arm64_SHA256SUM=a96fe1264a7df74113a2c6dc79ce197b53a9cf6d3362442ade49cb6f7bae0416

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kyverno@$(KYVERNO_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kyverno@$(KYVERNO_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Kyverno uses x86_64 instead of amd64 in download URLs, so translate the architecture
	$(eval ARCH := $(subst amd64,x86_64,$(HOST_ARCH)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/kyverno/kyverno/releases/download/$(KYVERNO_VERSION)/kyverno-cli_$(KYVERNO_VERSION)_$(HOST_OS)_$(ARCH).tar.gz -o $(outfile).tar.gz; \
		tar xfO $(outfile).tar.gz kyverno > $(outfile); \
		chmod +x $(outfile); \
		$(checkhash_script) $(outfile) $(kyverno_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		rm -f $(outfile).tar.gz

yq_linux_amd64_SHA256SUM=c5f056448f973ae7d39b5401949648a78f2dc1947d6a8eb65be60d5c504b9385
yq_linux_arm64_SHA256SUM=88a1016bc1d657375a35864e4f44b6f333df8ff97b559f51bba0adcb2169df09
yq_darwin_amd64_SHA256SUM=caa513cb04f3804b34d4752f0e0d7904fecb9e7cf1d34081289f83259319a7f6
yq_darwin_arm64_SHA256SUM=cceb0b8d71ea5294334121f8429f33f92b920e7217d904a2f9f35443968ac424

.PRECIOUS: $(DOWNLOAD_DIR)/tools/yq@$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/yq@$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/mikefarah/yq/releases/download/$(YQ_VERSION)/yq_$(HOST_OS)_$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(yq_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

ko_linux_amd64_SHA256SUM=6e79a3fbb871021a482a50bcb88cefe6c9e41d53b638961401cc0f2846f415dc
ko_linux_arm64_SHA256SUM=3ffb8fee5bf820d68accce6181484e2f0e6a0fa8896408325d1cf338c05d744a
ko_darwin_amd64_SHA256SUM=5cb7b7a08a2049a873e1b9e4469628d3b18d047ee1961ec50803a0414ab3a0ac
ko_darwin_arm64_SHA256SUM=45c601b888eee4089cac86f2d2fa8ed8c431a835476b0396e0387950a7e6b8e2

.PRECIOUS: $(DOWNLOAD_DIR)/tools/ko@$(KO_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/ko@$(KO_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Ko uses capitalized OS names (Linux/Darwin) and x86_64 instead of amd64
	$(eval OS := $(subst linux,Linux,$(subst darwin,Darwin,$(HOST_OS))))
	$(eval ARCH := $(subst amd64,x86_64,$(HOST_ARCH)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/ko-build/ko/releases/download/v$(KO_VERSION)/ko_$(KO_VERSION)_$(OS)_$(ARCH).tar.gz -o $(outfile).tar.gz; \
		tar xfO $(outfile).tar.gz ko > $(outfile); \
		chmod +x $(outfile); \
		$(checkhash_script) $(outfile) $(ko_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		rm -f $(outfile).tar.gz

protoc_linux_amd64_SHA256SUM=d2c65c3ea5eeb59427f684ed3e0a0cd458386122fc9f1b98de946a7242b53d31
protoc_linux_arm64_SHA256SUM=608546367dd64505f3a676f30fffb546941c833aaab0ae1002c615827807d54d
protoc_darwin_amd64_SHA256SUM=8ddc81374bb0fd6aa7aa86773cd35e2321b69844dad6574c6fac808538393716
protoc_darwin_arm64_SHA256SUM=d81c6d9240f7eb8d18d41c6abc9cd6ca7896e370c7b575adfcf2fa1d600727de

.PRECIOUS: $(DOWNLOAD_DIR)/tools/protoc@$(PROTOC_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/protoc@$(PROTOC_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Protoc uses different naming: darwin->osx, amd64->x86_64, arm64->aarch_64
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))
	$(eval ARCH := $(subst arm64,aarch_64,$(subst amd64,x86_64,$(HOST_ARCH))))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/protocolbuffers/protobuf/releases/download/$(PROTOC_VERSION)/protoc-$(PROTOC_VERSION:v%=%)-$(OS)-$(ARCH).zip -o $(outfile).zip; \
		unzip -p $(outfile).zip bin/protoc > $(outfile); \
		chmod +x $(outfile); \
		$(checkhash_script) $(outfile) $(protoc_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		rm -f $(outfile).zip

trivy_linux_amd64_SHA256SUM=d89bcc6510a267f11b773398cbf1be5520ce39f9e8b6633178c4487f05b7d791
trivy_linux_arm64_SHA256SUM=fed2c9ca7d27191ada34524b5eaf5216a845c6d6f3246143c3b475552ffe5358
trivy_darwin_amd64_SHA256SUM=43ae1fd02532315b44a9d0496ae06326d5a1f3496cae26499be624807813fa8c
trivy_darwin_arm64_SHA256SUM=0ed07c205ca9ecc1065dc57b9f9f77adc79393bb469d9d1de9ec90c8c94ffc2f

.PRECIOUS: $(DOWNLOAD_DIR)/tools/trivy@$(TRIVY_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/trivy@$(TRIVY_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Trivy uses unusual naming: Linux/macOS for OS, 64bit/ARM64 for architecture
	$(eval OS := $(subst linux,Linux,$(subst darwin,macOS,$(HOST_OS))))
	$(eval ARCH := $(subst amd64,64bit,$(subst arm64,ARM64,$(HOST_ARCH))))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/aquasecurity/trivy/releases/download/$(TRIVY_VERSION)/trivy_$(patsubst v%,%,$(TRIVY_VERSION))_$(OS)-$(ARCH).tar.gz -o $(outfile).tar.gz; \
		tar xfO $(outfile).tar.gz trivy > $(outfile); \
		chmod +x $(outfile); \
		$(checkhash_script) $(outfile) $(trivy_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		rm $(outfile).tar.gz

ytt_linux_amd64_SHA256SUM=512cc21193d3b0ce307b6e8db6ba8d40831f16e02526e1c753416456ea4319af
ytt_linux_arm64_SHA256SUM=6b09566cd9cbe90050c8685889aa1eef050c3f1168809df2486062e8a3ed1ec0
ytt_darwin_amd64_SHA256SUM=b7b8435cd5cca719b933b0bc846a0f872bd2ed0c68fa9b74ec8369bef2ac0987
ytt_darwin_arm64_SHA256SUM=4a61ebc3cace9ed6c1f2d4cc7285589e85c58869d96bc36cb0d09987ec14fcd1

.PRECIOUS: $(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) -sSfL https://github.com/vmware-tanzu/carvel-ytt/releases/download/$(YTT_VERSION)/ytt-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(ytt_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

rclone_linux_amd64_SHA256SUM=f3f9aff817f9766029e50adf9a7963c169e475b8f10c7927823568a0d9443db7
rclone_linux_arm64_SHA256SUM=a7094d6e48c6c26cb069175ae93ee221db7dabfa18f57cb6bf3d3d5e1fb1cf3a
rclone_darwin_amd64_SHA256SUM=da8f28fd63f96815505bbb6f2c8afc101f0dc5f6c12347d49bfad75d52547f41
rclone_darwin_arm64_SHA256SUM=f52ccc22e6fe61ea5791f0e186db323155ad1cc1b6dfe547f4bc665bea57a2dd

.PRECIOUS: $(DOWNLOAD_DIR)/tools/rclone@$(RCLONE_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/rclone@$(RCLONE_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Rclone uses "osx" instead of "darwin" in download URLs
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/rclone/rclone/releases/download/$(RCLONE_VERSION)/rclone-$(RCLONE_VERSION)-$(OS)-$(HOST_ARCH).zip -o $(outfile).zip; \
		unzip -p $(outfile).zip rclone-$(RCLONE_VERSION)-$(OS)-$(HOST_ARCH)/rclone > $(outfile); \
		chmod +x $(outfile); \
		$(checkhash_script) $(outfile) $(rclone_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		rm -f $(outfile).zip

istioctl_linux_amd64_SHA256SUM=14a2949dc942cd31d54255b62a1d258bc5b7702c6ffa92e8458bd79fe023fcba
istioctl_linux_arm64_SHA256SUM=7632bce846bf88133b054b59daea89f4e86add5a73e9f1f281d79ca0017da985
istioctl_darwin_amd64_SHA256SUM=dc75ba9d84a12a02387dec553758e3960d57be5a0ed1e36a7b4a7b5a1e50096b
istioctl_darwin_arm64_SHA256SUM=0b978fb4d5633dc673185c181eb5dace3e6bb5d64f93e19f74928da6d3e1d063

.PRECIOUS: $(DOWNLOAD_DIR)/tools/istioctl@$(ISTIOCTL_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/istioctl@$(ISTIOCTL_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Istio uses "osx" instead of "darwin" in download URLs
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/istio/istio/releases/download/$(ISTIOCTL_VERSION)/istio-$(ISTIOCTL_VERSION)-$(OS)-$(HOST_ARCH).tar.gz -o $(outfile).tar.gz; \
		tar xfO $(outfile).tar.gz istio-$(ISTIOCTL_VERSION)/bin/istioctl > $(outfile); \
		chmod +x $(outfile); \
		$(checkhash_script) $(outfile) $(istioctl_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		rm $(outfile).tar.gz

preflight_linux_amd64_SHA256SUM=43a8c5046c800442e58a37f583a9523d79421e81aec3a741c53c9fcffc82955b
preflight_linux_arm64_SHA256SUM=587716550f5acf7d32900322bc1fa20b9401aa3f8ffbf22c95d5ec0a32e4f6f0
preflight_darwin_amd64_SHA256SUM=a6866028b255da1ac930e14343c1539af091f853d5de3489a1b3dd53b6bb0140
preflight_darwin_arm64_SHA256SUM=bbe24db59d0aa24d416ae42d043c27c859014cfe5d5af132d75c8d760ff196bd

.PRECIOUS: $(DOWNLOAD_DIR)/tools/preflight@$(PREFLIGHT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/preflight@$(PREFLIGHT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/redhat-openshift-ecosystem/openshift-preflight/releases/download/$(PREFLIGHT_VERSION)/preflight-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(preflight_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

operator-sdk_linux_amd64_SHA256SUM=887a3bb0d63ccc4ca47a522d0c8ffac56d9d5246f6a2bd886b4ed23eb2e2672f
operator-sdk_linux_arm64_SHA256SUM=6db93cd821b429f0bb514cea4bbb5553827d273fc8aa211f13e14798599d31cd
operator-sdk_darwin_amd64_SHA256SUM=7cb0f24bb63b6383a117291ee4c808953c5dd789d5877da98051aa68b41f40ac
operator-sdk_darwin_arm64_SHA256SUM=098ae8b9dbe7dfd557e8e7ed0f1996736922dd4b984621df2aa033f225cae161

.PRECIOUS: $(DOWNLOAD_DIR)/tools/operator-sdk@$(OPERATOR-SDK_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/operator-sdk@$(OPERATOR-SDK_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/operator-framework/operator-sdk/releases/download/$(OPERATOR-SDK_VERSION)/operator-sdk_$(HOST_OS)_$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(operator-sdk_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

#################
# Other Targets #
#################

# Although we "vendor" most tools in $(bin_dir)/tools, we still require some binaries
# to be available on the system. The vendor-go MAKECMDGOALS trick prevents the
# check for the presence of Go when 'make vendor-go' is run.

# Gotcha warning: MAKECMDGOALS only contains what the _top level_ make invocation used, and doesn't look at target dependencies
# i.e. if we have a target "abc: vendor-go test" and run "make abc", we'll get an error
# about go being missing even though abc itself depends on vendor-go!
# That means we need to pass vendor-go at the top level if go is not installed (i.e. "make vendor-go abc")

# Check for required system tools by testing if each command exists
# If a command is missing, echo its name. The && chains mean all tests run,
# and "missing" will contain a space-separated list of any missing tools.
missing=$(shell (command -v curl >/dev/null || echo curl) \
             && (command -v sha256sum >/dev/null || command -v shasum >/dev/null || echo sha256sum) \
             && (command -v git >/dev/null || echo git) \
             && (command -v xargs >/dev/null || echo xargs) \
             && (command -v bash >/dev/null || echo bash))
ifneq ($(missing),)
$(error Missing required tools: $(missing))
endif

non_go_tool_names := $(filter-out $(go_tool_names),$(tool_names))

.PHONY: non-go-tools
## Download and setup all Non-Go tools
## @category [shared] Tools
non-go-tools: $(non_go_tool_names:%=$(bin_dir)/tools/%)

.PHONY: go-tools
## Download and setup all Go tools
## NOTE: this target is also used to learn the shas of
## these tools (see scripts/learn_tools_shas.sh in the
## Makefile modules repo)
## @category [shared] Tools
go-tools: $(go_tool_names:%=$(bin_dir)/tools/%)

.PHONY: tools
## Download and setup all tools
## @category [shared] Tools
tools: non-go-tools go-tools
