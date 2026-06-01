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
VENDORED_GO_VERSION := 1.26.3

$(bin_dir)/tools $(DOWNLOAD_DIR)/tools:
	@mkdir -p $@

checkhash_script := $(dir $(lastword $(MAKEFILE_LIST)))/util/checkhash.sh
lock_script := $(dir $(lastword $(MAKEFILE_LIST)))/util/lock.sh

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
tools += helm=v4.2.0
# https://github.com/helm-unittest/helm-unittest/releases
# renovate: datasource=github-releases packageName=helm-unittest/helm-unittest
tools += helm-unittest=v1.1.0
# https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl
# renovate: datasource=github-releases packageName=kubernetes/kubernetes
tools += kubectl=v1.36.1
# https://github.com/kubernetes-sigs/kind/releases
# renovate: datasource=github-releases packageName=kubernetes-sigs/kind
tools += kind=v0.31.0
# https://www.vaultproject.io/downloads
# renovate: datasource=github-releases packageName=hashicorp/vault
tools += vault=v2.0.0
# https://github.com/Azure/azure-workload-identity/releases
# renovate: datasource=github-releases packageName=Azure/azure-workload-identity
tools += azwi=v1.5.1
# https://github.com/kyverno/kyverno/releases
# renovate: datasource=github-releases packageName=kyverno/kyverno
tools += kyverno=v1.18.1
# https://github.com/mikefarah/yq/releases
# renovate: datasource=github-releases packageName=mikefarah/yq
tools += yq=v4.53.2
# https://github.com/ko-build/ko/releases
# renovate: datasource=github-releases packageName=ko-build/ko
tools += ko=0.18.1
# https://github.com/protocolbuffers/protobuf/releases
# renovate: datasource=github-releases packageName=protocolbuffers/protobuf
tools += protoc=v35.0
# https://github.com/aquasecurity/trivy/releases
# renovate: datasource=github-releases packageName=aquasecurity/trivy
tools += trivy=v0.70.0
# https://github.com/vmware-tanzu/carvel-ytt/releases
# renovate: datasource=github-releases packageName=vmware-tanzu/carvel-ytt
tools += ytt=v0.55.0
# https://github.com/rclone/rclone/releases
# renovate: datasource=github-releases packageName=rclone/rclone
tools += rclone=v1.74.2
# https://github.com/istio/istio/releases
# renovate: datasource=github-releases packageName=istio/istio
tools += istioctl=1.30.0

### go packages
# https://pkg.go.dev/sigs.k8s.io/controller-tools/cmd/controller-gen?tab=versions
# renovate: datasource=go packageName=sigs.k8s.io/controller-tools
tools += controller-gen=v0.21.0
# https://pkg.go.dev/golang.org/x/tools/cmd/goimports?tab=versions
# renovate: datasource=go packageName=golang.org/x/tools
tools += goimports=v0.45.0
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
tools += crane=v0.21.5
# https://pkg.go.dev/google.golang.org/protobuf/cmd/protoc-gen-go?tab=versions
# renovate: datasource=go packageName=google.golang.org/protobuf
tools += protoc-gen-go=v1.36.11
# https://pkg.go.dev/github.com/sigstore/cosign/v2/cmd/cosign?tab=versions
# renovate: datasource=go packageName=github.com/sigstore/cosign/v2
tools += cosign=v2.6.3
# https://pkg.go.dev/github.com/cert-manager/boilersuite?tab=versions
# renovate: datasource=go packageName=github.com/cert-manager/boilersuite
tools += boilersuite=v0.2.0
# https://pkg.go.dev/github.com/princjef/gomarkdoc/cmd/gomarkdoc?tab=versions
# renovate: datasource=go packageName=github.com/princjef/gomarkdoc
tools += gomarkdoc=v1.1.0
# https://pkg.go.dev/oras.land/oras/cmd/oras?tab=versions
# renovate: datasource=go packageName=oras.land/oras
tools += oras=v1.3.2
# https://pkg.go.dev/github.com/onsi/ginkgo/v2/ginkgo?tab=versions
# The gingko version should be kept in sync with the version used in code.
# If there is no go.mod file (which is only the case for the makefile-modules
# repo), then we default to a version that we know exists. We have to do this
# because otherwise the awk failure renders the whole makefile unusable.
detected_ginkgo_version := $(shell [[ -f go.mod ]] && awk '/ginkgo\/v2/ {print $$2}' go.mod || echo "v2.23.4")
tools += ginkgo=$(detected_ginkgo_version)
# https://pkg.go.dev/github.com/cert-manager/klone?tab=versions
# renovate: datasource=go packageName=github.com/cert-manager/klone
tools += klone=v0.2.0
# https://pkg.go.dev/github.com/goreleaser/goreleaser/v2?tab=versions
# renovate: datasource=go packageName=github.com/goreleaser/goreleaser/v2
tools += goreleaser=v2.16.0
# https://pkg.go.dev/github.com/anchore/syft/cmd/syft?tab=versions
# renovate: datasource=go packageName=github.com/anchore/syft
tools += syft=v1.44.0
# https://github.com/cert-manager/helm-tool/releases
# renovate: datasource=github-releases packageName=cert-manager/helm-tool
tools += helm-tool=v0.5.3
# https://github.com/cert-manager/image-tool/releases
# renovate: datasource=github-releases packageName=cert-manager/image-tool
tools += image-tool=v0.1.0
# https://github.com/cert-manager/cmctl/releases
# renovate: datasource=github-releases packageName=cert-manager/cmctl
tools += cmctl=v2.5.0
# https://pkg.go.dev/github.com/cert-manager/release/cmd/cmrel?tab=versions
# renovate: datasource=go packageName=github.com/cert-manager/release
tools += cmrel=v1.12.15-0.20241121151736-e3cbe5171488
# https://pkg.go.dev/github.com/golangci/golangci-lint/v2/cmd/golangci-lint?tab=versions
# renovate: datasource=go packageName=github.com/golangci/golangci-lint/v2
tools += golangci-lint=v2.12.2
# https://pkg.go.dev/golang.org/x/vuln?tab=versions
# renovate: datasource=go packageName=golang.org/x/vuln
tools += govulncheck=v1.3.0
# https://github.com/operator-framework/operator-sdk/releases
# renovate: datasource=github-releases packageName=operator-framework/operator-sdk
tools += operator-sdk=v1.42.2
# https://pkg.go.dev/github.com/cli/cli/v2?tab=versions
# renovate: datasource=go packageName=github.com/cli/cli/v2
tools += gh=v2.93.0
# https://github.com/redhat-openshift-ecosystem/openshift-preflight/releases
# renovate: datasource=github-releases packageName=redhat-openshift-ecosystem/openshift-preflight
tools += preflight=1.19.0
# https://github.com/daixiang0/gci/releases
# renovate: datasource=github-releases packageName=daixiang0/gci
tools += gci=v0.14.0
# https://github.com/google/yamlfmt/releases
# renovate: datasource=github-releases packageName=google/yamlfmt
tools += yamlfmt=v0.21.0
# https://github.com/yannh/kubeconform/releases
# renovate: datasource=github-releases packageName=yannh/kubeconform
tools += kubeconform=v0.7.0

# FIXME(erikgb): cert-manager needs the ability to override the version set here
# https://pkg.go.dev/k8s.io/code-generator/cmd?tab=versions
# renovate: datasource=go packageName=k8s.io/code-generator
K8S_CODEGEN_VERSION ?= v0.36.1
tools += client-gen=$(K8S_CODEGEN_VERSION)
tools += deepcopy-gen=$(K8S_CODEGEN_VERSION)
tools += informer-gen=$(K8S_CODEGEN_VERSION)
tools += lister-gen=$(K8S_CODEGEN_VERSION)
tools += applyconfiguration-gen=$(K8S_CODEGEN_VERSION)
tools += defaulter-gen=$(K8S_CODEGEN_VERSION)
tools += conversion-gen=$(K8S_CODEGEN_VERSION)
# https://github.com/kubernetes/kube-openapi
# renovate: datasource=go packageName=k8s.io/kube-openapi
tools += openapi-gen=v0.0.0-20260520065146-aa012df4f4af

# https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/master/envtest-releases.yaml
# FIXME: Find a way to configure Renovate to suggest upgrades
KUBEBUILDER_ASSETS_VERSION := v1.36.0
tools += etcd=$(KUBEBUILDER_ASSETS_VERSION)
tools += kube-apiserver=$(KUBEBUILDER_ASSETS_VERSION)

# Additional tools can be defined to reuse the tooling in this file
ADDITIONAL_TOOLS ?=
tools += $(ADDITIONAL_TOOLS)

# Print the go version which can be used in GH actions
.PHONY: print-go-version
print-go-version:
	@echo result=$(VENDORED_GO_VERSION)

# FORCE is used as an order-only prerequisite to make targets always run
# while still allowing Make to track their dependencies correctly
.PHONY: FORCE
FORCE:

# --silent = don't print output like progress meters
# --show-error = but do print errors when they happen
# --fail = exit with a nonzero error code without the response from the server when there's an HTTP error
# --location = follow redirects from the server
# --retry = the number of times to retry a failed attempt to connect
# --retry-connrefused = retry even if the initial connection was refused
CURL := curl --silent --show-error --fail --location --retry 10 --retry-connrefused

# LN is expected to be an atomic action, meaning that two Make processes
# can run the "link $(DOWNLOAD_DIR)/tools/xxx@$(XXX_VERSION)_$(HOST_OS)_$(HOST_ARCH)
# to $(bin_dir)/tools/xxx" operation simultaneously without issues (both
# will perform the action and the second time the link will be overwritten).
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
# - a .PHONY target $(bin_dir)/tools/xxx is generated that
#   ensures the cached binary exists with correct hash and creates a symlink to:
#   $(DOWNLOAD_DIR)/tools/xxx@$(XXX_VERSION)_$(HOST_OS)_$(HOST_ARCH)_$(hash)
define tool_defs
tool_names += $1

$(call uc,$1)_VERSION ?= $2
NEEDS_$(call uc,$1) := $$(bin_dir)/tools/$1
$(call uc,$1) := $$(CURDIR)/$$(bin_dir)/tools/$1

# .PHONY target that ensures cached binary exists and creates symlink
# For non-Go tools: also verifies hash
# For Go tools: skips hash check (Go tools have no SHA256SUM variables)
.PHONY: $$(bin_dir)/tools/$1
$$(bin_dir)/tools/$1: FORCE | $$(bin_dir)/tools
	@# Check if cached binary exists (and hash if defined)
	@cached="$$(DOWNLOAD_DIR)/tools/$1@$$($(call uc,$1)_VERSION)_$$(HOST_OS)_$$(HOST_ARCH)"; \
	expected_hash="$$($1_$$(HOST_OS)_$$(HOST_ARCH)_SHA256SUM)"; \
	if [ ! -f "$$$$cached" ]; then \
		$$(MAKE) --no-print-directory "$$$$cached"; \
	elif [ -n "$$$$expected_hash" ] && ! $$(checkhash_script) "$$$$cached" "$$$$expected_hash" 2>/dev/null; then \
		echo "[info] hash mismatch for $$$$cached, re-downloading..." >&2; \
		rm -f "$$$$cached"; \
		$$(MAKE) --no-print-directory "$$$$cached"; \
	fi; \
	cd $$(dir $$@) && $$(LN) "$$$$cached" $$(notdir $$@)
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
else
export GOROOT := $(CURDIR)/$(bin_dir)/tools/goroot
export PATH := $(CURDIR)/$(bin_dir)/tools/goroot/bin:$(PATH)
GO := $(CURDIR)/$(bin_dir)/tools/go
NEEDS_GO := $(bin_dir)/tools/go
MAKE := $(MAKE) vendor-go
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

#################
# go build tags #
#################

# NOTE: Go-based tools (built with 'go install') do NOT use hash checks.
# Reasons:
# 1. Go builds are not deterministic (hash changes with Go version, build time, etc.)
# 2. Go's module cache (go.sum) + build cache already provide integrity + speed
# 3. The version in the path (tool@version_os_arch) is sufficient
# 4. Cached build with Go's build cache is fast (~0.3s vs ~1.3s first build)
#
# Define empty hash variables to suppress Make warnings
define add_go_tool_empty_hashes
$1_linux_amd64_SHA256SUM :=
$1_linux_arm64_SHA256SUM :=
$1_darwin_amd64_SHA256SUM :=
$1_darwin_arm64_SHA256SUM :=
endef

# Helper to extract tool name from "tool=package" pairs
go_tool_name = $(word 1,$(subst =, ,$1))

# Define empty hash variables for all Go-based tools
$(foreach dep,$(go_dependencies),$(eval $(call add_go_tool_empty_hashes,$(call go_tool_name,$(dep)))))

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
# No hash check - Go builds are non-deterministic, rely on @version and go.sum
define go_dependency
go_tool_names += $1
$$(DOWNLOAD_DIR)/tools/$1@$($(call uc,$1)_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $$(NEEDS_GO) $$(DOWNLOAD_DIR)/tools
	@# 1. Use lock script to prevent concurrent builds of the same tool
	@# 2. Install to temp dir using GOBIN, with GOWORK=off to ignore workspace files
	@# 3. Move the binary to final location (no hash check for Go tools)
	@source $$(lock_script) $$@; \
		mkdir -p $$(outfile).dir; \
		GOWORK=off GOBIN=$$(outfile).dir $$(GO) install --tags "$(strip $(go_tags_$1))" $2@$($(call uc,$1)_VERSION); \
		mv $$(outfile).dir/$1 $$(outfile); \
		rm -rf $$(outfile).dir
endef
$(call for_each_kv,go_dependency,$(go_dependencies))

##################
# File downloads #
##################

# BREAKING CHANGE: All SHA256SUM values below are now for the FINAL BINARY,
# not the downloaded archive. For tools downloaded as archives (zip/tar.gz),
# these hashes must be recomputed for the extracted binary, not the archive.
# The cached binaries are stored at:
#   $(DOWNLOAD_DIR)/tools/<tool>@<version>_<os>_<arch>
# Every `make _bin/tools/<tool>` verifies the cached binary hash and
# re-downloads if there's a mismatch. This makes the shared cache safer
# and prevents hash mismatches between local environments and CI.

go_linux_amd64_SHA256SUM=d68b7abbc40d0844f673f6cf06ae3cded225c50437c6454fa37ef178d079fe65
go_linux_arm64_SHA256SUM=f721d17b9944a3442bcd39793703730b2e2c1b0e93e8cb0fe1cbccf34cd6cf58
go_darwin_amd64_SHA256SUM=15486907b11bbbc1a55c80173a74e583b82d95e712951ae7c759fbf0ba6e3c3f
go_darwin_arm64_SHA256SUM=0bdc5a1cfc9067e050f875767547064a2da19c33fec6662a520ab89fcf73ac88

.PRECIOUS: $(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz
$(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz: | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://go.dev/dl/go$(VENDORED_GO_VERSION).$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile).tmp.tar.gz; \
		mkdir -p $(outfile).tmp.dir; \
		tar xzf $(outfile).tmp.tar.gz -C $(outfile).tmp.dir; \
		$(checkhash_script) $(outfile).tmp.dir/go/bin/go $(go_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		mv $(outfile).tmp.tar.gz $(outfile); \
		rm -rf $(outfile).tmp.dir

helm_linux_amd64_SHA256SUM=bf1e2f933afaaab981b4dce6f0caea951635539336f463780ad479de5408f869
helm_linux_arm64_SHA256SUM=c1f29d55f81004fb7670b9527ad0c037e9c815c0f7460bdf31f0253b277f17da
helm_darwin_amd64_SHA256SUM=77f6879c2cf9b24defd8d85b5e5d07445d83cb11eb74f56bc5cd16549b38ace5
helm_darwin_arm64_SHA256SUM=fdafd9a22b25ff1a674116acb5a35af0420563cc87049a089aaf42222d27930e

.PRECIOUS: $(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://get.helm.sh/helm-$(HELM_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile).tmp.tar.gz; \
		tar xfO $(outfile).tmp.tar.gz $(HOST_OS)-$(HOST_ARCH)/helm > $(outfile).tmp; \
		chmod +x $(outfile).tmp; \
		$(checkhash_script) $(outfile).tmp $(helm_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		mv $(outfile).tmp $(outfile); \
		rm -f $(outfile).tmp.tar.gz

helm-unittest_linux_amd64_SHA256SUM=c30273ef2ce74576dfd08bb0d6b4034847d769f0e3d52547c3fda6093c832533
helm-unittest_linux_arm64_SHA256SUM=925f486683938a88abdeecc4689ed9e8b2ab9fbd13df49f189606c1054c91a38
helm-unittest_darwin_amd64_SHA256SUM=2a7b0e0516c44a163e4189f9ef0aed29f2c8d4bb3a1cdc0629789db062a3678d
helm-unittest_darwin_arm64_SHA256SUM=dc914aedc7ca7b64059f78793f6ce4decff1cbf30c68a94b2d23cfe35430173a

# helm-unittest uses "macos" instead of "darwin" in release filenames
helm_unittest_os := $(HOST_OS)
ifeq ($(HOST_OS),darwin)
helm_unittest_os := macos
endif

.PRECIOUS: $(DOWNLOAD_DIR)/tools/helm-unittest@$(HELM-UNITTEST_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/helm-unittest@$(HELM-UNITTEST_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/helm-unittest/helm-unittest/releases/download/$(HELM-UNITTEST_VERSION)/helm-unittest-$(helm_unittest_os)-$(HOST_ARCH)-$(HELM-UNITTEST_VERSION:v%=%).tgz -o $(outfile).tmp.tgz; \
		tar xfO $(outfile).tmp.tgz untt-$(helm_unittest_os)-$(HOST_ARCH) > $(outfile).tmp; \
		chmod +x $(outfile).tmp; \
		$(checkhash_script) $(outfile).tmp $(helm-unittest_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		mv $(outfile).tmp $(outfile); \
		rm -f $(outfile).tmp.tgz

kubectl_linux_amd64_SHA256SUM=629d3f410e09bf49b64ae7079f7f0bda1191efed311f7d37fdbab0ad5b0ec2b7
kubectl_linux_arm64_SHA256SUM=59f7ee8e477fae658447607dc3c8790ac17a1b016c01c622c12070e969e2d4e7
kubectl_darwin_amd64_SHA256SUM=b4973e90ebb00537d735b63d6f8293c1959156e6ff435f6a43c08aeaa1a2e7d7
kubectl_darwin_arm64_SHA256SUM=9092778abaef3079449da4cd70ded0e4be112480c93efcdeace3155968d1d133

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kubectl@$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kubectl@$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://dl.k8s.io/release/$(KUBECTL_VERSION)/bin/$(HOST_OS)/$(HOST_ARCH)/kubectl -o $(outfile); \
		$(checkhash_script) $(outfile) $(kubectl_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

kind_linux_amd64_SHA256SUM=eb244cbafcc157dff60cf68693c14c9a75c4e6e6fedaf9cd71c58117cb93e3fa
kind_linux_arm64_SHA256SUM=8e1014e87c34901cc422a1445866835d1e666f2a61301c27e722bdeab5a1f7e4
kind_darwin_amd64_SHA256SUM=a8b3cf77b2ad77aec5bf710d1a2589d9117576132af812885cad41e9dede4d4e
kind_darwin_arm64_SHA256SUM=88bf554fe9da6311c9f8c2d082613c002911a476f6b5090e9420b35d84e70c5c

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kind@$(KIND_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kind@$(KIND_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/kubernetes-sigs/kind/releases/download/$(KIND_VERSION)/kind-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(kind_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

vault_linux_amd64_SHA256SUM=80a6b16e4fc38751699e55c5f72a8afcbac326d6a7dba69a14c4fc88eb662cf6
vault_linux_arm64_SHA256SUM=4ab7d04c8f580985a90c7fe19a4c159b1b4cd66aa704423b680fcd0aa6ff632a
vault_darwin_amd64_SHA256SUM=c2823bcd4b3405961f35265b1406f9c42b36f70270c2421a587207ac06f9f617
vault_darwin_arm64_SHA256SUM=275c87609d8a9123883105946ede6ebf91cde91889389569cbfa43fe996b90a4

.PRECIOUS: $(DOWNLOAD_DIR)/tools/vault@$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/vault@$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://releases.hashicorp.com/vault/$(VAULT_VERSION:v%=%)/vault_$(VAULT_VERSION:v%=%)_$(HOST_OS)_$(HOST_ARCH).zip -o $(outfile).tmp.zip; \
		unzip -p $(outfile).tmp.zip vault > $(outfile).tmp; \
		chmod +x $(outfile).tmp; \
		$(checkhash_script) $(outfile).tmp $(vault_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		mv $(outfile).tmp $(outfile); \
		rm -f $(outfile).tmp.zip

azwi_linux_amd64_SHA256SUM=785c933e5c84d900f2b2a47f4dce1f2b7f63ab7acd84f1d1e875f9f29bd6ae4b
azwi_linux_arm64_SHA256SUM=086184a1d99b60981c1ab95d2fe03fb30385ec202a1910aa17546a9033db99bd
azwi_darwin_amd64_SHA256SUM=5592e9ec46eef88e36f25941eea41cfc01046c2caff92ca100ecafbeb035ce57
azwi_darwin_arm64_SHA256SUM=6b01fbf1fc6720c7dc9b35cb587d39c9d2f3c94cb7adac02cfdb670593fdd99d

.PRECIOUS: $(DOWNLOAD_DIR)/tools/azwi@$(AZWI_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/azwi@$(AZWI_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/Azure/azure-workload-identity/releases/download/$(AZWI_VERSION)/azwi-$(AZWI_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile).tmp.tar.gz; \
		tar xfO $(outfile).tmp.tar.gz azwi > $(outfile).tmp && chmod 775 $(outfile).tmp; \
		$(checkhash_script) $(outfile).tmp $(azwi_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		mv $(outfile).tmp $(outfile); \
		rm -f $(outfile).tmp.tar.gz

kubebuilder_tools_linux_amd64_SHA256SUM=d84f910bcefa3f6ab0205a49a7255672150c73b14bca3c36ac627db65040edf0
kubebuilder_tools_linux_arm64_SHA256SUM=84df585fea6e5b5ce9034dc66e4ceffef0cd300999811ae1102aab00ee9b4da6
kubebuilder_tools_darwin_amd64_SHA256SUM=1cbddd87af008b6bad1be5cf424ff88f7b5138489b488129723d1699c95cbd1b
kubebuilder_tools_darwin_arm64_SHA256SUM=211e620e9f61085ac2e3a176a4f4fc5ebc60d40be1dae9ab5e35895f0c748700

etcd_linux_amd64_SHA256SUM=b8956dc9f7479b1f15c46d03edae5dd9db508932840f91a9818e67717fcb1850
etcd_linux_arm64_SHA256SUM=6bb34361b70e114bd0a57f1ac899cade84ba951be23c50ed822005bc4243caeb
etcd_darwin_amd64_SHA256SUM=4f5d3debf9fc20b5d9e7c5f8da03d9b3229cdfcbb10698881678aff7b9065528
etcd_darwin_arm64_SHA256SUM=14444022aa4dc681988b1189e4a9b9741641bdad8a9d25399857f525428f1bc8

kube-apiserver_linux_amd64_SHA256SUM=8116b8f13d1c8bbbbba0599fff1a27959f2a13b6cbb18c4efad5f9777c0a839c
kube-apiserver_linux_arm64_SHA256SUM=f622843949492d97183dadf883b57ee96afcf04e19cc6799388eed5a08594965
kube-apiserver_darwin_amd64_SHA256SUM=bf7a8a8f131588e988ffb1b5237a67b738f8c68743f37020f54a07e6323fa251
kube-apiserver_darwin_arm64_SHA256SUM=5794cd2fab25328eda45b46d2bb23caa527708d3bef762a46412db01c56a9377

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz
$(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz: | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-$(KUBEBUILDER_ASSETS_VERSION)/envtest-$(KUBEBUILDER_ASSETS_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile); \
		$(checkhash_script) $(outfile) $(kubebuilder_tools_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)

$(DOWNLOAD_DIR)/tools/etcd@$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH): $(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz | $(DOWNLOAD_DIR)/tools
	@# Extract specific file from tarball using tar's -O flag (output to stdout)
	@source $(lock_script) $@; \
		tar xfO $< controller-tools/envtest/etcd > $(outfile).tmp && chmod 775 $(outfile).tmp; \
		$(checkhash_script) $(outfile).tmp $(etcd_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		mv $(outfile).tmp $(outfile)

$(DOWNLOAD_DIR)/tools/kube-apiserver@$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH): $(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz | $(DOWNLOAD_DIR)/tools
	@# Extract specific file from tarball using tar's -O flag (output to stdout)
	@source $(lock_script) $@; \
		tar xfO $< controller-tools/envtest/kube-apiserver > $(outfile).tmp && chmod 775 $(outfile).tmp; \
		$(checkhash_script) $(outfile).tmp $(kube-apiserver_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		mv $(outfile).tmp $(outfile)

kyverno_linux_amd64_SHA256SUM=407feba30302b62e8597d5b8740365053f2449c7b4c52a347cef54eff1873209
kyverno_linux_arm64_SHA256SUM=e8afd0cc70cfe3275632735c14fd549ccf12a3a4c1e5106c6cc922ede7a1b4b7
kyverno_darwin_amd64_SHA256SUM=5bc8a91a95c28b5575f569676b53e37cdda392d8f71e95a1cd5befb22da96b77
kyverno_darwin_arm64_SHA256SUM=192eabe3b7be7dcd6fc5cf14979f2d8b3036ce47bc7d7b066c1dcc0e1758c0fb

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kyverno@$(KYVERNO_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kyverno@$(KYVERNO_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Kyverno uses x86_64 instead of amd64 in download URLs, so translate the architecture
	$(eval ARCH := $(subst amd64,x86_64,$(HOST_ARCH)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/kyverno/kyverno/releases/download/$(KYVERNO_VERSION)/kyverno-cli_$(KYVERNO_VERSION)_$(HOST_OS)_$(ARCH).tar.gz -o $(outfile).tmp.tar.gz; \
		tar xfO $(outfile).tmp.tar.gz kyverno > $(outfile).tmp; \
		chmod +x $(outfile).tmp; \
		$(checkhash_script) $(outfile).tmp $(kyverno_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		mv $(outfile).tmp $(outfile); \
		rm -f $(outfile).tmp.tar.gz

yq_linux_amd64_SHA256SUM=d56bf5c6819e8e696340c312bd70f849dc1678a7cda9c2ad63eebd906371d56b
yq_linux_arm64_SHA256SUM=03061b2a50c7a498de2bbb92d7cb078ce433011f085a4994117c2726be4106ea
yq_darwin_amd64_SHA256SUM=616b0a0f6a5b79d746f05a169c2b9bb40dee00c605ef165b9a1c1681bba738ac
yq_darwin_arm64_SHA256SUM=541ba2287560df70f561955e2d7f7e1cd00cf2a15a884f6b5c87a4bfa887bc07

.PRECIOUS: $(DOWNLOAD_DIR)/tools/yq@$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/yq@$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/mikefarah/yq/releases/download/$(YQ_VERSION)/yq_$(HOST_OS)_$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(yq_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

ko_linux_amd64_SHA256SUM=8bdc5b642d7bf9adbedf18c020f0bad5c31352b9e329c67667b574f2a2e7d344
ko_linux_arm64_SHA256SUM=e320fb0698294e7e656379b185f7321b86a3705ec25049b6d0c9ac14d91bdc84
ko_darwin_amd64_SHA256SUM=302a2d65ed173daa3ce80bd9a3c25687662121e8800f6c1a3ee4ef3f64ca6db0
ko_darwin_arm64_SHA256SUM=52a58593ee596f059330d2bf4b4d97a2e6575c622276579954c8e762a0e175f4

.PRECIOUS: $(DOWNLOAD_DIR)/tools/ko@$(KO_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/ko@$(KO_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Ko uses capitalized OS names (Linux/Darwin) and x86_64 instead of amd64
	$(eval OS := $(subst linux,Linux,$(subst darwin,Darwin,$(HOST_OS))))
	$(eval ARCH := $(subst amd64,x86_64,$(HOST_ARCH)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/ko-build/ko/releases/download/v$(KO_VERSION)/ko_$(KO_VERSION)_$(OS)_$(ARCH).tar.gz -o $(outfile).tmp.tar.gz; \
		tar xfO $(outfile).tmp.tar.gz ko > $(outfile).tmp; \
		chmod +x $(outfile).tmp; \
		$(checkhash_script) $(outfile).tmp $(ko_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		mv $(outfile).tmp $(outfile); \
		rm -f $(outfile).tmp.tar.gz

protoc_linux_amd64_SHA256SUM=3d6aef252f3851bdee5a7e7a2c8c927d4980e014d8ac0f18c8ba2d6f084a0504
protoc_linux_arm64_SHA256SUM=89f21634e7de36c483b54abeee5f23e5060b6c34e070d6add0e825a72776108c
protoc_darwin_amd64_SHA256SUM=31fa8d15e76658da1730fd6c76be2f8251b1c3fe715c2a7103387d549bff7966
protoc_darwin_arm64_SHA256SUM=5c51efe5d53bb87ffb4de8beb43611757b13c98361ce1008ae590e5261f02ee2

.PRECIOUS: $(DOWNLOAD_DIR)/tools/protoc@$(PROTOC_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/protoc@$(PROTOC_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Protoc uses different naming: darwin->osx, amd64->x86_64, arm64->aarch_64
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))
	$(eval ARCH := $(subst arm64,aarch_64,$(subst amd64,x86_64,$(HOST_ARCH))))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/protocolbuffers/protobuf/releases/download/$(PROTOC_VERSION)/protoc-$(PROTOC_VERSION:v%=%)-$(OS)-$(ARCH).zip -o $(outfile).tmp.zip; \
		unzip -p $(outfile).tmp.zip bin/protoc > $(outfile).tmp; \
		chmod +x $(outfile).tmp; \
		$(checkhash_script) $(outfile).tmp $(protoc_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		mv $(outfile).tmp $(outfile); \
		rm -f $(outfile).tmp.zip

trivy_linux_amd64_SHA256SUM=379d59f24a4a828c55de5f0b91b6805cc35d13580180b658820e648611256166
trivy_linux_arm64_SHA256SUM=5bf6066f08c972e0575660eaeb87b4f1bac0e527076dcbf88184bc9baa353f65
trivy_darwin_amd64_SHA256SUM=a17293a8800c2dcd8d7cf161cce9232a7cc986288912eddf47b982db4b46466b
trivy_darwin_arm64_SHA256SUM=3122de2c39d6ae433c2355a87508fb18dca637cf7f149e0006b63ddefb0cdc52

.PRECIOUS: $(DOWNLOAD_DIR)/tools/trivy@$(TRIVY_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/trivy@$(TRIVY_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Trivy uses unusual naming: Linux/macOS for OS, 64bit/ARM64 for architecture
	$(eval OS := $(subst linux,Linux,$(subst darwin,macOS,$(HOST_OS))))
	$(eval ARCH := $(subst amd64,64bit,$(subst arm64,ARM64,$(HOST_ARCH))))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/aquasecurity/trivy/releases/download/$(TRIVY_VERSION)/trivy_$(patsubst v%,%,$(TRIVY_VERSION))_$(OS)-$(ARCH).tar.gz -o $(outfile).tmp.tar.gz; \
		tar xfO $(outfile).tmp.tar.gz trivy > $(outfile).tmp; \
		chmod +x $(outfile).tmp; \
		$(checkhash_script) $(outfile).tmp $(trivy_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		mv $(outfile).tmp $(outfile); \
		rm -f $(outfile).tmp.tar.gz

ytt_linux_amd64_SHA256SUM=013adf9ed2fbd392b9861e5ec34015dabfcfa2e82da9e8cc0ee1e5c6a7f9b64b
ytt_linux_arm64_SHA256SUM=14e0a83a793c04bd26b2a2328f6df169b38ddf24257a64ffde23038f4ecab0bf
ytt_darwin_amd64_SHA256SUM=6218426752505fffce393a18eb700e7ddb2ddcc1c8ad521d02101bdb9db2f7f6
ytt_darwin_arm64_SHA256SUM=76c2d8f958568ceabe927d32206d79b779bd8341450d99b78d028ae608d1348b

.PRECIOUS: $(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) -sSfL https://github.com/vmware-tanzu/carvel-ytt/releases/download/$(YTT_VERSION)/ytt-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(ytt_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

rclone_linux_amd64_SHA256SUM=920b6ee51518922a3a8b70509d44410e686146867c2103ad58384a71e1694b75
rclone_linux_arm64_SHA256SUM=9d31b718dc7b230c5ed353ab5909dd301a911f9483e7c92f5fa4b7762bb3c3db
rclone_darwin_amd64_SHA256SUM=f7008053d0e84ee45e81ecd8578ec8cf0fe6bf01c47b7840ac09b0c9d70f2e67
rclone_darwin_arm64_SHA256SUM=078112b57bfa04092dfef1f9b38769d95401ebf3f2c621004e729ad4a3fff533

.PRECIOUS: $(DOWNLOAD_DIR)/tools/rclone@$(RCLONE_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/rclone@$(RCLONE_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Rclone uses "osx" instead of "darwin" in download URLs
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/rclone/rclone/releases/download/$(RCLONE_VERSION)/rclone-$(RCLONE_VERSION)-$(OS)-$(HOST_ARCH).zip -o $(outfile).tmp.zip; \
		unzip -p $(outfile).tmp.zip rclone-$(RCLONE_VERSION)-$(OS)-$(HOST_ARCH)/rclone > $(outfile).tmp; \
		chmod +x $(outfile).tmp; \
		$(checkhash_script) $(outfile).tmp $(rclone_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		mv $(outfile).tmp $(outfile); \
		rm -f $(outfile).tmp.zip

istioctl_linux_amd64_SHA256SUM=4806bade63175897beae346a13f041ff47da889b36bac6096adce8ad0a8108b8
istioctl_linux_arm64_SHA256SUM=b9ce69f2d89f5f218b4fa15a123dcda248d2f3cce58d09edc6fb1af124ab6cbb
istioctl_darwin_amd64_SHA256SUM=6e96eb1f6f2cb27719ccb6efab975af46682427d22897c71e2c3b1b02bb2acd2
istioctl_darwin_arm64_SHA256SUM=7be2917d86ef6edebcc3939bcc9b346b815876eacac222f0501c575b3c2db500

.PRECIOUS: $(DOWNLOAD_DIR)/tools/istioctl@$(ISTIOCTL_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/istioctl@$(ISTIOCTL_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Istio uses "osx" instead of "darwin" in download URLs
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/istio/istio/releases/download/$(ISTIOCTL_VERSION)/istio-$(ISTIOCTL_VERSION)-$(OS)-$(HOST_ARCH).tar.gz -o $(outfile).tmp.tar.gz; \
		tar xfO $(outfile).tmp.tar.gz istio-$(ISTIOCTL_VERSION)/bin/istioctl > $(outfile).tmp; \
		chmod +x $(outfile).tmp; \
		$(checkhash_script) $(outfile).tmp $(istioctl_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		mv $(outfile).tmp $(outfile); \
		rm -f $(outfile).tmp.tar.gz

preflight_linux_amd64_SHA256SUM=1d7a845c4528f9476c8ef9a551b4da5c06d62de558e56a37054c6fa737d583e5
preflight_linux_arm64_SHA256SUM=09e59f31c1d13e30381260ddf64d9f46120131e490e94bd0e7a958ba1af0d6cb
preflight_darwin_amd64_SHA256SUM=ec8c8be7a6fd48e2acf8c4630f75b6a8eae4fed0b5e76cf295f2bf6216a61440
preflight_darwin_arm64_SHA256SUM=ec4ff1ec8b2369b6955121dada4c3d5389a6d1b5f9462758b94bbb04b79a530d

.PRECIOUS: $(DOWNLOAD_DIR)/tools/preflight@$(PREFLIGHT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/preflight@$(PREFLIGHT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/redhat-openshift-ecosystem/openshift-preflight/releases/download/$(PREFLIGHT_VERSION)/preflight-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(preflight_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

operator-sdk_linux_amd64_SHA256SUM=8847c45ea994ac62b3cd134f77934df2a16a56a39a634eb988e0d1db99d1a413
operator-sdk_linux_arm64_SHA256SUM=5fbb4c9f1eb3d8f6e9f870bfb48160842b9b541ce644d602282ef86578fedc1c
operator-sdk_darwin_amd64_SHA256SUM=0293b988886b5a2a82b6c141c46293915f0c67cae43cabdb36a0ffdf8af042b6
operator-sdk_darwin_arm64_SHA256SUM=8f7c19e35ce6ad4069502fcb66ea89548d0173ff8a02b253b0be4ad4909eeaf6

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
