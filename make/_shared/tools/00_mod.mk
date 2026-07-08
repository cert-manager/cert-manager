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
VENDORED_GO_VERSION := 1.26.5

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
tools += helm=v4.2.2
# https://github.com/helm-unittest/helm-unittest/releases
# renovate: datasource=github-releases packageName=helm-unittest/helm-unittest
tools += helm-unittest=v1.1.1
# https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl
# renovate: datasource=github-releases packageName=kubernetes/kubernetes
tools += kubectl=v1.36.2
# https://github.com/kubernetes-sigs/kind/releases
# renovate: datasource=github-releases packageName=kubernetes-sigs/kind
tools += kind=v0.32.0
# https://www.vaultproject.io/downloads
# renovate: datasource=github-releases packageName=hashicorp/vault
tools += vault=v2.0.3
# https://github.com/Azure/azure-workload-identity/releases
# renovate: datasource=github-releases packageName=Azure/azure-workload-identity
tools += azwi=v1.6.0
# https://github.com/kyverno/kyverno/releases
# renovate: datasource=github-releases packageName=kyverno/kyverno
tools += kyverno=v1.18.1
# https://github.com/mikefarah/yq/releases
# renovate: datasource=github-releases packageName=mikefarah/yq
tools += yq=v4.53.3
# https://github.com/ko-build/ko/releases
# renovate: datasource=github-releases packageName=ko-build/ko
tools += ko=0.19.1
# https://github.com/protocolbuffers/protobuf/releases
# renovate: datasource=github-releases packageName=protocolbuffers/protobuf
tools += protoc=v35.1
# https://github.com/aquasecurity/trivy/releases
# renovate: datasource=github-releases packageName=aquasecurity/trivy
tools += trivy=v0.72.0
# https://github.com/vmware-tanzu/carvel-ytt/releases
# renovate: datasource=github-releases packageName=vmware-tanzu/carvel-ytt
tools += ytt=v0.55.1
# https://github.com/rclone/rclone/releases
# renovate: datasource=github-releases packageName=rclone/rclone
tools += rclone=v1.74.3
# https://github.com/istio/istio/releases
# renovate: datasource=github-releases packageName=istio/istio
tools += istioctl=1.30.2

### go packages
# https://pkg.go.dev/sigs.k8s.io/controller-tools/cmd/controller-gen?tab=versions
# renovate: datasource=go packageName=sigs.k8s.io/controller-tools
tools += controller-gen=v0.21.0
# https://pkg.go.dev/golang.org/x/tools/cmd/goimports?tab=versions
# renovate: datasource=go packageName=golang.org/x/tools
tools += goimports=v0.47.0
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
tools += crane=v0.21.7
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
tools += klone=v0.3.0
# https://pkg.go.dev/github.com/goreleaser/goreleaser/v2?tab=versions
# renovate: datasource=go packageName=github.com/goreleaser/goreleaser/v2
tools += goreleaser=v2.17.0
# https://pkg.go.dev/github.com/anchore/syft/cmd/syft?tab=versions
# renovate: datasource=go packageName=github.com/anchore/syft
tools += syft=v1.46.0
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
tools += golangci-lint=v2.12.2
# https://pkg.go.dev/golang.org/x/vuln?tab=versions
# renovate: datasource=go packageName=golang.org/x/vuln
tools += govulncheck=v1.5.0
# https://github.com/operator-framework/operator-sdk/releases
# renovate: datasource=github-releases packageName=operator-framework/operator-sdk
tools += operator-sdk=v1.42.3
# https://pkg.go.dev/github.com/cli/cli/v2?tab=versions
# renovate: datasource=go packageName=github.com/cli/cli/v2
tools += gh=v2.96.0
# https://github.com/redhat-openshift-ecosystem/openshift-preflight/releases
# renovate: datasource=github-releases packageName=redhat-openshift-ecosystem/openshift-preflight
tools += preflight=1.19.1
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
tools += pinact=v4.1.0

# FIXME(erikgb): cert-manager needs the ability to override the version set here
# https://pkg.go.dev/k8s.io/code-generator/cmd?tab=versions
# renovate: datasource=go packageName=k8s.io/code-generator
K8S_CODEGEN_VERSION ?= v0.36.2
tools += client-gen=$(K8S_CODEGEN_VERSION)
tools += deepcopy-gen=$(K8S_CODEGEN_VERSION)
tools += informer-gen=$(K8S_CODEGEN_VERSION)
tools += lister-gen=$(K8S_CODEGEN_VERSION)
tools += applyconfiguration-gen=$(K8S_CODEGEN_VERSION)
tools += defaulter-gen=$(K8S_CODEGEN_VERSION)
tools += conversion-gen=$(K8S_CODEGEN_VERSION)
# https://github.com/kubernetes/kube-openapi
# renovate: datasource=go packageName=k8s.io/kube-openapi
tools += openapi-gen=v0.0.0-20260706235625-cdb1db5517a0

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
# - an unversioned target $(bin_dir)/tools/xxx is generated that
#   creates a link to the corresponding versioned target:
#   $(DOWNLOAD_DIR)/tools/xxx@$(XXX_VERSION)_$(HOST_OS)_$(HOST_ARCH)
define tool_defs
tool_names += $1

$(call uc,$1)_VERSION ?= $2
NEEDS_$(call uc,$1) := $$(bin_dir)/tools/$1
$(call uc,$1) := $$(CURDIR)/$$(bin_dir)/tools/$1

# Create symlink from $(bin_dir)/tools/$1 to the versioned binary in $(DOWNLOAD_DIR)
$$(bin_dir)/tools/$1: $$(bin_dir)/scratch/$(call uc,$1)_VERSION | $$(DOWNLOAD_DIR)/tools/$1@$$($(call uc,$1)_VERSION)_$$(HOST_OS)_$$(HOST_ARCH) $$(bin_dir)/tools
	@# cd into tools dir and create relative symlink (e.g., ../downloaded/tools/helm@v4.0.1_darwin_arm64)
	@# patsubst converts absolute path to relative by replacing $(bin_dir) with ..
	@cd $$(dir $$@) && $$(LN) $$(patsubst $$(bin_dir)/%,../%,$$(word 1,$$|)) $$(notdir $$@)
	@touch $$@ # making sure the target of the symlink is newer than *_VERSION
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
$$(DOWNLOAD_DIR)/tools/$1@$($(call uc,$1)_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $$(NEEDS_GO) $$(DOWNLOAD_DIR)/tools
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

##################
# File downloads #
##################

go_linux_amd64_SHA256SUM=5c2c3b16caefa1d968a94c1daca04a7ca301a496d9b086e17ad77bb81393f053
go_linux_arm64_SHA256SUM=fe4789e92b1f33358680864bbe8704289e7bb5fc207d80623c308935bd696d49
go_darwin_amd64_SHA256SUM=6231d8d3b8f5552ec6cbf6d685bdd5482e1e703214b120e89b3bf0d7bf1ef725
go_darwin_arm64_SHA256SUM=efb87ff28af9a188d0536ef5d42e63dd52ba8263cd7344a993cc48dd11dedb6a

.PRECIOUS: $(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz
$(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz: | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://go.dev/dl/go$(VENDORED_GO_VERSION).$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile); \
		$(checkhash_script) $(outfile) $(go_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)

helm_linux_amd64_SHA256SUM=9adafecab4d406853bba163a70e9f104f47dbbf65ce24b7653bae7e36150bcb6
helm_linux_arm64_SHA256SUM=78803142087a0069fa4b50d3f32a84d3ef25c14d1ee8a40fbccf86a6216d2f36
helm_darwin_amd64_SHA256SUM=10c1e36ee8c5f2e2ee25a16599cb03ab74c0953cd889cacb980a49ba4b6574ba
helm_darwin_arm64_SHA256SUM=5410a0dae3d5d91f45653b161260d9301aabc4ae80ae50a6605d66884b6df8ea

.PRECIOUS: $(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://get.helm.sh/helm-$(HELM_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(helm_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz $(HOST_OS)-$(HOST_ARCH)/helm > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).tar.gz

helm-unittest_linux_amd64_SHA256SUM=07c4fee69e9402e5f66f35b4f932b66afdf9c848637f06196fc479b501d6ad29
helm-unittest_linux_arm64_SHA256SUM=9ac79f441ea65bd095c632c66a6e429b3d89e7aacb5a157d891dc0b6217e9045
helm-unittest_darwin_amd64_SHA256SUM=aeeb891c34e0f447a6f55bbe1605704b46fbc4da41a4448e3227ec57aecbf92b
helm-unittest_darwin_arm64_SHA256SUM=0163ad5fe1aedb75d09e42d3bfe930680daf628471e4cc5130980a6abfe51e8e

# helm-unittest uses "macos" instead of "darwin" in release filenames
helm_unittest_os := $(HOST_OS)
ifeq ($(HOST_OS),darwin)
helm_unittest_os := macos
endif

.PRECIOUS: $(DOWNLOAD_DIR)/tools/helm-unittest@$(HELM-UNITTEST_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/helm-unittest@$(HELM-UNITTEST_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/helm-unittest/helm-unittest/releases/download/$(HELM-UNITTEST_VERSION)/helm-unittest-$(helm_unittest_os)-$(HOST_ARCH)-$(HELM-UNITTEST_VERSION:v%=%).tgz -o $(outfile).tgz; \
		$(checkhash_script) $(outfile).tgz $(helm-unittest_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tgz untt-$(helm_unittest_os)-$(HOST_ARCH) > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).tgz

kubectl_linux_amd64_SHA256SUM=1e9045ec32bea85da43de85f0065358529ea7c7a152eca78154fba5b58c27d82
kubectl_linux_arm64_SHA256SUM=c957eb8c4bea27a3bb35b269edd9082e27f027f7b76b20b5bf4afebc726c6d3e
kubectl_darwin_amd64_SHA256SUM=ce6c5e55cd17559e87e4fb5e73ebbbc2511bcf2b695d7a40c1b1461a9817d4b3
kubectl_darwin_arm64_SHA256SUM=4408c85c83fd3a31adaa555bdf3c7a6c81f74b19449a9060ba31ab91926f023d

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

vault_linux_amd64_SHA256SUM=1e0ffb7a82491219c7242da6e05e2d756b05d1097c29799a42228661f229bc2a
vault_linux_arm64_SHA256SUM=9423a715aea0689f9e498fe7cc5ea692aa1eff282f8b9bc26af28cad69d6d841
vault_darwin_amd64_SHA256SUM=a3462df67c00d1092727dd4fedfba256d2d22d5846fb514c96e03133f567b6af
vault_darwin_arm64_SHA256SUM=abf89e4e56a3af41471ccccdaac1b691874c5e8b20e72c053133d948be0cec42

.PRECIOUS: $(DOWNLOAD_DIR)/tools/vault@$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/vault@$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://releases.hashicorp.com/vault/$(VAULT_VERSION:v%=%)/vault_$(VAULT_VERSION:v%=%)_$(HOST_OS)_$(HOST_ARCH).zip -o $(outfile).zip; \
		$(checkhash_script) $(outfile).zip $(vault_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		unzip -p $(outfile).zip vault > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).zip

azwi_linux_amd64_SHA256SUM=d478f877bea2882666f0ddda3c42276140c86167a938d801df484d109890d5c0
azwi_linux_arm64_SHA256SUM=29f624bb87f563aa120d284ecf5763fc0f78900a23ba0480b64df417d2668c92
azwi_darwin_amd64_SHA256SUM=ed1c50d14f339a79abdf3c2225d9d901f4045d70eea74d845faab2e8715cc9cb
azwi_darwin_arm64_SHA256SUM=2c62df9dacc4a2b893f3ec482fd2dc087ac52dd1f2fd30d6e3e8d40646bf216e

.PRECIOUS: $(DOWNLOAD_DIR)/tools/azwi@$(AZWI_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/azwi@$(AZWI_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/Azure/azure-workload-identity/releases/download/$(AZWI_VERSION)/azwi-$(AZWI_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(azwi_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz azwi > $(outfile) && chmod 775 $(outfile); \
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

$(DOWNLOAD_DIR)/tools/etcd@$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH): $(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz | $(DOWNLOAD_DIR)/tools
	@# Extract specific file from tarball using tar's -O flag (output to stdout)
	@source $(lock_script) $@; \
		tar xfO $< controller-tools/envtest/etcd > $(outfile) && chmod 775 $(outfile)

$(DOWNLOAD_DIR)/tools/kube-apiserver@$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH): $(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz | $(DOWNLOAD_DIR)/tools
	@# Extract specific file from tarball using tar's -O flag (output to stdout)
	@source $(lock_script) $@; \
		tar xfO $< controller-tools/envtest/kube-apiserver > $(outfile) && chmod 775 $(outfile)

kyverno_linux_amd64_SHA256SUM=5e6bba9ca85beec6c93e94ca7fb0972a66df3b2e67636a08bef090cd3fc6535c
kyverno_linux_arm64_SHA256SUM=55eb60200925bf878b020e8af8771ce800d85d2186724a93155058c103ce6bf9
kyverno_darwin_amd64_SHA256SUM=c0d343842a6f630c20f0581d4c5618a8cbef2f3a7bfc935866771af6080c59d7
kyverno_darwin_arm64_SHA256SUM=40d957b4b05be802b4872858e5599ecf3f383949965166fded77c7acd8e9813e

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kyverno@$(KYVERNO_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kyverno@$(KYVERNO_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Kyverno uses x86_64 instead of amd64 in download URLs, so translate the architecture
	$(eval ARCH := $(subst amd64,x86_64,$(HOST_ARCH)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/kyverno/kyverno/releases/download/$(KYVERNO_VERSION)/kyverno-cli_$(KYVERNO_VERSION)_$(HOST_OS)_$(ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(kyverno_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz kyverno > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).tar.gz

yq_linux_amd64_SHA256SUM=fa52a4e758c63d38299163fbdd1edfb4c4963247918bf9c1c5d31d84789eded4
yq_linux_arm64_SHA256SUM=578648e463a11c1b6db6010cbf41eafed6bee79466fcffa1bb446672cf7945ea
yq_darwin_amd64_SHA256SUM=b4ba1ecce3c47f00803f4f964de38394326c7a32eb6540616e04fb2935a0f08d
yq_darwin_arm64_SHA256SUM=877de31753a4dd2401aa048937aa9a7fc4d5f6ce858cf31508c5802954297213

.PRECIOUS: $(DOWNLOAD_DIR)/tools/yq@$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/yq@$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/mikefarah/yq/releases/download/$(YQ_VERSION)/yq_$(HOST_OS)_$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(yq_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

ko_linux_amd64_SHA256SUM=635ac6ea3fd376c935fee597fbb29ab2c2449f49ef1655085fe3aa9c25fed7a5
ko_linux_arm64_SHA256SUM=4099b2d1170d3b8a70e049237462efc2dd14d5fa30e9d2e5e108fb4f778cdd3f
ko_darwin_amd64_SHA256SUM=1b4ed52a5e506a55b085c7f106eb743ee756c776cc90fa232a539a47ad665310
ko_darwin_arm64_SHA256SUM=a1338c4140c8c94e789733e21b161a3de177b467cd3c388b634fe1a869574509

.PRECIOUS: $(DOWNLOAD_DIR)/tools/ko@$(KO_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/ko@$(KO_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Ko uses capitalized OS names (Linux/Darwin) and x86_64 instead of amd64
	$(eval OS := $(subst linux,Linux,$(subst darwin,Darwin,$(HOST_OS))))
	$(eval ARCH := $(subst amd64,x86_64,$(HOST_ARCH)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/ko-build/ko/releases/download/v$(KO_VERSION)/ko_$(KO_VERSION)_$(OS)_$(ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(ko_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz ko > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).tar.gz

protoc_linux_amd64_SHA256SUM=6930ebf62bd4ea607b98fff052596c6ee564b9835b4ce172c75a3f53ae9d91b7
protoc_linux_arm64_SHA256SUM=01bf9d08808c7f96678b63f4bd8efa559bb4f83d5a7a270d5edaf507f9d5d9cf
protoc_darwin_amd64_SHA256SUM=537d73604a344ded6fc94e98e07e529d4fe3e4a0b09e59905353950fafc2a1f7
protoc_darwin_arm64_SHA256SUM=193289af0470c6a1aada357d4fba0bbf8d78bfaac8b5e42ca30af2ef75583de2

.PRECIOUS: $(DOWNLOAD_DIR)/tools/protoc@$(PROTOC_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/protoc@$(PROTOC_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Protoc uses different naming: darwin->osx, amd64->x86_64, arm64->aarch_64
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))
	$(eval ARCH := $(subst arm64,aarch_64,$(subst amd64,x86_64,$(HOST_ARCH))))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/protocolbuffers/protobuf/releases/download/$(PROTOC_VERSION)/protoc-$(PROTOC_VERSION:v%=%)-$(OS)-$(ARCH).zip -o $(outfile).zip; \
		$(checkhash_script) $(outfile).zip $(protoc_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		unzip -p $(outfile).zip bin/protoc > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).zip

trivy_linux_amd64_SHA256SUM=bbb64b9695866ce4a7a8f5c9592002c5961cab378577fa3f8a040df362b9b2ea
trivy_linux_arm64_SHA256SUM=2ca2c023109c2db6b2b77366b6717291452d4531167377d95c79547f0c8e3467
trivy_darwin_amd64_SHA256SUM=ee5e60df8a98e5b89fd74a6d86f9e5c7e9a266a35002cb1e43291698b3bfee08
trivy_darwin_arm64_SHA256SUM=88f208680dc05da2b459e19b4f5aa2b4dc7c2117892ba4aab2ae63baba330016

.PRECIOUS: $(DOWNLOAD_DIR)/tools/trivy@$(TRIVY_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/trivy@$(TRIVY_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Trivy uses unusual naming: Linux/macOS for OS, 64bit/ARM64 for architecture
	$(eval OS := $(subst linux,Linux,$(subst darwin,macOS,$(HOST_OS))))
	$(eval ARCH := $(subst amd64,64bit,$(subst arm64,ARM64,$(HOST_ARCH))))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/aquasecurity/trivy/releases/download/$(TRIVY_VERSION)/trivy_$(patsubst v%,%,$(TRIVY_VERSION))_$(OS)-$(ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(trivy_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz trivy > $(outfile); \
		chmod +x $(outfile); \
		rm $(outfile).tar.gz

ytt_linux_amd64_SHA256SUM=3a2c925ed222f8db4956946d40279688edd6ceb3e919f03f919a8fc8b8532eda
ytt_linux_arm64_SHA256SUM=ce61f7aee3f66f9b78d5781ef8528b7c8e199a2747796ef17a954118d3e65724
ytt_darwin_amd64_SHA256SUM=b6a946878b74883c093bcc3e93960c68a6058a7e2be6ee2c78f1ba5f80fe3c02
ytt_darwin_arm64_SHA256SUM=cf4d4afcf32e5cab1ba55a74f436c7e4bd04326c168a11be17078162629100e9

.PRECIOUS: $(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) -sSfL https://github.com/vmware-tanzu/carvel-ytt/releases/download/$(YTT_VERSION)/ytt-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(ytt_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

rclone_linux_amd64_SHA256SUM=dbee7ccd7a5d617e4ed4cd4555c16669b511abfe8d31164f61be35ac9e999bd2
rclone_linux_arm64_SHA256SUM=8f8d47446e061f80c3256659fe8e21f56d72d96aaefe1275d088ea5eb6b42aa7
rclone_darwin_amd64_SHA256SUM=417cabd402d57806d597bd0ba8fb33a434ca8c2a1a5aa98de5a0bd4b52b39202
rclone_darwin_arm64_SHA256SUM=33a435ab17023b686918ce9a3975aceb75fe1796c694f38f1993024be1f063f5

.PRECIOUS: $(DOWNLOAD_DIR)/tools/rclone@$(RCLONE_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/rclone@$(RCLONE_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Rclone uses "osx" instead of "darwin" in download URLs
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/rclone/rclone/releases/download/$(RCLONE_VERSION)/rclone-$(RCLONE_VERSION)-$(OS)-$(HOST_ARCH).zip -o $(outfile).zip; \
		$(checkhash_script) $(outfile).zip $(rclone_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		unzip -p $(outfile).zip rclone-$(RCLONE_VERSION)-$(OS)-$(HOST_ARCH)/rclone > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).zip

istioctl_linux_amd64_SHA256SUM=ba8ee0ee408a97fe64dbcd408f7374864c1edccf5bf88bb6ad2131bfb0af6adf
istioctl_linux_arm64_SHA256SUM=7cd62e298d6e982d463dc18bd32f47f44e0b0a857ad99a7820318dca694d0cc0
istioctl_darwin_amd64_SHA256SUM=10d8ac9ae5156c6801395e70e91169c9094521b0ffea8a2eac8b72cb96490be1
istioctl_darwin_arm64_SHA256SUM=56deb84b26fefbf425eadc6b71cc9a32da5d8d1a62560c74968d27af80ba18d7

.PRECIOUS: $(DOWNLOAD_DIR)/tools/istioctl@$(ISTIOCTL_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/istioctl@$(ISTIOCTL_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@# Istio uses "osx" instead of "darwin" in download URLs
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/istio/istio/releases/download/$(ISTIOCTL_VERSION)/istio-$(ISTIOCTL_VERSION)-$(OS)-$(HOST_ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(istioctl_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz istio-$(ISTIOCTL_VERSION)/bin/istioctl > $(outfile); \
		chmod +x $(outfile); \
		rm $(outfile).tar.gz

preflight_linux_amd64_SHA256SUM=e8d80effa42b802a88ce90002fb74449a672fd53b9a0addc8c32caa0f6937d58
preflight_linux_arm64_SHA256SUM=027ecfa68e87831ed5a25720730134d38b584e23d6ad43727c1d44164cac65e7
preflight_darwin_amd64_SHA256SUM=f25cf8948166360e14a856e457a6837372cadf76a39b148022adededb23c51a7
preflight_darwin_arm64_SHA256SUM=c2f770992aa424de65218174d4e14e387b4709989834c22a47d16513d7b7e14d

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
