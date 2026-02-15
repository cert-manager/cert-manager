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
tools += helm=v4.1.1
# https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl
# renovate: datasource=github-releases packageName=kubernetes/kubernetes
tools += kubectl=v1.35.1
# https://github.com/kubernetes-sigs/kind/releases
# renovate: datasource=github-releases packageName=kubernetes-sigs/kind
tools += kind=v0.31.0
# https://www.vaultproject.io/downloads
# renovate: datasource=github-releases packageName=hashicorp/vault
tools += vault=v1.21.2
# https://github.com/Azure/azure-workload-identity/releases
# renovate: datasource=github-releases packageName=Azure/azure-workload-identity
tools += azwi=v1.5.1
# https://github.com/kyverno/kyverno/releases
# renovate: datasource=github-releases packageName=kyverno/kyverno
tools += kyverno=v1.17.0
# https://github.com/mikefarah/yq/releases
# renovate: datasource=github-releases packageName=mikefarah/yq
tools += yq=v4.52.4
# https://github.com/ko-build/ko/releases
# renovate: datasource=github-releases packageName=ko-build/ko
tools += ko=0.18.1
# https://github.com/protocolbuffers/protobuf/releases
# renovate: datasource=github-releases packageName=protocolbuffers/protobuf
tools += protoc=v33.5
# https://github.com/aquasecurity/trivy/releases
# renovate: datasource=github-releases packageName=aquasecurity/trivy
tools += trivy=v0.69.1
# https://github.com/vmware-tanzu/carvel-ytt/releases
# renovate: datasource=github-releases packageName=vmware-tanzu/carvel-ytt
tools += ytt=v0.53.0
# https://github.com/rclone/rclone/releases
# renovate: datasource=github-releases packageName=rclone/rclone
tools += rclone=v1.73.0
# https://github.com/istio/istio/releases
# renovate: datasource=github-releases packageName=istio/istio
tools += istioctl=1.28.3

### go packages
# https://pkg.go.dev/sigs.k8s.io/controller-tools/cmd/controller-gen?tab=versions
# renovate: datasource=go packageName=sigs.k8s.io/controller-tools
tools += controller-gen=v0.20.1
# https://pkg.go.dev/golang.org/x/tools/cmd/goimports?tab=versions
# renovate: datasource=go packageName=golang.org/x/tools
tools += goimports=v0.42.0
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
tools += gojq=v0.12.18
# https://pkg.go.dev/github.com/google/go-containerregistry/pkg/crane?tab=versions
# renovate: datasource=go packageName=github.com/google/go-containerregistry
tools += crane=v0.20.7
# https://pkg.go.dev/google.golang.org/protobuf/cmd/protoc-gen-go?tab=versions
# renovate: datasource=go packageName=google.golang.org/protobuf
tools += protoc-gen-go=v1.36.11
# https://pkg.go.dev/github.com/sigstore/cosign/v2/cmd/cosign?tab=versions
# renovate: datasource=go packageName=github.com/sigstore/cosign/v2
tools += cosign=v2.6.2
# https://pkg.go.dev/github.com/cert-manager/boilersuite?tab=versions
# renovate: datasource=go packageName=github.com/cert-manager/boilersuite
tools += boilersuite=v0.2.0
# https://pkg.go.dev/github.com/princjef/gomarkdoc/cmd/gomarkdoc?tab=versions
# renovate: datasource=go packageName=github.com/princjef/gomarkdoc
tools += gomarkdoc=v1.1.0
# https://pkg.go.dev/oras.land/oras/cmd/oras?tab=versions
# renovate: datasource=go packageName=oras.land/oras
tools += oras=v1.3.0
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
tools += goreleaser=v2.13.3
# https://pkg.go.dev/github.com/anchore/syft/cmd/syft?tab=versions
# renovate: datasource=go packageName=github.com/anchore/syft
tools += syft=v1.42.0
# https://github.com/cert-manager/helm-tool/releases
# renovate: datasource=github-releases packageName=cert-manager/helm-tool
tools += helm-tool=v0.5.3
# https://github.com/cert-manager/image-tool/releases
# renovate: datasource=github-releases packageName=cert-manager/image-tool
tools += image-tool=v0.1.0
# https://github.com/cert-manager/cmctl/releases
# renovate: datasource=github-releases packageName=cert-manager/cmctl
tools += cmctl=v2.4.0
# https://pkg.go.dev/github.com/cert-manager/release/cmd/cmrel?tab=versions
# renovate: datasource=go packageName=github.com/cert-manager/release
tools += cmrel=v1.12.15-0.20241121151736-e3cbe5171488
# https://pkg.go.dev/github.com/golangci/golangci-lint/v2/cmd/golangci-lint?tab=versions
# renovate: datasource=go packageName=github.com/golangci/golangci-lint/v2
tools += golangci-lint=v2.9.0
# https://pkg.go.dev/golang.org/x/vuln?tab=versions
# renovate: datasource=go packageName=golang.org/x/vuln
tools += govulncheck=v1.1.4
# https://github.com/operator-framework/operator-sdk/releases
# renovate: datasource=github-releases packageName=operator-framework/operator-sdk
tools += operator-sdk=v1.42.0
# https://pkg.go.dev/github.com/cli/cli/v2?tab=versions
# renovate: datasource=go packageName=github.com/cli/cli/v2
tools += gh=v2.86.0
# https://github.com/redhat-openshift-ecosystem/openshift-preflight/releases
# renovate: datasource=github-releases packageName=redhat-openshift-ecosystem/openshift-preflight
tools += preflight=1.16.0
# https://github.com/daixiang0/gci/releases
# renovate: datasource=github-releases packageName=daixiang0/gci
tools += gci=v0.13.7
# https://github.com/google/yamlfmt/releases
# renovate: datasource=github-releases packageName=google/yamlfmt
tools += yamlfmt=v0.21.0
# https://github.com/yannh/kubeconform/releases
# renovate: datasource=github-releases packageName=yannh/kubeconform
tools += kubeconform=v0.7.0

# FIXME(erikgb): cert-manager needs the ability to override the version set here
# https://pkg.go.dev/k8s.io/code-generator/cmd?tab=versions
# renovate: datasource=go packageName=k8s.io/code-generator
K8S_CODEGEN_VERSION ?= v0.35.1
tools += client-gen=$(K8S_CODEGEN_VERSION)
tools += deepcopy-gen=$(K8S_CODEGEN_VERSION)
tools += informer-gen=$(K8S_CODEGEN_VERSION)
tools += lister-gen=$(K8S_CODEGEN_VERSION)
tools += applyconfiguration-gen=$(K8S_CODEGEN_VERSION)
tools += defaulter-gen=$(K8S_CODEGEN_VERSION)
tools += conversion-gen=$(K8S_CODEGEN_VERSION)
# https://github.com/kubernetes/kube-openapi
# renovate: datasource=go packageName=k8s.io/kube-openapi
tools += openapi-gen=v0.0.0-20260127142750-a19766b6e2d4

# https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/master/envtest-releases.yaml
# FIXME: Find a way to configure Renovate to suggest upgrades
KUBEBUILDER_ASSETS_VERSION := v1.35.0
tools += etcd=$(KUBEBUILDER_ASSETS_VERSION)
tools += kube-apiserver=$(KUBEBUILDER_ASSETS_VERSION)

# Additional tools can be defined to reuse the tooling in this file
ADDITIONAL_TOOLS ?=
tools += $(ADDITIONAL_TOOLS)

# https://go.dev/dl/
# renovate: datasource=golang-version packageName=go
VENDORED_GO_VERSION := 1.26.0

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

go_linux_amd64_SHA256SUM=aac1b08a0fb0c4e0a7c1555beb7b59180b05dfc5a3d62e40e9de90cd42f88235
go_linux_arm64_SHA256SUM=bd03b743eb6eb4193ea3c3fd3956546bf0e3ca5b7076c8226334afe6b75704cd
go_darwin_amd64_SHA256SUM=1ca28b7703cbea05a65b2a1d92d6b308610ef92f8824578a0874f2e60c9d5a22
go_darwin_arm64_SHA256SUM=b1640525dfe68f066d56f200bef7bf4dce955a1a893bd061de6754c211431023

.PRECIOUS: $(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz
$(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz: | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://go.dev/dl/go$(VENDORED_GO_VERSION).$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile); \
		$(checkhash_script) $(outfile) $(go_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)

helm_linux_amd64_SHA256SUM=5d4c7623283e6dfb1971957f4b755468ab64917066a8567dd50464af298f4031
helm_linux_arm64_SHA256SUM=02a5fb7742469d2d132e24cb7c3f52885894043576588c6788b6813297629edd
helm_darwin_amd64_SHA256SUM=6b8dbb03abb74e9ab8e69ca3f9b6459178be11317d0ac502f922621c05fdc866
helm_darwin_arm64_SHA256SUM=b8f49e105b1d2fd8c8a90ba3fc9af48db91d2d1ca3b9e788352fc7c896bbb71a

.PRECIOUS: $(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://get.helm.sh/helm-$(HELM_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(helm_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz $(HOST_OS)-$(HOST_ARCH)/helm > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).tar.gz

kubectl_linux_amd64_SHA256SUM=36e2f4ac66259232341dd7866952d64a958846470f6a9a6a813b9117bd965207
kubectl_linux_arm64_SHA256SUM=706256e21a4e9192ee62d1a007ac0bfcff2b0b26e92cc7baad487a6a5d08ff82
kubectl_darwin_amd64_SHA256SUM=07a04d82bc2de2f5d53dfd81f2109ca864f634a82b225257daa2f9c2db15ccef
kubectl_darwin_arm64_SHA256SUM=2b000dded317319b1ebca19c2bc70f772c7aaa0e8962fae2d987ba04dd1a1b50

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

vault_linux_amd64_SHA256SUM=d2005a053a2ab75318d395ca8151aef9116fde67f75dc8f43a4fa9def6f3fc9e
vault_linux_arm64_SHA256SUM=27dc55533a201be4c427319a31caa3ca330cfd40b158d111f22a1dee94ae1f17
vault_darwin_amd64_SHA256SUM=1bb297df6230212764f24df88b3123419c49be6528743cffcaf8d676547634dc
vault_darwin_arm64_SHA256SUM=d197adcb303cb527834774e19d6a67abcefb11cc9c57bd42f5bcdd4a1b21be9c

.PRECIOUS: $(DOWNLOAD_DIR)/tools/vault@$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/vault@$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://releases.hashicorp.com/vault/$(VAULT_VERSION:v%=%)/vault_$(VAULT_VERSION:v%=%)_$(HOST_OS)_$(HOST_ARCH).zip -o $(outfile).zip; \
		$(checkhash_script) $(outfile).zip $(vault_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		unzip -p $(outfile).zip vault > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).zip

azwi_linux_amd64_SHA256SUM=d816d24c865d86ca101219197b493e399d3f669e8e20e0aaffc5a09f0f4c0aaf
azwi_linux_arm64_SHA256SUM=f74799439ec3d33d6f69dcaa237fbdde8501390f06ee6d6fb1edfb36f64e1fa6
azwi_darwin_amd64_SHA256SUM=50dec4f29819a68827d695950a36b296aff501e81420787c16603d6394503c97
azwi_darwin_arm64_SHA256SUM=f267f5fad691cb60d1983a3df5c9a67d83cba0ca0d87aa707a713d2ba4f47776

.PRECIOUS: $(DOWNLOAD_DIR)/tools/azwi@$(AZWI_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/azwi@$(AZWI_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/Azure/azure-workload-identity/releases/download/$(AZWI_VERSION)/azwi-$(AZWI_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(azwi_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz azwi > $(outfile) && chmod 775 $(outfile); \
		rm -f $(outfile).tar.gz

kubebuilder_tools_linux_amd64_SHA256SUM=5716719def14a3fec3ed285e5e8c4280e6268854039b5073a96e8c0adafb1c02
kubebuilder_tools_linux_arm64_SHA256SUM=5057fb45eecf246929da768b21d32434b8c96e22a78ef6cdfe912f1a67aae45a
kubebuilder_tools_darwin_amd64_SHA256SUM=e733f72effc8a8076f2c8eb892de4aeb4bb54ea02082808ce3e51f80f2ff85e2
kubebuilder_tools_darwin_arm64_SHA256SUM=3c6b1ebd745b82daed47605fb565f7c670c8a3344b57a377a914d013b6b9eef0

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

kyverno_linux_amd64_SHA256SUM=f3ed671574fcca224e30c259131e524b0594f84f864c7c5087cdcfdae6d605e2
kyverno_linux_arm64_SHA256SUM=ebb5249f5d10eba6eb071fe359398be2d3b812711042fb2c7fec503e6f6cbddd
kyverno_darwin_amd64_SHA256SUM=c20d87c88ea8c22ba83fcbc4da136326c9933d93ae37790fbfc2b5e3a3593c1e
kyverno_darwin_arm64_SHA256SUM=bcfaf4056494d1f4e1387bdbd6350a7ba79f8596480697f633a374c66dd3c760

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

yq_linux_amd64_SHA256SUM=0c4d965ea944b64b8fddaf7f27779ee3034e5693263786506ccd1c120f184e8c
yq_linux_arm64_SHA256SUM=4c2cc022a129be5cc1187959bb4b09bebc7fb543c5837b93001c68f97ce39a5d
yq_darwin_amd64_SHA256SUM=d72a75fe9953c707d395f653d90095b133675ddd61aa738e1ac9a73c6c05e8be
yq_darwin_arm64_SHA256SUM=6bfa43a439936644d63c70308832390c8838290d064970eaada216219c218a13

.PRECIOUS: $(DOWNLOAD_DIR)/tools/yq@$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/yq@$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/mikefarah/yq/releases/download/$(YQ_VERSION)/yq_$(HOST_OS)_$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(yq_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

ko_linux_amd64_SHA256SUM=048ab11818089a43b7b74bc554494a79a3fd0d9822c061142e5cd3cf8b30cb27
ko_linux_arm64_SHA256SUM=9a26698876892128952fa3d038a4e99bea961d0d225865c60474b79e3db12e99
ko_darwin_amd64_SHA256SUM=0e0dd8fddbefebb8572ece4dca8f07a7472de862fedd7e9845fd9d651e0d5dbe
ko_darwin_arm64_SHA256SUM=752a639e0fbc013a35a43974b5ed87e7008bc2aee4952dfd2cc19f0013205492

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

protoc_linux_amd64_SHA256SUM=24e58fb231d50306ee28491f33a170301e99540f7e29ca461e0e80fd1239f8d1
protoc_linux_arm64_SHA256SUM=2b0fcf9b2c32cbadccc0eb7a88b841fffecd4a06fc80acdba2b5be45e815c38a
protoc_darwin_amd64_SHA256SUM=7f31625f8bec4929082ae9209e101c1c03692624457cc6332f83736db495ee92
protoc_darwin_arm64_SHA256SUM=7084c6482e3bb416a33fe2162ba566711773b842e6953bf6cb181647b9ef57c0

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

trivy_linux_amd64_SHA256SUM=dd93975bc1e58053810a9bafea89923e5df42ddd3f99905fdf840fd797145157
trivy_linux_arm64_SHA256SUM=7a98c13e6c5799fc46219c94fa500b807532b4555501cce85fa4eead9f755516
trivy_darwin_amd64_SHA256SUM=1054f37ba02173a7e1a05e2bcc1179d7573124cea1502a37cc59de89582de307
trivy_darwin_arm64_SHA256SUM=ae5ce4a7b9bf2bd3794ccb3c257993526fa47470b3814d729a73788d36aff3d0

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

ytt_linux_amd64_SHA256SUM=2e4986f44f3908a0a220b645587eab4d0ec70ff4a6818ca26d3a44e29e25f13c
ytt_linux_arm64_SHA256SUM=f4922e95801bc2b9b4baf553d4650b9300670e2821e20690026f1bfd78cf8cd5
ytt_darwin_amd64_SHA256SUM=37fb4c7528e025582bc74a0692dded61f85e9192ddf4263fdebdeb8c7cd82660
ytt_darwin_arm64_SHA256SUM=403dcbd6fef85bf40a086348f25c0ae3a817ad761755df4fe8cf5276dad18995

.PRECIOUS: $(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) -sSfL https://github.com/vmware-tanzu/carvel-ytt/releases/download/$(YTT_VERSION)/ytt-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(ytt_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

rclone_linux_amd64_SHA256SUM=2a69bf23b6e937b03f4b6f71e97154543d81610b2e5d209e9a2b96b1f9c2d803
rclone_linux_arm64_SHA256SUM=4e361cc6a5bd29ce157bb60f3d4579d8b323c8c0e3643f226549cf0c050a5fa5
rclone_darwin_amd64_SHA256SUM=07a6b81920be1cb6f1512c57e814d4add59bb5859755529eed504ab9feeae7b2
rclone_darwin_arm64_SHA256SUM=9efe8f1c147be5150950956a087e44670407bbab1c71df9d7dc4e23d69a77e3e

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

istioctl_linux_amd64_SHA256SUM=48d8bbe5879b121d47a553d5fbe55c19d53cfaecaa0634c86366da72ced38ac2
istioctl_linux_arm64_SHA256SUM=6e364e372d99886631e6f841c314d13abd549a7c5be1f89417c13f0dd6fbc4a1
istioctl_darwin_amd64_SHA256SUM=028a6d8d0c054c87ceefc47e8269a71136f26e9221339e471b73da5dde1d6929
istioctl_darwin_arm64_SHA256SUM=748da8498069348065611a7b38132e3f43cd4851b8b8f35c59531f38de944410

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

preflight_linux_amd64_SHA256SUM=09269abbd18746c07efdc5b3d34967ed28e697649fab614bad7746bc3cf06963
preflight_linux_arm64_SHA256SUM=e615bb2d45b81844d71b3901fd89d41ede16fe1080712dd431d1e7d98dcda7bf
preflight_darwin_amd64_SHA256SUM=e26589c1770482e017dfa73d9080a74aaeb0ecf65da7360ae87917e51bb42cf7
preflight_darwin_arm64_SHA256SUM=3c71d0e10cc09f3f53d664de78b5e671cbfd4a2088376f6e77234552d6f8acc8

.PRECIOUS: $(DOWNLOAD_DIR)/tools/preflight@$(PREFLIGHT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/preflight@$(PREFLIGHT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/redhat-openshift-ecosystem/openshift-preflight/releases/download/$(PREFLIGHT_VERSION)/preflight-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(preflight_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

operator-sdk_linux_amd64_SHA256SUM=5b730c233dbc8da816dde11ac96ff538929cb9a11aca93cb98d68fe63e89303a
operator-sdk_linux_arm64_SHA256SUM=36ccecbfe6b4f22ca13bb6ae32d5f131f845357b51cabc01381a98a245ea8a37
operator-sdk_darwin_amd64_SHA256SUM=2a2b03ae4e54d6e7fba42f89b7bdb366cf76ad33ce39967bde5775fbd0c0dba8
operator-sdk_darwin_arm64_SHA256SUM=57d68ba70d8db64bc7f5bfa754623e0a08f81f85104254aff3774fd3baf88662

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
