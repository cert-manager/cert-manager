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

export DOWNLOAD_DIR ?= $(CURDIR)/$(bin_dir)/downloaded
export GOVENDOR_DIR ?= $(CURDIR)/$(bin_dir)/go_vendor

$(bin_dir)/scratch/image $(bin_dir)/tools $(DOWNLOAD_DIR)/tools:
	@mkdir -p $@

checkhash_script := $(dir $(lastword $(MAKEFILE_LIST)))/util/checkhash.sh
lock_script := $(dir $(lastword $(MAKEFILE_LIST)))/util/lock.sh

# $outfile is a variable in the lock script
outfile := $$outfile

for_each_kv = $(foreach item,$2,$(eval $(call $1,$(word 1,$(subst =, ,$(item))),$(word 2,$(subst =, ,$(item))))))

# To make sure we use the right version of each tool, we put symlink in
# $(bin_dir)/tools, and the actual binaries are in $(bin_dir)/downloaded. When bumping
# the version of the tools, this symlink gets updated.

# Let's have $(bin_dir)/tools in front of the PATH so that we don't inavertedly
# pick up the wrong binary somewhere. Watch out, $(shell echo $$PATH) will
# still print the original PATH, since GNU make does not honor exported
# variables: https://stackoverflow.com/questions/54726457
export PATH := $(CURDIR)/$(bin_dir)/tools:$(PATH)

CTR=docker

TOOLS :=
# https://github.com/helm/helm/releases
TOOLS += helm=v3.14.0
# https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl
TOOLS += kubectl=v1.29.1
# https://github.com/kubernetes-sigs/kind/releases
TOOLS += kind=v0.20.0
# https://www.vaultproject.io/downloads
TOOLS += vault=1.15.4
# https://github.com/Azure/azure-workload-identity/releases
TOOLS += azwi=v1.2.0
# https://github.com/kyverno/kyverno/releases
TOOLS += kyverno=v1.11.3
# https://github.com/mikefarah/yq/releases
TOOLS += yq=v4.43.1
# https://github.com/ko-build/ko/releases
TOOLS += ko=0.15.1
# https://github.com/protocolbuffers/protobuf/releases
TOOLS += protoc=25.2
# https://github.com/aquasecurity/trivy/releases
TOOLS += trivy=v0.45.0
# https://github.com/vmware-tanzu/carvel-ytt/releases
TOOLS += ytt=v0.45.4
# https://github.com/rclone/rclone/releases
TOOLS += rclone=v1.64.0

### go packages
# https://pkg.go.dev/sigs.k8s.io/controller-tools/cmd/controller-gen?tab=versions
TOOLS += controller-gen=v0.14.0
# https://pkg.go.dev/golang.org/x/tools/cmd/goimports?tab=versions
TOOLS += goimports=v0.17.0
# https://pkg.go.dev/github.com/google/go-licenses/licenses?tab=versions
TOOLS += go-licenses=706b9c60edd424a8b6d253fe10dfb7b8e942d4a5
# https://pkg.go.dev/gotest.tools/gotestsum?tab=versions
TOOLS += gotestsum=v1.11.0
# https://pkg.go.dev/sigs.k8s.io/kustomize/kustomize/v4?tab=versions
TOOLS += kustomize=v4.5.7
# https://pkg.go.dev/github.com/itchyny/gojq?tab=versions
TOOLS += gojq=v0.12.14
# https://pkg.go.dev/github.com/google/go-containerregistry/pkg/crane?tab=versions
TOOLS += crane=v0.18.0
# https://pkg.go.dev/google.golang.org/protobuf/cmd/protoc-gen-go?tab=versions
TOOLS += protoc-gen-go=v1.32.0
# https://pkg.go.dev/github.com/norwoodj/helm-docs/cmd/helm-docs?tab=versions
TOOLS += helm-docs=v1.12.0
# https://pkg.go.dev/github.com/sigstore/cosign/v2/cmd/cosign?tab=versions
TOOLS += cosign=v2.2.2
# https://pkg.go.dev/github.com/cert-manager/boilersuite?tab=versions
TOOLS += boilersuite=v0.1.0
# https://pkg.go.dev/github.com/princjef/gomarkdoc/cmd/gomarkdoc?tab=versions
TOOLS += gomarkdoc=v1.1.0
# https://pkg.go.dev/oras.land/oras/cmd/oras?tab=versions
TOOLS += oras=v1.1.0
# https://pkg.go.dev/github.com/onsi/ginkgo/v2/ginkgo?tab=versions
# The gingko version should be kept in sync with the version used in code.
# If there is no go.mod file (which is only the case for the makefile-modules
# repo), then we default to a version that we know exists. We have to do this
# because otherwise the awk failure renders the whole makefile unusable.
TOOLS += ginkgo=$(shell [[ -f go.mod ]] && awk '/ginkgo\/v2/ {print $$2}' go.mod || echo "v2.13.2")
# https://pkg.go.dev/github.com/cert-manager/klone?tab=versions
TOOLS += klone=v0.0.4
# https://pkg.go.dev/github.com/goreleaser/goreleaser?tab=versions
TOOLS += goreleaser=v1.23.0
# https://pkg.go.dev/github.com/anchore/syft/cmd/syft?tab=versions
TOOLS += syft=v0.100.0
# https://github.com/cert-manager/helm-tool
TOOLS += helm-tool=v0.4.2
# https://github.com/cert-manager/cmctl
TOOLS += cmctl=2f75014a7c360c319f8c7c8afe8e9ce33fe26dca
# https://pkg.go.dev/github.com/cert-manager/release/cmd/cmrel?tab=versions
TOOLS += cmrel=fa10147dadc8c36718b7b08aed6d8c6418eb2
# https://github.com/golangci/golangci-lint/releases
TOOLS += golangci-lint=v1.57.1
# https://pkg.go.dev/golang.org/x/vuln?tab=versions
TOOLS += govulncheck=v1.0.4
# https://pkg.go.dev/github.com/operator-framework/operator-sdk/cmd/operator-sdk?tab=versions
TOOLS += operator-sdk=v1.34.1
# https://pkg.go.dev/github.com/cli/cli/v2?tab=versions
TOOLS += gh=v2.47.0
# https:///github.com/redhat-openshift-ecosystem/openshift-preflight/releases
TOOLS += preflight=1.9.2

# https://pkg.go.dev/k8s.io/code-generator/cmd?tab=versions
K8S_CODEGEN_VERSION=v0.29.1
TOOLS += client-gen=$(K8S_CODEGEN_VERSION)
TOOLS += deepcopy-gen=$(K8S_CODEGEN_VERSION)
TOOLS += informer-gen=$(K8S_CODEGEN_VERSION)
TOOLS += lister-gen=$(K8S_CODEGEN_VERSION)
TOOLS += applyconfiguration-gen=$(K8S_CODEGEN_VERSION)
TOOLS += openapi-gen=$(K8S_CODEGEN_VERSION)
TOOLS += defaulter-gen=$(K8S_CODEGEN_VERSION)
TOOLS += conversion-gen=$(K8S_CODEGEN_VERSION)

# https://github.com/kubernetes-sigs/kubebuilder/blob/tools-releases/build/cloudbuild_tools.yaml
KUBEBUILDER_ASSETS_VERSION=1.29.0
TOOLS += etcd=$(KUBEBUILDER_ASSETS_VERSION)
TOOLS += kube-apiserver=$(KUBEBUILDER_ASSETS_VERSION)

# Additional tools can be defined to reuse the tooling in this file
ADDITIONAL_TOOLS ?=
TOOLS += $(ADDITIONAL_TOOLS)

# https://go.dev/dl/
VENDORED_GO_VERSION := 1.22.2

# Print the go version which can be used in GH actions
.PHONY: print-go-version
print-go-version:
	@echo result=$(VENDORED_GO_VERSION)

# When switching branches which use different versions of the tools, we
# need a way to re-trigger the symlinking from $(bin_dir)/downloaded to $(bin_dir)/tools.
$(bin_dir)/scratch/%_VERSION: FORCE | $(bin_dir)/scratch
	@test "$($*_VERSION)" == "$(shell cat $@ 2>/dev/null)" || echo $($*_VERSION) > $@

# --silent = don't print output like progress meters
# --show-error = but do print errors when they happen
# --fail = exit with a nonzero error code without the response from the server when there's an HTTP error
# --location = follow redirects from the server
# --retry = the number of times to retry a failed attempt to connect
# --retry-connrefused = retry even if the initial connection was refused
CURL = curl --silent --show-error --fail --location --retry 10 --retry-connrefused

# LN is expected to be an atomic action, meaning that two Make processes
# can run the "link $(DOWNLOAD_DIR)/tools/xxx@$(XXX_VERSION)_$(HOST_OS)_$(HOST_ARCH)
# to $(bin_dir)/tools/xxx" operation simulatiously without issues (both
# will perform the action and the second time the link will be overwritten).
LN := ln -fs

UC = $(shell echo '$1' | tr a-z A-Z)
LC = $(shell echo '$1' | tr A-Z a-z)

TOOL_NAMES :=

# for each item `xxx` in the TOOLS variable:
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
TOOL_NAMES += $1

$(call UC,$1)_VERSION ?= $2
NEEDS_$(call UC,$1) := $$(bin_dir)/tools/$1
$(call UC,$1) := $$(CURDIR)/$$(bin_dir)/tools/$1

$$(bin_dir)/tools/$1: $$(bin_dir)/scratch/$(call UC,$1)_VERSION | $$(DOWNLOAD_DIR)/tools/$1@$$($(call UC,$1)_VERSION)_$$(HOST_OS)_$$(HOST_ARCH) $$(bin_dir)/tools
	@cd $$(dir $$@) && $$(LN) $$(patsubst $$(bin_dir)/%,../%,$$(word 1,$$|)) $$(notdir $$@)
	@touch $$@ # making sure the target of the symlink is newer than *_VERSION
endef

$(foreach TOOL,$(TOOLS),$(eval $(call tool_defs,$(word 1,$(subst =, ,$(TOOL))),$(word 2,$(subst =, ,$(TOOL))))))

TOOLS_PATHS := $(TOOL_NAMES:%=$(bin_dir)/tools/%)

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
export NEEDS_GO ?= $(if $(findstring vendor-go,$(MAKECMDGOALS))$(shell [ -f $(bin_dir)/tools/go ] && echo yes), $(bin_dir)/tools/go,)
ifeq ($(NEEDS_GO),)
GO := go
else
export GOROOT := $(CURDIR)/$(bin_dir)/tools/goroot
export PATH := $(CURDIR)/$(bin_dir)/tools/goroot/bin:$(PATH)
GO := $(CURDIR)/$(bin_dir)/tools/go
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
	@cd $(dir $@) && $(LN) ./goroot/bin/go $(notdir $@)
	@touch $@ # making sure the target of the symlink is newer than *_VERSION

# The "_" in "_bin" prevents "go mod tidy" from trying to tidy the vendored goroot.
$(bin_dir)/tools/goroot: $(bin_dir)/scratch/VENDORED_GO_VERSION | $(GOVENDOR_DIR)/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH)/goroot $(bin_dir)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(bin_dir)/%,../%,$(word 1,$|)) $(notdir $@)
	@touch $@ # making sure the target of the symlink is newer than *_VERSION

# Extract the tar to the $(GOVENDOR_DIR) directory, this directory is not cached across CI runs.
$(GOVENDOR_DIR)/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH)/goroot: | $(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz
	@source $(lock_script) $@; \
		mkdir -p $(outfile).dir; \
		tar xzf $| -C $(outfile).dir; \
		mv $(outfile).dir/go $(outfile); \
		rm -rf $(outfile).dir

###################
# go dependencies #
###################

GO_DEPENDENCIES :=
GO_DEPENDENCIES += ginkgo=github.com/onsi/ginkgo/v2/ginkgo
GO_DEPENDENCIES += controller-gen=sigs.k8s.io/controller-tools/cmd/controller-gen
GO_DEPENDENCIES += goimports=golang.org/x/tools/cmd/goimports
GO_DEPENDENCIES += go-licenses=github.com/google/go-licenses
GO_DEPENDENCIES += gotestsum=gotest.tools/gotestsum
GO_DEPENDENCIES += kustomize=sigs.k8s.io/kustomize/kustomize/v4
GO_DEPENDENCIES += gojq=github.com/itchyny/gojq/cmd/gojq
GO_DEPENDENCIES += crane=github.com/google/go-containerregistry/cmd/crane
GO_DEPENDENCIES += protoc-gen-go=google.golang.org/protobuf/cmd/protoc-gen-go
GO_DEPENDENCIES += helm-docs=github.com/norwoodj/helm-docs/cmd/helm-docs
GO_DEPENDENCIES += cosign=github.com/sigstore/cosign/v2/cmd/cosign
GO_DEPENDENCIES += boilersuite=github.com/cert-manager/boilersuite
GO_DEPENDENCIES += gomarkdoc=github.com/princjef/gomarkdoc/cmd/gomarkdoc
GO_DEPENDENCIES += oras=oras.land/oras/cmd/oras
GO_DEPENDENCIES += klone=github.com/cert-manager/klone
GO_DEPENDENCIES += goreleaser=github.com/goreleaser/goreleaser
GO_DEPENDENCIES += syft=github.com/anchore/syft/cmd/syft
GO_DEPENDENCIES += client-gen=k8s.io/code-generator/cmd/client-gen
GO_DEPENDENCIES += deepcopy-gen=k8s.io/code-generator/cmd/deepcopy-gen
GO_DEPENDENCIES += informer-gen=k8s.io/code-generator/cmd/informer-gen
GO_DEPENDENCIES += lister-gen=k8s.io/code-generator/cmd/lister-gen
GO_DEPENDENCIES += applyconfiguration-gen=k8s.io/code-generator/cmd/applyconfiguration-gen
GO_DEPENDENCIES += openapi-gen=k8s.io/code-generator/cmd/openapi-gen
GO_DEPENDENCIES += defaulter-gen=k8s.io/code-generator/cmd/defaulter-gen
GO_DEPENDENCIES += conversion-gen=k8s.io/code-generator/cmd/conversion-gen
GO_DEPENDENCIES += helm-tool=github.com/cert-manager/helm-tool
GO_DEPENDENCIES += cmctl=github.com/cert-manager/cmctl/v2
GO_DEPENDENCIES += cmrel=github.com/cert-manager/release/cmd/cmrel
GO_DEPENDENCIES += golangci-lint=github.com/golangci/golangci-lint/cmd/golangci-lint
GO_DEPENDENCIES += govulncheck=golang.org/x/vuln/cmd/govulncheck
GO_DEPENDENCIES += operator-sdk=github.com/operator-framework/operator-sdk/cmd/operator-sdk
GO_DEPENDENCIES += gh=github.com/cli/cli/v2/cmd/gh

#################
# go build tags #
#################

GO_TAGS :=

# Additional Go dependencies can be defined to re-use the tooling in this file
ADDITIONAL_GO_DEPENDENCIES ?=
ADDITIONAL_GO_TAGS ?=
GO_DEPENDENCIES += $(ADDITIONAL_GO_DEPENDENCIES)
GO_TAGS += $(ADDITIONAL_GO_TAGS)

go_tags_init = go_tags_$1 :=
$(call for_each_kv,go_tags_init,$(GO_DEPENDENCIES))

go_tags_defs = go_tags_$1 += $2
$(call for_each_kv,go_tags_defs,$(GO_TAGS))

define go_dependency
$$(DOWNLOAD_DIR)/tools/$1@$($(call UC,$1)_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $$(NEEDS_GO) $$(DOWNLOAD_DIR)/tools
	@source $$(lock_script) $$@; \
		mkdir -p $$(outfile).dir; \
		GOWORK=off GOBIN=$$(outfile).dir $$(GO) install --tags "$(strip $(go_tags_$1))" $2@$($(call UC,$1)_VERSION); \
		mv $$(outfile).dir/$1 $$(outfile); \
		rm -rf $$(outfile).dir
endef
$(call for_each_kv,go_dependency,$(GO_DEPENDENCIES))

##################
# File downloads #
##################

GO_linux_amd64_SHA256SUM=5901c52b7a78002aeff14a21f93e0f064f74ce1360fce51c6ee68cd471216a17
GO_linux_arm64_SHA256SUM=4d169d9cf3dde1692b81c0fd9484fa28d8bc98f672d06bf9db9c75ada73c5fbc
GO_darwin_amd64_SHA256SUM=c0599a349b8d4a1afa3a1721478bb21136ab96c0d75b5f0a0b5fdc9e3b736880
GO_darwin_arm64_SHA256SUM=3411600bd7596c57ae29cfdb4978e5d45cafa3f428a44a526ad5a2d5ad870506

.PRECIOUS: $(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz
$(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz: | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://go.dev/dl/go$(VENDORED_GO_VERSION).$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile); \
		$(checkhash_script) $(outfile) $(GO_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)

HELM_linux_amd64_SHA256SUM=f43e1c3387de24547506ab05d24e5309c0ce0b228c23bd8aa64e9ec4b8206651
HELM_linux_arm64_SHA256SUM=b29e61674731b15f6ad3d1a3118a99d3cc2ab25a911aad1b8ac8c72d5a9d2952
HELM_darwin_amd64_SHA256SUM=804586896496f7b3da97f56089ea00f220e075e969b6fdf6c0b7b9cdc22de120
HELM_darwin_arm64_SHA256SUM=c2f36f3289a01c7c93ca11f84d740a170e0af1d2d0280bd523a409a62b8dfa1d

.PRECIOUS: $(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://get.helm.sh/helm-$(HELM_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(HELM_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz $(HOST_OS)-$(HOST_ARCH)/helm > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).tar.gz

KUBECTL_linux_amd64_SHA256SUM=69ab3a931e826bf7ac14d38ba7ca637d66a6fcb1ca0e3333a2cafdf15482af9f
KUBECTL_linux_arm64_SHA256SUM=96d6dc7b2bdcd344ce58d17631c452225de5bbf59b83fd3c89c33c6298fb5d8b
KUBECTL_darwin_amd64_SHA256SUM=c4da86e5c0fc9415db14a48d9ef1515b0b472346cbc9b7f015175b6109505d2c
KUBECTL_darwin_arm64_SHA256SUM=c31b99d7bf0faa486a6554c5f96e36af4821a488e90176a12ba18298bc4c8fb0

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kubectl@$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kubectl@$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://dl.k8s.io/release/$(KUBECTL_VERSION)/bin/$(HOST_OS)/$(HOST_ARCH)/kubectl -o $(outfile); \
		$(checkhash_script) $(outfile) $(KUBECTL_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

KIND_linux_amd64_SHA256SUM=513a7213d6d3332dd9ef27c24dab35e5ef10a04fa27274fe1c14d8a246493ded
KIND_linux_arm64_SHA256SUM=639f7808443559aa30c3642d9913b1615d611a071e34f122340afeda97b8f422
KIND_darwin_amd64_SHA256SUM=bffd8fb2006dc89fa0d1dde5ba6bf48caacb707e4df8551528f49145ebfeb7ad
KIND_darwin_arm64_SHA256SUM=8df041a5cae55471f3b039c3c9942226eb909821af63b5677fc80904caffaabf

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kind@$(KIND_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kind@$(KIND_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools $(bin_dir)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/kubernetes-sigs/kind/releases/download/$(KIND_VERSION)/kind-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(KIND_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

VAULT_linux_amd64_SHA256SUM=f42f550713e87cceef2f29a4e2b754491697475e3d26c0c5616314e40edd8e1b
VAULT_linux_arm64_SHA256SUM=79aee168078eb8c0dbb31c283e1136a7575f59fe36fccbb1f1ef6a16e0b67fdb
VAULT_darwin_amd64_SHA256SUM=a9d7c6e76d7d5c9be546e9a74860b98db6486fc0df095d8b00bc7f63fb1f6c1c
VAULT_darwin_arm64_SHA256SUM=4bf594a231bef07fbcfbf7329c8004acb8d219ce6a7aff186e0bac7027a0ab25

.PRECIOUS: $(DOWNLOAD_DIR)/tools/vault@$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/vault@$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://releases.hashicorp.com/vault/$(VAULT_VERSION)/vault_$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH).zip -o $(outfile).zip; \
		$(checkhash_script) $(outfile).zip $(VAULT_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		unzip -qq -c $(outfile).zip > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).zip

AZWI_linux_amd64_SHA256SUM=d2ef0f27609b7157595fe62b13c03381a481f833c1e1b6290df560454890d337
AZWI_linux_arm64_SHA256SUM=72e34bc96611080095e90ecce58a72e50debf846106b13976f2972bf06ae12df
AZWI_darwin_amd64_SHA256SUM=2be5f18c0acfb213a22db5a149dd89c7d494690988cb8e8a785dd6915f7094d0
AZWI_darwin_arm64_SHA256SUM=d0b01768102dd472c72c98bb51ae990af8779e811c9f7ab1db48ccefc9988f4c

.PRECIOUS: $(DOWNLOAD_DIR)/tools/azwi@$(AZWI_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/azwi@$(AZWI_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/Azure/azure-workload-identity/releases/download/$(AZWI_VERSION)/azwi-$(AZWI_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(AZWI_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz azwi > $(outfile) && chmod 775 $(outfile); \
		rm -f $(outfile).tar.gz

KUBEBUILDER_TOOLS_linux_amd64_SHA256SUM=e9899574fb92fd4a4ca27539d15a30f313f8a482b61b46cb874a07f2ba4f9bcb
KUBEBUILDER_TOOLS_linux_arm64_SHA256SUM=ef22e16c439b45f3e116498f7405be311bab92c3345766ab2142e86458cda92e
KUBEBUILDER_TOOLS_darwin_amd64_SHA256SUM=e5796637cc8e40029f0def639bbe7d99193c1872555c919d2b76c32e0e34378f
KUBEBUILDER_TOOLS_darwin_arm64_SHA256SUM=9734b90206f17a46f4dd0a7e3bb107d44aec9e79b7b135c6eb7c8a250ffd5e03

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz
$(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz: | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-$(KUBEBUILDER_ASSETS_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile); \
		$(checkhash_script) $(outfile) $(KUBEBUILDER_TOOLS_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)

$(DOWNLOAD_DIR)/tools/etcd@$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH): $(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		tar xfO $< kubebuilder/bin/etcd > $(outfile) && chmod 775 $(outfile)

$(DOWNLOAD_DIR)/tools/kube-apiserver@$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH): $(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		tar xfO $< kubebuilder/bin/kube-apiserver > $(outfile) && chmod 775 $(outfile)

KYVERNO_linux_amd64_SHA256SUM=08cf3640b847e3bbd41c5014ece4e0aa6c39915f5c199eeac8d80267955676e6
KYVERNO_linux_arm64_SHA256SUM=31805a52e98733b390c60636f209e0bda3174bd09e764ba41fa971126b98d2fc
KYVERNO_darwin_amd64_SHA256SUM=21fa0733d1a73d510fa0e30ac10310153b7124381aa21224b54fe34a38239542
KYVERNO_darwin_arm64_SHA256SUM=022bc2640f05482cab290ca8cd28a67f55b24c14b93076bd144c37a1732e6d7e

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kyverno@$(KYVERNO_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kyverno@$(KYVERNO_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval ARCH := $(subst amd64,x86_64,$(HOST_ARCH)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/kyverno/kyverno/releases/download/$(KYVERNO_VERSION)/kyverno-cli_$(KYVERNO_VERSION)_$(HOST_OS)_$(ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(KYVERNO_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz kyverno > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).tar.gz

YQ_linux_amd64_SHA256SUM=cfbbb9ba72c9402ef4ab9d8f843439693dfb380927921740e51706d90869c7e1
YQ_linux_arm64_SHA256SUM=a8186efb079673293289f8c31ee252b0d533c7bb8b1ada6a778ddd5ec0f325b6
YQ_darwin_amd64_SHA256SUM=fdc42b132ac460037f4f0f48caea82138772c651d91cfbb735210075ddfdbaed
YQ_darwin_arm64_SHA256SUM=9f1063d910698834cb9176593aa288471898031929138d226c2c2de9f262f8e5

.PRECIOUS: $(DOWNLOAD_DIR)/tools/yq@$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/yq@$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/mikefarah/yq/releases/download/$(YQ_VERSION)/yq_$(HOST_OS)_$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(YQ_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

KO_linux_amd64_SHA256SUM=5b06079590371954cceadf0ddcfa8471afb039c29a2e971043915957366a2f39
KO_linux_arm64_SHA256SUM=fcbb736f7440d686ca1cf8b4c3f6b9b80948eb17d6cef7c14242eddd275cab42
KO_darwin_amd64_SHA256SUM=4f388a4b08bde612a20d799045a57a9b8847483baf1a1590d3c32735e7c30c16
KO_darwin_arm64_SHA256SUM=45f2c1a50fdadb7ef38abbb479897d735c95238ec25c4f505177d77d60ed91d6

.PRECIOUS: $(DOWNLOAD_DIR)/tools/ko@$(KO_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/ko@$(KO_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval OS := $(subst linux,Linux,$(subst darwin,Darwin,$(HOST_OS))))
	$(eval ARCH := $(subst amd64,x86_64,$(HOST_ARCH)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/ko-build/ko/releases/download/v$(KO_VERSION)/ko_$(KO_VERSION)_$(OS)_$(ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(KO_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz ko > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).tar.gz

PROTOC_linux_amd64_SHA256SUM=78ab9c3288919bdaa6cfcec6127a04813cf8a0ce406afa625e48e816abee2878
PROTOC_linux_arm64_SHA256SUM=07683afc764e4efa3fa969d5f049fbc2bdfc6b4e7786a0b233413ac0d8753f6b
PROTOC_darwin_amd64_SHA256SUM=5fe89993769616beff1ed77408d1335216379ce7010eee80284a01f9c87c8888
PROTOC_darwin_arm64_SHA256SUM=8822b090c396800c96ac652040917eb3fbc5e542538861aad7c63b8457934b20

.PRECIOUS: $(DOWNLOAD_DIR)/tools/protoc@$(PROTOC_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/protoc@$(PROTOC_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))
	$(eval ARCH := $(subst arm64,aarch_64,$(subst amd64,x86_64,$(HOST_ARCH))))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOC_VERSION)/protoc-$(PROTOC_VERSION)-$(OS)-$(ARCH).zip -o $(outfile).zip; \
		$(checkhash_script) $(outfile).zip $(PROTOC_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		unzip -qq -c $(outfile).zip bin/protoc > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).zip

TRIVY_linux_amd64_SHA256SUM=b9785455f711e3116c0a97b01ad6be334895143ed680a405e88a4c4c19830d5d
TRIVY_linux_arm64_SHA256SUM=a192edfcef8766fa7e3e96a6a5faf50cd861371785891857471548e4af7cb60b
TRIVY_darwin_amd64_SHA256SUM=997622dee1d07de0764f903b72d16ec4314daaf202d91c957137b4fd1a2f73c3
TRIVY_darwin_arm64_SHA256SUM=68aa451f395fa5418f5af59ce4081ef71075c857b95a297dc61da49c6a229a45

.PRECIOUS: $(DOWNLOAD_DIR)/tools/trivy@$(TRIVY_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/trivy@$(TRIVY_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval OS := $(subst linux,Linux,$(subst darwin,macOS,$(HOST_OS))))
	$(eval ARCH := $(subst amd64,64bit,$(subst arm64,ARM64,$(HOST_ARCH))))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/aquasecurity/trivy/releases/download/$(TRIVY_VERSION)/trivy_$(patsubst v%,%,$(TRIVY_VERSION))_$(OS)-$(ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(TRIVY_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz trivy > $(outfile); \
		chmod +x $(outfile); \
		rm $(outfile).tar.gz

YTT_linux_amd64_SHA256SUM=9bf62175c7cc0b54f9731a5b87ee40250f0457b1fce1b0b36019c2f8d96db8f8
YTT_linux_arm64_SHA256SUM=cbfc85f11ffd8e61d63accf799b8997caaebe46ee046290cc1c4d05ed1ab145b
YTT_darwin_amd64_SHA256SUM=2b6d173dec1b6087e22690386474786fd9a2232c4479d8975cc98ae8160eea76
YTT_darwin_arm64_SHA256SUM=3e6f092bfe7a121d15126a0de6503797818c6b6745fbc97213f519d35fab08f9

.PRECIOUS: $(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) -sSfL https://github.com/vmware-tanzu/carvel-ytt/releases/download/$(YTT_VERSION)/ytt-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(YTT_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

RCLONE_linux_amd64_SHA256SUM=7ebdb680e615f690bd52c661487379f9df8de648ecf38743e49fe12c6ace6dc7
RCLONE_linux_arm64_SHA256SUM=b5a6cb3aef4fd1a2165fb8c21b1b1705f3cb754a202adc81931b47cd39c64749
RCLONE_darwin_amd64_SHA256SUM=9ef83833296876f3182b87030b4f2e851b56621bad4ca4d7a14753553bb8b640
RCLONE_darwin_arm64_SHA256SUM=9183f495b28acb12c872175c6af1f6ba8ca677650cb9d2774caefea273294c8a

.PRECIOUS: $(DOWNLOAD_DIR)/tools/rclone@$(RCLONE_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/rclone@$(RCLONE_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/rclone/rclone/releases/download/$(RCLONE_VERSION)/rclone-$(RCLONE_VERSION)-$(OS)-$(HOST_ARCH).zip -o $(outfile).zip; \
		$(checkhash_script) $(outfile).zip $(RCLONE_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		unzip -p $(outfile).zip rclone-$(RCLONE_VERSION)-$(OS)-$(HOST_ARCH)/rclone > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).zip

PREFLIGHT_linux_amd64_SHA256SUM=20f31e4af2004e8e3407844afea4e973975069169d69794e0633f0cb91d45afd
PREFLIGHT_linux_arm64_SHA256SUM=c42cf4132027d937da88da07760e8fd9b1a8836f9c7795a1b60513d99c6939fe

# Currently there are no offical releases for darwin, you cannot submit results 
# on non-official binaries, but we can still run tests.
#
# Once https://github.com/redhat-openshift-ecosystem/openshift-preflight/pull/942 is merged
# we can remove this darwin specific hack
.PRECIOUS: $(DOWNLOAD_DIR)/tools/preflight@$(PREFLIGHT_VERSION)_darwin_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/preflight@$(PREFLIGHT_VERSION)_darwin_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		mkdir -p $(outfile).dir; \
		GOWORK=off GOBIN=$(outfile).dir $(GO) install github.com/redhat-openshift-ecosystem/openshift-preflight/cmd/preflight@$(PREFLIGHT_VERSION); \
		mv $(outfile).dir/preflight $(outfile); \
		rm -rf $(outfile).dir

.PRECIOUS: $(DOWNLOAD_DIR)/tools/preflight@$(PREFLIGHT_VERSION)_linux_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/preflight@$(PREFLIGHT_VERSION)_linux_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/redhat-openshift-ecosystem/openshift-preflight/releases/download/$(PREFLIGHT_VERSION)/preflight-linux-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(PREFLIGHT_linux_$(HOST_ARCH)_SHA256SUM); \
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

MISSING=$(shell (command -v curl >/dev/null || echo curl) \
             && (command -v sha256sum >/dev/null || command -v shasum >/dev/null || echo sha256sum) \
             && (command -v git >/dev/null || echo git) \
             && (command -v rsync >/dev/null || echo rsync) \
             && ([ -n "$(findstring vendor-go,$(MAKECMDGOALS),)" ] \
                || command -v $(GO) >/dev/null || echo "$(GO) (or run 'make vendor-go')") \
             && (command -v $(CTR) >/dev/null || echo "$(CTR) (or set CTR to a docker-compatible tool)"))
ifneq ($(MISSING),)
$(error Missing required tools: $(MISSING))
endif

.PHONY: tools
## Download and setup all tools
## @category [shared] Tools
tools: $(TOOLS_PATHS)

self_file := $(dir $(lastword $(MAKEFILE_LIST)))/00_mod.mk

# This target is used to learn the sha256sum of the tools. It is used only
# in the makefile-modules repo, and should not be used in any other repo.
.PHONY: tools-learn-sha
tools-learn-sha: | $(bin_dir)
	rm -rf ./$(bin_dir)/
	mkdir -p ./$(bin_dir)/scratch/
	$(eval export LEARN_FILE=$(CURDIR)/$(bin_dir)/scratch/learn_tools_file)
	echo -n "" > "$(LEARN_FILE)"

	HOST_OS=linux HOST_ARCH=amd64 $(MAKE) tools
	HOST_OS=linux HOST_ARCH=arm64 $(MAKE) tools
	HOST_OS=darwin HOST_ARCH=amd64 $(MAKE) tools
	HOST_OS=darwin HOST_ARCH=arm64 $(MAKE) tools
	
	HOST_OS=linux HOST_ARCH=amd64 $(MAKE) vendor-go
	HOST_OS=linux HOST_ARCH=arm64 $(MAKE) vendor-go
	HOST_OS=darwin HOST_ARCH=amd64 $(MAKE) vendor-go
	HOST_OS=darwin HOST_ARCH=arm64 $(MAKE) vendor-go

	while read p; do \
		sed -i "$$p" $(self_file); \
	done <"$(LEARN_FILE)"
