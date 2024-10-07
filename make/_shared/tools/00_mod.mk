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
tools += helm=v3.15.4
# https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl
tools += kubectl=v1.31.0
# https://github.com/kubernetes-sigs/kind/releases
tools += kind=v0.24.0
# https://www.vaultproject.io/downloads
tools += vault=1.17.3
# https://github.com/Azure/azure-workload-identity/releases
tools += azwi=v1.3.0
# https://github.com/kyverno/kyverno/releases
tools += kyverno=v1.12.5
# https://github.com/mikefarah/yq/releases
tools += yq=v4.44.3
# https://github.com/ko-build/ko/releases
tools += ko=0.16.0
# https://github.com/protocolbuffers/protobuf/releases
tools += protoc=27.3
# https://github.com/aquasecurity/trivy/releases
tools += trivy=v0.54.1
# https://github.com/vmware-tanzu/carvel-ytt/releases
tools += ytt=v0.50.0
# https://github.com/rclone/rclone/releases
tools += rclone=v1.67.0

### go packages
# https://pkg.go.dev/sigs.k8s.io/controller-tools/cmd/controller-gen?tab=versions
tools += controller-gen=v0.16.1
# https://pkg.go.dev/golang.org/x/tools/cmd/goimports?tab=versions
tools += goimports=v0.24.0
# https://pkg.go.dev/github.com/google/go-licenses/licenses?tab=versions
tools += go-licenses=706b9c60edd424a8b6d253fe10dfb7b8e942d4a5
# https://pkg.go.dev/gotest.tools/gotestsum?tab=versions
tools += gotestsum=v1.12.0
# https://pkg.go.dev/sigs.k8s.io/kustomize/kustomize/v4?tab=versions
tools += kustomize=v4.5.7
# https://pkg.go.dev/github.com/itchyny/gojq?tab=versions
tools += gojq=v0.12.16
# https://pkg.go.dev/github.com/google/go-containerregistry/pkg/crane?tab=versions
tools += crane=v0.20.2
# https://pkg.go.dev/google.golang.org/protobuf/cmd/protoc-gen-go?tab=versions
tools += protoc-gen-go=v1.34.2
# https://pkg.go.dev/github.com/norwoodj/helm-docs/cmd/helm-docs?tab=versions
tools += helm-docs=v1.14.2
# https://pkg.go.dev/github.com/sigstore/cosign/v2/cmd/cosign?tab=versions
tools += cosign=v2.4.0
# https://pkg.go.dev/github.com/cert-manager/boilersuite?tab=versions
tools += boilersuite=v0.1.0
# https://pkg.go.dev/github.com/princjef/gomarkdoc/cmd/gomarkdoc?tab=versions
tools += gomarkdoc=v1.1.0
# https://pkg.go.dev/oras.land/oras/cmd/oras?tab=versions
tools += oras=v1.2.0
# https://pkg.go.dev/github.com/onsi/ginkgo/v2/ginkgo?tab=versions
# The gingko version should be kept in sync with the version used in code.
# If there is no go.mod file (which is only the case for the makefile-modules
# repo), then we default to a version that we know exists. We have to do this
# because otherwise the awk failure renders the whole makefile unusable.
detected_ginkgo_version := $(shell [[ -f go.mod ]] && awk '/ginkgo\/v2/ {print $$2}' go.mod || echo "v2.13.2")
tools += ginkgo=$(detected_ginkgo_version)
# https://pkg.go.dev/github.com/cert-manager/klone?tab=versions
tools += klone=v0.1.0
# https://pkg.go.dev/github.com/goreleaser/goreleaser?tab=versions
tools += goreleaser=v1.26.2
# https://pkg.go.dev/github.com/anchore/syft/cmd/syft?tab=versions
tools += syft=v0.100.0
# https://github.com/cert-manager/helm-tool
tools += helm-tool=v0.5.3
# https://github.com/cert-manager/cmctl
tools += cmctl=v2.1.0
# https://pkg.go.dev/github.com/cert-manager/release/cmd/cmrel?tab=versions
tools += cmrel=e4c3a4dc07df5c7c0379d334c5bb00e172462551
# https://github.com/golangci/golangci-lint/releases
tools += golangci-lint=v1.61.0
# https://pkg.go.dev/golang.org/x/vuln?tab=versions
tools += govulncheck=v1.1.3
# https://pkg.go.dev/github.com/operator-framework/operator-sdk/cmd/operator-sdk?tab=versions
tools += operator-sdk=v1.36.1
# https://pkg.go.dev/github.com/cli/cli/v2?tab=versions
tools += gh=v2.54.0
# https:///github.com/redhat-openshift-ecosystem/openshift-preflight/releases
tools += preflight=1.10.0
# https://github.com/daixiang0/gci/releases
tools += gci=v0.13.4
# https://github.com/google/yamlfmt/releases
tools += yamlfmt=v0.13.0

# https://pkg.go.dev/k8s.io/code-generator/cmd?tab=versions
K8S_CODEGEN_VERSION := v0.31.0
tools += client-gen=$(K8S_CODEGEN_VERSION)
tools += deepcopy-gen=$(K8S_CODEGEN_VERSION)
tools += informer-gen=$(K8S_CODEGEN_VERSION)
tools += lister-gen=$(K8S_CODEGEN_VERSION)
tools += applyconfiguration-gen=$(K8S_CODEGEN_VERSION)
tools += defaulter-gen=$(K8S_CODEGEN_VERSION)
tools += conversion-gen=$(K8S_CODEGEN_VERSION)
# https://github.com/kubernetes/kube-openapi
tools += openapi-gen=91dab695df6fb4696a1ea93e510a5a4c6d10d369

# https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/master/envtest-releases.yaml
KUBEBUILDER_ASSETS_VERSION := v1.31.0
tools += etcd=$(KUBEBUILDER_ASSETS_VERSION)
tools += kube-apiserver=$(KUBEBUILDER_ASSETS_VERSION)

# Additional tools can be defined to reuse the tooling in this file
ADDITIONAL_TOOLS ?=
tools += $(ADDITIONAL_TOOLS)

# https://go.dev/dl/
VENDORED_GO_VERSION := 1.23.2

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

upper_map := a:A b:B c:C d:D e:E f:F g:G h:H i:I j:J k:K l:L m:M n:N o:O p:P q:Q r:R s:S t:T u:U v:V w:W x:X y:Y z:Z
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

$$(bin_dir)/tools/$1: $$(bin_dir)/scratch/$(call uc,$1)_VERSION | $$(DOWNLOAD_DIR)/tools/$1@$$($(call uc,$1)_VERSION)_$$(HOST_OS)_$$(HOST_ARCH) $$(bin_dir)/tools
	@cd $$(dir $$@) && $$(LN) $$(patsubst $$(bin_dir)/%,../%,$$(word 1,$$|)) $$(notdir $$@)
	@touch $$@ # making sure the target of the symlink is newer than *_VERSION
endef

$(foreach tool,$(tools),$(eval $(call tool_defs,$(word 1,$(subst =, ,$(tool))),$(word 2,$(subst =, ,$(tool))))))

tools_paths := $(tool_names:%=$(bin_dir)/tools/%)

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

go_dependencies :=
go_dependencies += ginkgo=github.com/onsi/ginkgo/v2/ginkgo
go_dependencies += controller-gen=sigs.k8s.io/controller-tools/cmd/controller-gen
go_dependencies += goimports=golang.org/x/tools/cmd/goimports
go_dependencies += go-licenses=github.com/google/go-licenses
go_dependencies += gotestsum=gotest.tools/gotestsum
go_dependencies += kustomize=sigs.k8s.io/kustomize/kustomize/v4
go_dependencies += gojq=github.com/itchyny/gojq/cmd/gojq
go_dependencies += crane=github.com/google/go-containerregistry/cmd/crane
go_dependencies += protoc-gen-go=google.golang.org/protobuf/cmd/protoc-gen-go
go_dependencies += helm-docs=github.com/norwoodj/helm-docs/cmd/helm-docs
go_dependencies += cosign=github.com/sigstore/cosign/v2/cmd/cosign
go_dependencies += boilersuite=github.com/cert-manager/boilersuite
go_dependencies += gomarkdoc=github.com/princjef/gomarkdoc/cmd/gomarkdoc
go_dependencies += oras=oras.land/oras/cmd/oras
go_dependencies += klone=github.com/cert-manager/klone
go_dependencies += goreleaser=github.com/goreleaser/goreleaser
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
go_dependencies += cmctl=github.com/cert-manager/cmctl/v2
go_dependencies += cmrel=github.com/cert-manager/release/cmd/cmrel
go_dependencies += golangci-lint=github.com/golangci/golangci-lint/cmd/golangci-lint
go_dependencies += govulncheck=golang.org/x/vuln/cmd/govulncheck
go_dependencies += operator-sdk=github.com/operator-framework/operator-sdk/cmd/operator-sdk
go_dependencies += gh=github.com/cli/cli/v2/cmd/gh
go_dependencies += gci=github.com/daixiang0/gci
go_dependencies += yamlfmt=github.com/google/yamlfmt/cmd/yamlfmt

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

define go_dependency
$$(DOWNLOAD_DIR)/tools/$1@$($(call uc,$1)_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $$(NEEDS_GO) $$(DOWNLOAD_DIR)/tools
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

go_linux_amd64_SHA256SUM=542d3c1705f1c6a1c5a80d5dc62e2e45171af291e755d591c5e6531ef63b454e
go_linux_arm64_SHA256SUM=f626cdd92fc21a88b31c1251f419c17782933a42903db87a174ce74eeecc66a9
go_darwin_amd64_SHA256SUM=445c0ef19d8692283f4c3a92052cc0568f5a048f4e546105f58e991d4aea54f5
go_darwin_arm64_SHA256SUM=d87031194fe3e01abdcaf3c7302148ade97a7add6eac3fec26765bcb3207b80f

.PRECIOUS: $(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz
$(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz: | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://go.dev/dl/go$(VENDORED_GO_VERSION).$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile); \
		$(checkhash_script) $(outfile) $(go_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)

helm_linux_amd64_SHA256SUM=11400fecfc07fd6f034863e4e0c4c4445594673fd2a129e701fe41f31170cfa9
helm_linux_arm64_SHA256SUM=fa419ecb139442e8a594c242343fafb7a46af3af34041c4eac1efcc49d74e626
helm_darwin_amd64_SHA256SUM=1bc3f354f7ce4d7fd9cfa5bcc701c1f32c88d27076d96c2792d5b5226062aee5
helm_darwin_arm64_SHA256SUM=88115846a1fb58f8eb8f64fec5c343d95ca394f1be811602fa54a887c98730ac

.PRECIOUS: $(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://get.helm.sh/helm-$(HELM_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(helm_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz $(HOST_OS)-$(HOST_ARCH)/helm > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).tar.gz

kubectl_linux_amd64_SHA256SUM=7c27adc64a84d1c0cc3dcf7bf4b6e916cc00f3f576a2dbac51b318d926032437
kubectl_linux_arm64_SHA256SUM=f42832db7d77897514639c6df38214a6d8ae1262ee34943364ec1ffaee6c009c
kubectl_darwin_amd64_SHA256SUM=fb6e07a69acc4e16885eda55b524c13b84bfbcf78cfac8d6c378d2bad321e105
kubectl_darwin_arm64_SHA256SUM=b7472df17a885574ed7273947a8a274c156357db21b981208e8e109b9ed4022d

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kubectl@$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kubectl@$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://dl.k8s.io/release/$(KUBECTL_VERSION)/bin/$(HOST_OS)/$(HOST_ARCH)/kubectl -o $(outfile); \
		$(checkhash_script) $(outfile) $(kubectl_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

kind_linux_amd64_SHA256SUM=b89aada5a39d620da3fcd16435b7f28d858927dd53f92cbac77686b0588b600d
kind_linux_arm64_SHA256SUM=2968808d916e12d0a25c56d07c9a1c987163f972513fa8a94a2125a69f9c50eb
kind_darwin_amd64_SHA256SUM=6cf7ba50b37d3446153bbfb8990f03fb8102778898c84502cdb841710b499ed5
kind_darwin_arm64_SHA256SUM=8e34f2edc7efc5c7c160487251848a954cd60ccd52b56a3fc360eaab33543fc0

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kind@$(KIND_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kind@$(KIND_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/kubernetes-sigs/kind/releases/download/$(KIND_VERSION)/kind-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(kind_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

vault_linux_amd64_SHA256SUM=146536fd9ef8aa1465894e718a8fe7a9ca13d68761bae900428f01f7ecd83806
vault_linux_arm64_SHA256SUM=6c7dc39df0058b1fa9e65050227cdb12dc7913153ecd56956911fb973c353590
vault_darwin_amd64_SHA256SUM=fd7e7c7a467723639cc0b624533a9f7aff0691bfbfe47602abac75af0be4914a
vault_darwin_arm64_SHA256SUM=26f11328a9c9e3b5599ec63efe394aed5fed0879c662f9ca320b8ec63d839582

.PRECIOUS: $(DOWNLOAD_DIR)/tools/vault@$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/vault@$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://releases.hashicorp.com/vault/$(VAULT_VERSION)/vault_$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH).zip -o $(outfile).zip; \
		$(checkhash_script) $(outfile).zip $(vault_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		unzip -qq -c $(outfile).zip > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).zip

azwi_linux_amd64_SHA256SUM=bbc84c7e5fcaf4c6e3e58064dc66b3b7f70f38a6d8f9cdd07f0669a8499bdd47
azwi_linux_arm64_SHA256SUM=7c4315ec8e21509641d90cf3160a379ae6ec771963df4bac0f18aa0a3ecef4ba
azwi_darwin_amd64_SHA256SUM=998dfaea81b652a5cbe92bb7dd3f770a391b8129f2a57137966d375c9f135062
azwi_darwin_arm64_SHA256SUM=b8a4a8ebcba2248b439f43c1d2431f469b023894b2f862879dc0999293dc1154

.PRECIOUS: $(DOWNLOAD_DIR)/tools/azwi@$(AZWI_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/azwi@$(AZWI_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/Azure/azure-workload-identity/releases/download/$(AZWI_VERSION)/azwi-$(AZWI_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(azwi_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz azwi > $(outfile) && chmod 775 $(outfile); \
		rm -f $(outfile).tar.gz

kubebuilder_tools_linux_amd64_SHA256SUM=b72c0c764c797e6b2cfd6d417abdad7b25d4fbc9f8475edeb44c8dd598999b76
kubebuilder_tools_linux_arm64_SHA256SUM=087123cfb6ac48a1002db19df7ee96949b54d34860805a41397bcb4cd0b5d5e4
kubebuilder_tools_darwin_amd64_SHA256SUM=e8a3bc6245dd30597aab163239337cd125194037ac13328798aa17b86aff0cb4
kubebuilder_tools_darwin_arm64_SHA256SUM=9f2d49e16368aa278adaf3802c7f3a3ca73560345e2634f9af13844a3936dc5b

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz
$(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz: | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/kubernetes-sigs/controller-tools/releases/download/envtest-$(KUBEBUILDER_ASSETS_VERSION)/envtest-$(KUBEBUILDER_ASSETS_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile); \
		$(checkhash_script) $(outfile) $(kubebuilder_tools_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)

$(DOWNLOAD_DIR)/tools/etcd@$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH): $(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		tar xfO $< controller-tools/envtest/etcd > $(outfile) && chmod 775 $(outfile)

$(DOWNLOAD_DIR)/tools/kube-apiserver@$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH): $(DOWNLOAD_DIR)/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		tar xfO $< controller-tools/envtest/kube-apiserver > $(outfile) && chmod 775 $(outfile)

kyverno_linux_amd64_SHA256SUM=962c396cdb149eadc7d6cc0cb345d3c01b6980d5265c8bb585c55ecd4b8a76b9
kyverno_linux_arm64_SHA256SUM=dd66d363656685af142ec2fcbaa8ff997951df3241b25a3dbe3eb890da124121
kyverno_darwin_amd64_SHA256SUM=f0053827f59aeed7e26b8ab578e9a86d9c002060414c442a46bfa8c49ac8280c
kyverno_darwin_arm64_SHA256SUM=4467e97fafa5a2067b93a5cbc954069ba00c890e3e867d0702b864ac7242ee0e

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kyverno@$(KYVERNO_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kyverno@$(KYVERNO_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval ARCH := $(subst amd64,x86_64,$(HOST_ARCH)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/kyverno/kyverno/releases/download/$(KYVERNO_VERSION)/kyverno-cli_$(KYVERNO_VERSION)_$(HOST_OS)_$(ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(kyverno_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz kyverno > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).tar.gz

yq_linux_amd64_SHA256SUM=a2c097180dd884a8d50c956ee16a9cec070f30a7947cf4ebf87d5f36213e9ed7
yq_linux_arm64_SHA256SUM=0e7e1524f68d91b3ff9b089872d185940ab0fa020a5a9052046ef10547023156
yq_darwin_amd64_SHA256SUM=216ddfa03e7ba0e5aba00b236ec78324b5bfc49b610db254fe92310878baea20
yq_darwin_arm64_SHA256SUM=559a594ef7a6ebc5b81a67b7717fb3accedd266d8fa7d8352da7fec9e463f48b

.PRECIOUS: $(DOWNLOAD_DIR)/tools/yq@$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/yq@$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/mikefarah/yq/releases/download/$(YQ_VERSION)/yq_$(HOST_OS)_$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(yq_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

ko_linux_amd64_SHA256SUM=aee2caeced511e60c6889a4cfaf9ebe28ec35acb49531b7a90b09e0a963bcff7
ko_linux_arm64_SHA256SUM=45b6ba20084b2199c63dcc738c54f7f6c37ea4e9c7f79eefc286d9947b11d0d1
ko_darwin_amd64_SHA256SUM=5c98d0229fd2a82cc69510705b74a7196fc184641693930b0f9282b6d1f79d95
ko_darwin_arm64_SHA256SUM=9c75b97f26ba98c62a86f3b39e2c74ced6c97092f301cd73fe4e5b3e16261698

.PRECIOUS: $(DOWNLOAD_DIR)/tools/ko@$(KO_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/ko@$(KO_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval OS := $(subst linux,Linux,$(subst darwin,Darwin,$(HOST_OS))))
	$(eval ARCH := $(subst amd64,x86_64,$(HOST_ARCH)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/ko-build/ko/releases/download/v$(KO_VERSION)/ko_$(KO_VERSION)_$(OS)_$(ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(ko_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz ko > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).tar.gz

protoc_linux_amd64_SHA256SUM=6dab2adab83f915126cab53540d48957c40e9e9023969c3e84d44bfb936c7741
protoc_linux_arm64_SHA256SUM=bdad36f3ad7472281d90568c4956ea2e203c216e0de005c6bd486f1920f2751c
protoc_darwin_amd64_SHA256SUM=ce282648fed0e7fbd6237d606dc9ec168dd2c1863889b04efa0b19c47da65d1b
protoc_darwin_arm64_SHA256SUM=b22116bd97cdbd7ea25346abe635a9df268515fe5ef5afa93cd9a68fc2513f84

.PRECIOUS: $(DOWNLOAD_DIR)/tools/protoc@$(PROTOC_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/protoc@$(PROTOC_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))
	$(eval ARCH := $(subst arm64,aarch_64,$(subst amd64,x86_64,$(HOST_ARCH))))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/protocolbuffers/protobuf/releases/download/v$(PROTOC_VERSION)/protoc-$(PROTOC_VERSION)-$(OS)-$(ARCH).zip -o $(outfile).zip; \
		$(checkhash_script) $(outfile).zip $(protoc_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		unzip -qq -c $(outfile).zip bin/protoc > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).zip

trivy_linux_amd64_SHA256SUM=bbaaf8278b2a9bb49aa848fe23c8bfe19f7db4f5dc7b55a9793357cd78cb5ec5
trivy_linux_arm64_SHA256SUM=26f8ee5a44ca027082c426d982ce95a37b88cf66defa1e982641eb4497bf1e99
trivy_darwin_amd64_SHA256SUM=d182c2de5496504120269b8d50b543e88b4837f8c9876055e54248f0a4e93d77
trivy_darwin_arm64_SHA256SUM=0ea077b074e38c3bce419d3cfaa417581c36e985beb9e571c06c01293158ff6f

.PRECIOUS: $(DOWNLOAD_DIR)/tools/trivy@$(TRIVY_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/trivy@$(TRIVY_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval OS := $(subst linux,Linux,$(subst darwin,macOS,$(HOST_OS))))
	$(eval ARCH := $(subst amd64,64bit,$(subst arm64,ARM64,$(HOST_ARCH))))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/aquasecurity/trivy/releases/download/$(TRIVY_VERSION)/trivy_$(patsubst v%,%,$(TRIVY_VERSION))_$(OS)-$(ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(trivy_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz trivy > $(outfile); \
		chmod +x $(outfile); \
		rm $(outfile).tar.gz

ytt_linux_amd64_SHA256SUM=61dec6e00131f990db853afc4b7531c318bd3af3ba18f2cfdbc0d5e83a45c445
ytt_linux_arm64_SHA256SUM=f38290c2666ddcf6feb4907f91033c4f41022b3fb84893c42d1f48948597b82a
ytt_darwin_amd64_SHA256SUM=d79f0b4189403c4142f5c646989de0769a316896a6096dfd1719605d313e8d1e
ytt_darwin_arm64_SHA256SUM=f3ce72031d34f0a3d909b1c971017bb3788bb786d3bb5cba1bf6d699255be643

.PRECIOUS: $(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) -sSfL https://github.com/vmware-tanzu/carvel-ytt/releases/download/$(YTT_VERSION)/ytt-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(ytt_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

rclone_linux_amd64_SHA256SUM=07c23d21a94d70113d949253478e13261c54d14d72023bb14d96a8da5f3e7722
rclone_linux_arm64_SHA256SUM=2b44981a1a7d1f432c53c0f2f0b6bcdd410f6491c47dc55428fdac0b85c763f1
rclone_darwin_amd64_SHA256SUM=1a1a3b080393b721ba5f38597305be2dbac3b654b43dfac3ebe4630b4e6406c3
rclone_darwin_arm64_SHA256SUM=4dc6142aea78bb86f1236fe38e570b715990503c09733418c0cd2300e45651e4

.PRECIOUS: $(DOWNLOAD_DIR)/tools/rclone@$(RCLONE_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/rclone@$(RCLONE_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/rclone/rclone/releases/download/$(RCLONE_VERSION)/rclone-$(RCLONE_VERSION)-$(OS)-$(HOST_ARCH).zip -o $(outfile).zip; \
		$(checkhash_script) $(outfile).zip $(rclone_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		unzip -p $(outfile).zip rclone-$(RCLONE_VERSION)-$(OS)-$(HOST_ARCH)/rclone > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).zip

preflight_linux_amd64_SHA256SUM=97750df31f31200f073e3b2844628a0a3681a403648c76d12319f83c80666104
preflight_linux_arm64_SHA256SUM=e12b2afe063c07ee75f69f285f8cc56be99b85e2abac99cbef5fb22b91ef0cb7

# Currently there are no official releases for darwin, you cannot submit results
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
		$(checkhash_script) $(outfile) $(preflight_linux_$(HOST_ARCH)_SHA256SUM); \
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

missing=$(shell (command -v curl >/dev/null || echo curl) \
             && (command -v sha256sum >/dev/null || command -v shasum >/dev/null || echo sha256sum) \
             && (command -v git >/dev/null || echo git) \
             && (command -v rsync >/dev/null || echo rsync) \
             && (command -v bash >/dev/null || echo bash))
ifneq ($(missing),)
$(error Missing required tools: $(missing))
endif

.PHONY: tools
## Download and setup all tools
## @category [shared] Tools
tools: $(tools_paths)
