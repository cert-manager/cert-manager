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
# renovate: datasource=github-releases packageName=helm/helm
tools += helm=v3.18.6
# https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl
# renovate: datasource=github-releases packageName=kubernetes/kubernetes
tools += kubectl=v1.34.0
# https://github.com/kubernetes-sigs/kind/releases
# renovate: datasource=github-releases packageName=kubernetes-sigs/kind
tools += kind=v0.30.0
# https://www.vaultproject.io/downloads
# renovate: datasource=github-releases packageName=hashicorp/vault
tools += vault=v1.20.3
# https://github.com/Azure/azure-workload-identity/releases
# renovate: datasource=github-releases packageName=Azure/azure-workload-identity
tools += azwi=v1.5.1
# https://github.com/kyverno/kyverno/releases
# renovate: datasource=github-releases packageName=kyverno/kyverno
tools += kyverno=v1.15.1
# https://github.com/mikefarah/yq/releases
# renovate: datasource=github-releases packageName=mikefarah/yq
tools += yq=v4.47.1
# https://github.com/ko-build/ko/releases
# renovate: datasource=github-releases packageName=ko-build/ko
tools += ko=0.18.0
# https://github.com/protocolbuffers/protobuf/releases
# renovate: datasource=github-releases packageName=protocolbuffers/protobuf
tools += protoc=32.0
# https://github.com/aquasecurity/trivy/releases
# renovate: datasource=github-releases packageName=aquasecurity/trivy
tools += trivy=v0.66.0
# https://github.com/vmware-tanzu/carvel-ytt/releases
# renovate: datasource=github-releases packageName=vmware-tanzu/carvel-ytt
tools += ytt=v0.52.0
# https://github.com/rclone/rclone/releases
# renovate: datasource=github-releases packageName=rclone/rclone
tools += rclone=v1.71.0
# https://github.com/istio/istio/releases
# renovate: datasource=github-releases packageName=istio/istio
tools += istioctl=1.27.1

### go packages
# https://pkg.go.dev/sigs.k8s.io/controller-tools/cmd/controller-gen?tab=versions
# renovate: datasource=go packageName=sigs.k8s.io/controller-tools
tools += controller-gen=v0.19.0
# https://pkg.go.dev/golang.org/x/tools/cmd/goimports?tab=versions
# renovate: datasource=go packageName=golang.org/x/tools
tools += goimports=v0.36.0
# https://pkg.go.dev/github.com/google/go-licenses/v2?tab=versions
# renovate: datasource=go packageName=github.com/inteon/go-licenses/v2
tools += go-licenses=v2.0.0-20250821024731-e4be79958780
# https://pkg.go.dev/gotest.tools/gotestsum?tab=versions
# renovate: datasource=github-releases packageName=gotestyourself/gotestsum
tools += gotestsum=v1.12.3
# https://pkg.go.dev/sigs.k8s.io/kustomize/kustomize/v5?tab=versions
# renovate: datasource=go packageName=sigs.k8s.io/kustomize/kustomize/v5
tools += kustomize=v5.7.1
# https://pkg.go.dev/github.com/itchyny/gojq?tab=versions
# renovate: datasource=go packageName=github.com/itchyny/gojq
tools += gojq=v0.12.17
# https://pkg.go.dev/github.com/google/go-containerregistry/pkg/crane?tab=versions
# renovate: datasource=go packageName=github.com/google/go-containerregistry
tools += crane=v0.20.6
# https://pkg.go.dev/google.golang.org/protobuf/cmd/protoc-gen-go?tab=versions
# renovate: datasource=go packageName=google.golang.org/protobuf
tools += protoc-gen-go=v1.36.8
# https://pkg.go.dev/github.com/sigstore/cosign/v2/cmd/cosign?tab=versions
# renovate: datasource=go packageName=github.com/sigstore/cosign/v2
tools += cosign=v2.5.3
# https://pkg.go.dev/github.com/cert-manager/boilersuite?tab=versions
# renovate: datasource=go packageName=github.com/cert-manager/boilersuite
tools += boilersuite=v0.1.0
# https://pkg.go.dev/github.com/princjef/gomarkdoc/cmd/gomarkdoc?tab=versions
# renovate: datasource=go packageName=github.com/princjef/gomarkdoc
tools += gomarkdoc=v1.1.0
# https://pkg.go.dev/oras.land/oras/cmd/oras?tab=versions
# renovate: datasource=go packageName=oras.land/oras
tools += oras=v1.2.3
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
tools += goreleaser=v2.12.0
# https://pkg.go.dev/github.com/anchore/syft/cmd/syft?tab=versions
# renovate: datasource=go packageName=github.com/anchore/syft
tools += syft=v1.32.0
# https://github.com/cert-manager/helm-tool/releases
# renovate: datasource=github-releases packageName=cert-manager/helm-tool
tools += helm-tool=v0.5.3
# https://github.com/cert-manager/image-tool/releases
# renovate: datasource=github-releases packageName=cert-manager/image-tool
tools += image-tool=v0.1.0
# https://github.com/cert-manager/cmctl/releases
# renovate: datasource=github-releases packageName=cert-manager/cmctl
tools += cmctl=v2.3.0
# https://pkg.go.dev/github.com/cert-manager/release/cmd/cmrel?tab=versions
# renovate: datasource=go packageName=github.com/cert-manager/release
tools += cmrel=v1.12.15-0.20241121151736-e3cbe5171488
# https://pkg.go.dev/github.com/golangci/golangci-lint/v2/cmd/golangci-lint?tab=versions
# renovate: datasource=go packageName=github.com/golangci/golangci-lint/v2
tools += golangci-lint=v2.4.0
# https://pkg.go.dev/golang.org/x/vuln?tab=versions
# renovate: datasource=go packageName=golang.org/x/vuln
tools += govulncheck=v1.1.4
# https://github.com/operator-framework/operator-sdk/releases
# renovate: datasource=github-releases packageName=operator-framework/operator-sdk
tools += operator-sdk=v1.41.1
# https://pkg.go.dev/github.com/cli/cli/v2?tab=versions
# renovate: datasource=go packageName=github.com/cli/cli/v2
tools += gh=v2.78.0
# https://github.com/redhat-openshift-ecosystem/openshift-preflight/releases
# renovate: datasource=github-releases packageName=redhat-openshift-ecosystem/openshift-preflight
tools += preflight=1.14.1
# https://github.com/daixiang0/gci/releases
# renovate: datasource=github-releases packageName=daixiang0/gci
tools += gci=v0.13.7
# https://github.com/google/yamlfmt/releases
# renovate: datasource=github-releases packageName=google/yamlfmt
tools += yamlfmt=v0.17.2
# https://github.com/yannh/kubeconform/releases
# renovate: datasource=github-releases packageName=yannh/kubeconform
tools += kubeconform=v0.7.0

# FIXME(erikgb): cert-manager needs the ability to override the version set here
# https://pkg.go.dev/k8s.io/code-generator/cmd?tab=versions
# renovate: datasource=go packageName=k8s.io/code-generator
K8S_CODEGEN_VERSION ?= v0.34.0
tools += client-gen=$(K8S_CODEGEN_VERSION)
tools += deepcopy-gen=$(K8S_CODEGEN_VERSION)
tools += informer-gen=$(K8S_CODEGEN_VERSION)
tools += lister-gen=$(K8S_CODEGEN_VERSION)
tools += applyconfiguration-gen=$(K8S_CODEGEN_VERSION)
tools += defaulter-gen=$(K8S_CODEGEN_VERSION)
tools += conversion-gen=$(K8S_CODEGEN_VERSION)
# https://github.com/kubernetes/kube-openapi
# renovate: datasource=go packageName=k8s.io/kube-openapi
tools += openapi-gen=v0.0.0-20250905212525-66792eed8611

# https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/master/envtest-releases.yaml
# FIXME: Find a way to configure Renovate to suggest upgrades
KUBEBUILDER_ASSETS_VERSION := v1.33.0
tools += etcd=$(KUBEBUILDER_ASSETS_VERSION)
tools += kube-apiserver=$(KUBEBUILDER_ASSETS_VERSION)

# Additional tools can be defined to reuse the tooling in this file
ADDITIONAL_TOOLS ?=
tools += $(ADDITIONAL_TOOLS)

# https://go.dev/dl/
# renovate: datasource=golang-version packageName=go
VENDORED_GO_VERSION := 1.25.1

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

define go_dependency
go_tool_names += $1
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

go_linux_amd64_SHA256SUM=7716a0d940a0f6ae8e1f3b3f4f36299dc53e31b16840dbd171254312c41ca12e
go_linux_arm64_SHA256SUM=65a3e34fb2126f55b34e1edfc709121660e1be2dee6bdf405fc399a63a95a87d
go_darwin_amd64_SHA256SUM=1d622468f767a1b9fe1e1e67bd6ce6744d04e0c68712adc689748bbeccb126bb
go_darwin_arm64_SHA256SUM=68deebb214f39d542e518ebb0598a406ab1b5a22bba8ec9ade9f55fb4dd94a6c

.PRECIOUS: $(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz
$(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz: | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://go.dev/dl/go$(VENDORED_GO_VERSION).$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile); \
		$(checkhash_script) $(outfile) $(go_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)

helm_linux_amd64_SHA256SUM=3f43c0aa57243852dd542493a0f54f1396c0bc8ec7296bbb2c01e802010819ce
helm_linux_arm64_SHA256SUM=5b8e00b6709caab466cbbb0bc29ee09059b8dc9417991dd04b497530e49b1737
helm_darwin_amd64_SHA256SUM=80cad0470e38cf25731cdead7c32dfbeb887bc177bd6fa01e31b065722f8f06b
helm_darwin_arm64_SHA256SUM=48e30d236a1f334c6acb78501be5a851eaa2a267fefeb1131b6484eb2f9f30d7

.PRECIOUS: $(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://get.helm.sh/helm-$(HELM_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(helm_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz $(HOST_OS)-$(HOST_ARCH)/helm > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).tar.gz

kubectl_linux_amd64_SHA256SUM=cfda68cba5848bc3b6c6135ae2f20ba2c78de20059f68789c090166d6abc3e2c
kubectl_linux_arm64_SHA256SUM=00b182d103a8a73da7a4d11e7526d0543dcf352f06cc63a1fde25ce9243f49a0
kubectl_darwin_amd64_SHA256SUM=a5904061dd5c8e57d55e52c78fa23790e76de30924b26ba31be891e75710d7a9
kubectl_darwin_arm64_SHA256SUM=d491f4c47c34856188d38e87a27866bd94a66a57b8db3093a82ae43baf3bb20d

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kubectl@$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kubectl@$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://dl.k8s.io/release/$(KUBECTL_VERSION)/bin/$(HOST_OS)/$(HOST_ARCH)/kubectl -o $(outfile); \
		$(checkhash_script) $(outfile) $(kubectl_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

kind_linux_amd64_SHA256SUM=517ab7fc89ddeed5fa65abf71530d90648d9638ef0c4cde22c2c11f8097b8889
kind_linux_arm64_SHA256SUM=7ea2de9d2d190022ed4a8a4e3ac0636c8a455e460b9a13ccf19f15d07f4f00eb
kind_darwin_amd64_SHA256SUM=4f0b6e3b88bdc66d922c08469f05ef507d4903dd236e6319199bb9c868eed274
kind_darwin_arm64_SHA256SUM=ceaf40df1d1551c481fb50e3deb5c3deecad5fd599df5469626b70ddf52a1518

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kind@$(KIND_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kind@$(KIND_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/kubernetes-sigs/kind/releases/download/$(KIND_VERSION)/kind-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(kind_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

vault_linux_amd64_SHA256SUM=128d35b82bed319b8ce3caec99286a7d458342d8def5e6ca4d20cc7621df53d3
vault_linux_arm64_SHA256SUM=35847f819eb3917f1b454994bd517bf4f83fdbd7e9a06fa17f37a7c99ab7eb9d
vault_darwin_amd64_SHA256SUM=c83250d6432a200f6fdbda3e648351858ea8754d20147a761fc85f40f4357d13
vault_darwin_arm64_SHA256SUM=134ca9433205d065180073f2e02c62558e4ee7d06115112189746991a40b8fde

.PRECIOUS: $(DOWNLOAD_DIR)/tools/vault@$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/vault@$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://releases.hashicorp.com/vault/$(VAULT_VERSION:v%=%)/vault_$(VAULT_VERSION:v%=%)_$(HOST_OS)_$(HOST_ARCH).zip -o $(outfile).zip; \
		$(checkhash_script) $(outfile).zip $(vault_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		unzip -qq -c $(outfile).zip > $(outfile); \
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

kubebuilder_tools_linux_amd64_SHA256SUM=3fb446463d20a6c4e093cb6a0facaae8bab966192a387624190fb15b34ce6abb
kubebuilder_tools_linux_arm64_SHA256SUM=56c0ab934591543b3decdf4e80a27dccccbfeeb59a1e6103ad0e935aacb34e74
kubebuilder_tools_darwin_amd64_SHA256SUM=c63643447f9a2ee23191a0b1f32d503a8bca6df7013dd4beb9eaae7088a1bea1
kubebuilder_tools_darwin_arm64_SHA256SUM=36a413216c7a2a11c2164eb8553a009a2997c383a6bf768cb5e3709bf36e4596

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

kyverno_linux_amd64_SHA256SUM=6b252750af3063e698f4d72cbf7599e8b292bd710248e23d0b1c8935e88aee67
kyverno_linux_arm64_SHA256SUM=de2a9398cd9d75747e0fd50ce824a31389663a0e50e62481ddf8f52a40172d24
kyverno_darwin_amd64_SHA256SUM=6875b5836f188b089fe4af6d3be8709a61ccad46d7e39febf06472df19d171f5
kyverno_darwin_arm64_SHA256SUM=a6a2a25b1d0ee1ea564cc3303434096f0313f45fdac1ec453b5f63586b2ebdfb

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kyverno@$(KYVERNO_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kyverno@$(KYVERNO_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval ARCH := $(subst amd64,x86_64,$(HOST_ARCH)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/kyverno/kyverno/releases/download/$(KYVERNO_VERSION)/kyverno-cli_$(KYVERNO_VERSION)_$(HOST_OS)_$(ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(kyverno_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz kyverno > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).tar.gz

yq_linux_amd64_SHA256SUM=0fb28c6680193c41b364193d0c0fc4a03177aecde51cfc04d506b1517158c2fb
yq_linux_arm64_SHA256SUM=b7f7c991abe262b0c6f96bbcb362f8b35429cefd59c8b4c2daa4811f1e9df599
yq_darwin_amd64_SHA256SUM=a9b5ca36f7750576c6ace3cc7193349cd676b3a6bf30193fb2773ff45f5af5c2
yq_darwin_arm64_SHA256SUM=99aae3a7c9ddfe76bb339f0e7acd8224324b6527436fb6a5d890079bf5fcc590

.PRECIOUS: $(DOWNLOAD_DIR)/tools/yq@$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/yq@$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/mikefarah/yq/releases/download/$(YQ_VERSION)/yq_$(HOST_OS)_$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(yq_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

ko_linux_amd64_SHA256SUM=ce8c8776b243357e0a822c279b06c34302460221e834765dee5f4e9e2c0b7b38
ko_linux_arm64_SHA256SUM=cf9abbdcc4fb7cf85f5e5ba029eba257ee98ef9410bcef94fae17056ec32bab5
ko_darwin_amd64_SHA256SUM=066013c67e6e4b7c5f7c1a6b3c93ba66989e47de435558ff7edb875608028668
ko_darwin_arm64_SHA256SUM=2efa5796986e38994a3a233641b98404fa071a76456e3c99b3c00df0436d5833

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

protoc_linux_amd64_SHA256SUM=7ca037bfe5e5cabd4255ccd21dd265f79eb82d3c010117994f5dc81d2140ee88
protoc_linux_arm64_SHA256SUM=56af3fc2e43a0230802e6fadb621d890ba506c5c17a1ae1070f685fe79ba12d0
protoc_darwin_amd64_SHA256SUM=63eeba15ddc12ab11b0a8bce81fb2d46cc69022c3e6ad21fecde90d52139bff6
protoc_darwin_arm64_SHA256SUM=09a2c729cc821215cc0d4c564b761760961fe338c52f24b302fd7e18e7b675d1

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

trivy_linux_amd64_SHA256SUM=93678741c3223c15120934ac00671ca7e797c9a5a4d89148db9ffca9184a5f0d
trivy_linux_arm64_SHA256SUM=a51268845bdeb68f5f885f7de6c92fe33b64d630392e546eec0e16f79cfd42e8
trivy_darwin_amd64_SHA256SUM=284a3d3346429837f3da11aa6c25bf196e4fe5431733d4f6f99eac8578b329ed
trivy_darwin_arm64_SHA256SUM=964bb69fc0e652891b38514fed4ee31de004a58ac22ea2a23c6891728bb6b6eb

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

ytt_linux_amd64_SHA256SUM=4c222403a9a2d54d8bb0e0ca46f699ee4040a2bddd5ab3b6354efd2c85d3209f
ytt_linux_arm64_SHA256SUM=781f8950da84b2d2928b139eb38567584d9ddebc7e5a34fd97209ad61ae9cc65
ytt_darwin_amd64_SHA256SUM=924eb899bdbb4b3652d941c7662acc434a7a35c07537e7cf48a7645b960a7ab5
ytt_darwin_arm64_SHA256SUM=f77bcbcd71802fcb55cb0333ed7e640e6cc6e9164b757af01a6ac69f6b503b47

.PRECIOUS: $(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) -sSfL https://github.com/vmware-tanzu/carvel-ytt/releases/download/$(YTT_VERSION)/ytt-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(ytt_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

rclone_linux_amd64_SHA256SUM=3ddbcfd535ef2e6eb00cd006831766537f1fef1c8baeed1ee4632e7bcc699e93
rclone_linux_arm64_SHA256SUM=b710ac2ded37261d2cc6ab046dcd644828944524cf1ee7c2b17dd746f0fd8684
rclone_darwin_amd64_SHA256SUM=858fcdb96597776672c38416a4cdf72b87f5ed8e05353374c894b38ae381b965
rclone_darwin_arm64_SHA256SUM=ee9964d24f1aed3f0a2183f5a93eeec29526782240435d4b3f302b45f6f34b61

.PRECIOUS: $(DOWNLOAD_DIR)/tools/rclone@$(RCLONE_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/rclone@$(RCLONE_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/rclone/rclone/releases/download/$(RCLONE_VERSION)/rclone-$(RCLONE_VERSION)-$(OS)-$(HOST_ARCH).zip -o $(outfile).zip; \
		$(checkhash_script) $(outfile).zip $(rclone_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		unzip -p $(outfile).zip rclone-$(RCLONE_VERSION)-$(OS)-$(HOST_ARCH)/rclone > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).zip

istioctl_linux_amd64_SHA256SUM=554bff365fda222280bc02d89a59ffc6c9c9b560a75508789a093ed0a3c4931b
istioctl_linux_arm64_SHA256SUM=966bdd32a216dfcc74d7634e75e69f0ac8ca744412261d41021ddcf1c7622799
istioctl_darwin_amd64_SHA256SUM=eb353c4b381ca04337a68da2f7ca3702d4f6dce9d582f576b39b1cfa7a7c49df
istioctl_darwin_arm64_SHA256SUM=decd937baf43055f876a72b33a56d5ac1f366826f4023a8f4d97d023b1231937

.PRECIOUS: $(DOWNLOAD_DIR)/tools/istioctl@$(ISTIOCTL_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/istioctl@$(ISTIOCTL_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/istio/istio/releases/download/$(ISTIOCTL_VERSION)/istio-$(ISTIOCTL_VERSION)-$(OS)-$(HOST_ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(istioctl_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz istio-$(ISTIOCTL_VERSION)/bin/istioctl > $(outfile); \
		chmod +x $(outfile); \
		rm $(outfile).tar.gz

preflight_linux_amd64_SHA256SUM=cd1b6143fb511433d07f29075b4840b712933d7d4d4fc6353b079b59c1cb06cd
preflight_linux_arm64_SHA256SUM=cd29e198bd54cec46b219fc151b1b9c8fe71c33e7fdab7814862736a309a2a7c
preflight_darwin_amd64_SHA256SUM=7e03a564cfb1697a6a3179c5d2f6f0a861a14bf4443f553d946f92ac06376b98
preflight_darwin_arm64_SHA256SUM=216b5f8846b6d3292bb798765a63f935627c36285fcba649ddab535973e70914

.PRECIOUS: $(DOWNLOAD_DIR)/tools/preflight@$(PREFLIGHT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/preflight@$(PREFLIGHT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/redhat-openshift-ecosystem/openshift-preflight/releases/download/$(PREFLIGHT_VERSION)/preflight-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(preflight_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

operator-sdk_linux_amd64_SHA256SUM=348284cbd5298f70e2b0a01f9f86820a3149aa6e7e19272e886a9d5769c7fb69
operator-sdk_linux_arm64_SHA256SUM=719e5565cb11895995284d236e94bc14af0c9e7c96954ce4f30f450d8c86995e
operator-sdk_darwin_amd64_SHA256SUM=d1d55418a37f142913b7155cfdd16416aeaa657eb25e27644bd37a91451f7751
operator-sdk_darwin_arm64_SHA256SUM=e9f3bdc229697a30f725ffa5bbb15ee59ca7eba6e6f58b3028bf940903ed0df6

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
## Download and setup all Go tools
## @category [shared] Tools
non-go-tools: $(non_go_tool_names:%=$(bin_dir)/tools/%)

.PHONY: go-tools
## Download and setup all Non-Go tools
## NOTE: this target is also used to learn the shas of
## these tools (see scripts/learn_tools_shas.sh in the
## Makefile modules repo)
## @category [shared] Tools
go-tools: $(go_tool_names:%=$(bin_dir)/tools/%)

.PHONY: tools
## Download and setup all tools
## @category [shared] Tools
tools: non-go-tools go-tools
