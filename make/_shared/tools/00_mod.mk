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
tools += helm=v3.19.0
# https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl
# renovate: datasource=github-releases packageName=kubernetes/kubernetes
tools += kubectl=v1.34.1
# https://github.com/kubernetes-sigs/kind/releases
# renovate: datasource=github-releases packageName=kubernetes-sigs/kind
tools += kind=v0.30.0
# https://www.vaultproject.io/downloads
# renovate: datasource=github-releases packageName=hashicorp/vault
tools += vault=v1.21.0
# https://github.com/Azure/azure-workload-identity/releases
# renovate: datasource=github-releases packageName=Azure/azure-workload-identity
tools += azwi=v1.5.1
# https://github.com/kyverno/kyverno/releases
# renovate: datasource=github-releases packageName=kyverno/kyverno
tools += kyverno=v1.15.2
# https://github.com/mikefarah/yq/releases
# renovate: datasource=github-releases packageName=mikefarah/yq
tools += yq=v4.48.1
# https://github.com/ko-build/ko/releases
# renovate: datasource=github-releases packageName=ko-build/ko
tools += ko=0.18.0
# https://github.com/protocolbuffers/protobuf/releases
# renovate: datasource=github-releases packageName=protocolbuffers/protobuf
tools += protoc=v33.0
# https://github.com/aquasecurity/trivy/releases
# renovate: datasource=github-releases packageName=aquasecurity/trivy
tools += trivy=v0.67.2
# https://github.com/vmware-tanzu/carvel-ytt/releases
# renovate: datasource=github-releases packageName=vmware-tanzu/carvel-ytt
tools += ytt=v0.52.1
# https://github.com/rclone/rclone/releases
# renovate: datasource=github-releases packageName=rclone/rclone
tools += rclone=v1.71.2
# https://github.com/istio/istio/releases
# renovate: datasource=github-releases packageName=istio/istio
tools += istioctl=1.28.0

### go packages
# https://pkg.go.dev/sigs.k8s.io/controller-tools/cmd/controller-gen?tab=versions
# renovate: datasource=go packageName=sigs.k8s.io/controller-tools
tools += controller-gen=v0.19.0
# https://pkg.go.dev/golang.org/x/tools/cmd/goimports?tab=versions
# renovate: datasource=go packageName=golang.org/x/tools
tools += goimports=v0.38.0
# https://pkg.go.dev/github.com/google/go-licenses/v2?tab=versions
# renovate: datasource=go packageName=github.com/inteon/go-licenses/v2
tools += go-licenses=v2.0.0-20250821024731-e4be79958780
# https://pkg.go.dev/gotest.tools/gotestsum?tab=versions
# renovate: datasource=github-releases packageName=gotestyourself/gotestsum
tools += gotestsum=v1.13.0
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
tools += protoc-gen-go=v1.36.10
# https://pkg.go.dev/github.com/sigstore/cosign/v2/cmd/cosign?tab=versions
# renovate: datasource=go packageName=github.com/sigstore/cosign/v2
tools += cosign=v2.6.1
# https://pkg.go.dev/github.com/cert-manager/boilersuite?tab=versions
# renovate: datasource=go packageName=github.com/cert-manager/boilersuite
tools += boilersuite=v0.1.0
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
tools += goreleaser=v2.12.7
# https://pkg.go.dev/github.com/anchore/syft/cmd/syft?tab=versions
# renovate: datasource=go packageName=github.com/anchore/syft
tools += syft=v1.37.0
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
tools += golangci-lint=v2.6.1
# https://pkg.go.dev/golang.org/x/vuln?tab=versions
# renovate: datasource=go packageName=golang.org/x/vuln
tools += govulncheck=v1.1.4
# https://github.com/operator-framework/operator-sdk/releases
# renovate: datasource=github-releases packageName=operator-framework/operator-sdk
tools += operator-sdk=v1.41.1
# https://pkg.go.dev/github.com/cli/cli/v2?tab=versions
# renovate: datasource=go packageName=github.com/cli/cli/v2
tools += gh=v2.83.0
# https://github.com/redhat-openshift-ecosystem/openshift-preflight/releases
# renovate: datasource=github-releases packageName=redhat-openshift-ecosystem/openshift-preflight
tools += preflight=1.14.1
# https://github.com/daixiang0/gci/releases
# renovate: datasource=github-releases packageName=daixiang0/gci
tools += gci=v0.13.7
# https://github.com/google/yamlfmt/releases
# renovate: datasource=github-releases packageName=google/yamlfmt
tools += yamlfmt=v0.20.0
# https://github.com/yannh/kubeconform/releases
# renovate: datasource=github-releases packageName=yannh/kubeconform
tools += kubeconform=v0.7.0

# FIXME(erikgb): cert-manager needs the ability to override the version set here
# https://pkg.go.dev/k8s.io/code-generator/cmd?tab=versions
# renovate: datasource=go packageName=k8s.io/code-generator
K8S_CODEGEN_VERSION ?= v0.34.1
tools += client-gen=$(K8S_CODEGEN_VERSION)
tools += deepcopy-gen=$(K8S_CODEGEN_VERSION)
tools += informer-gen=$(K8S_CODEGEN_VERSION)
tools += lister-gen=$(K8S_CODEGEN_VERSION)
tools += applyconfiguration-gen=$(K8S_CODEGEN_VERSION)
tools += defaulter-gen=$(K8S_CODEGEN_VERSION)
tools += conversion-gen=$(K8S_CODEGEN_VERSION)
# https://github.com/kubernetes/kube-openapi
# renovate: datasource=go packageName=k8s.io/kube-openapi
tools += openapi-gen=v0.0.0-20250910181357-589584f1c912

# https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/master/envtest-releases.yaml
# FIXME: Find a way to configure Renovate to suggest upgrades
KUBEBUILDER_ASSETS_VERSION := v1.34.1
tools += etcd=$(KUBEBUILDER_ASSETS_VERSION)
tools += kube-apiserver=$(KUBEBUILDER_ASSETS_VERSION)

# Additional tools can be defined to reuse the tooling in this file
ADDITIONAL_TOOLS ?=
tools += $(ADDITIONAL_TOOLS)

# https://go.dev/dl/
# renovate: datasource=golang-version packageName=go
VENDORED_GO_VERSION := 1.25.4

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

go_linux_amd64_SHA256SUM=9fa5ffeda4170de60f67f3aa0f824e426421ba724c21e133c1e35d6159ca1bec
go_linux_arm64_SHA256SUM=a68e86d4b72c2c2fecf7dfed667680b6c2a071221bbdb6913cf83ce3f80d9ff0
go_darwin_amd64_SHA256SUM=33ba03ff9973f5bd26d516eea35328832a9525ecc4d169b15937ffe2ce66a7d8
go_darwin_arm64_SHA256SUM=c1b04e74251fe1dfbc5382e73d0c6d96f49642d8aebb7ee10a7ecd4cae36ebd2

.PRECIOUS: $(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz
$(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz: | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://go.dev/dl/go$(VENDORED_GO_VERSION).$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile); \
		$(checkhash_script) $(outfile) $(go_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)

helm_linux_amd64_SHA256SUM=a7f81ce08007091b86d8bd696eb4d86b8d0f2e1b9f6c714be62f82f96a594496
helm_linux_arm64_SHA256SUM=440cf7add0aee27ebc93fada965523c1dc2e0ab340d4348da2215737fc0d76ad
helm_darwin_amd64_SHA256SUM=09a108c0abda42e45af172be65c49125354bf7cd178dbe10435e94540e49c7b9
helm_darwin_arm64_SHA256SUM=31513e1193da4eb4ae042eb5f98ef9aca7890cfa136f4707c8d4f70e2115bef6

.PRECIOUS: $(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://get.helm.sh/helm-$(HELM_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(helm_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz $(HOST_OS)-$(HOST_ARCH)/helm > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).tar.gz

kubectl_linux_amd64_SHA256SUM=7721f265e18709862655affba5343e85e1980639395d5754473dafaadcaa69e3
kubectl_linux_arm64_SHA256SUM=420e6110e3ba7ee5a3927b5af868d18df17aae36b720529ffa4e9e945aa95450
kubectl_darwin_amd64_SHA256SUM=bb211f2b31f2b3bc60562b44cc1e3b712a16a98e9072968ba255beb04cefcfdf
kubectl_darwin_arm64_SHA256SUM=d80e5fa36f2b14005e5bb35d3a72818acb1aea9a081af05340a000e5fbdb2f76

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

vault_linux_amd64_SHA256SUM=5a91c93a9949ed8863ee4b91cfc30640bc49ab04225f0b1c5a0650c4d6e10171
vault_linux_arm64_SHA256SUM=0083b02005ad89f6a01773866c6a892194ba27867b5f26ee374a0dfbbfb84c07
vault_darwin_amd64_SHA256SUM=2e00e327be8141751f7bcc840aad93c8a5428908a4131f17d02d22eab444bcf2
vault_darwin_arm64_SHA256SUM=fd1b26fcbc78c04c2d76d35a13a9564d450074f2547871b2046ddb95bbd7ea9c

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

kubebuilder_tools_linux_amd64_SHA256SUM=c8500090806ed5ce4064eeeb2a5666476a5168c1f4ff0eadd54fe59b22c4baa7
kubebuilder_tools_linux_arm64_SHA256SUM=cb56759108ea15933abf79d8573bbf66cca8c13e20425d7bc9f95941a060649d
kubebuilder_tools_darwin_amd64_SHA256SUM=84d47d6c3a2fa4d14571249b4cccfafad1eb77087bb680693553b438b8ec8c43
kubebuilder_tools_darwin_arm64_SHA256SUM=f25c213bc88582750935b370fa2c6108f0259b9c8f59ece5a82345d48858fc7d

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

kyverno_linux_amd64_SHA256SUM=c90520ba24fb8b8df003ec22d6d2621e4a3d3c7497665fdcf84e9eab4ff1dfe0
kyverno_linux_arm64_SHA256SUM=3d9b2465d09d2d251b42a8de92531cf00ecef4afc1e74ea6af01498f6a8b8c80
kyverno_darwin_amd64_SHA256SUM=bf6348d84ef0ee487b3476db03217d24e6e980ceaea35248932f6e96ffb6d0c8
kyverno_darwin_arm64_SHA256SUM=217af6bc2fc21006dd243101db64a48436c01a63092feabb3d994e286d64d4b1

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kyverno@$(KYVERNO_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kyverno@$(KYVERNO_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval ARCH := $(subst amd64,x86_64,$(HOST_ARCH)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/kyverno/kyverno/releases/download/$(KYVERNO_VERSION)/kyverno-cli_$(KYVERNO_VERSION)_$(HOST_OS)_$(ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(kyverno_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz kyverno > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).tar.gz

yq_linux_amd64_SHA256SUM=99df6047f5b577a9d25f969f7c3823ada3488de2e2115b30a0abb10d9324fd9f
yq_linux_arm64_SHA256SUM=0e46b5b926a9e57c526fa2bd8f8e38b7e17fbf6e2403ff1741f3b268e3363a9e
yq_darwin_amd64_SHA256SUM=c93d5e5880c78e22aec4efc1d719751b60f9adc49b2735a8009916581b8457c2
yq_darwin_arm64_SHA256SUM=05e19db817704d945f28f73763cc2b3c5142ef114a991f57b83bd034c2b86646

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

protoc_linux_amd64_SHA256SUM=d99c011b799e9e412064244f0be417e5d76c9b6ace13a2ac735330fa7d57ad8f
protoc_linux_arm64_SHA256SUM=4b96bc91f8b54d829b8c3ca2207ff1ceb774843321e4fa5a68502faece584272
protoc_darwin_amd64_SHA256SUM=e4e50a703147a92d1a5a2d3a34c9e41717f67ade67d4be72b9a466eb8f22fe87
protoc_darwin_arm64_SHA256SUM=3cf55dd47118bd2efda9cd26b74f8bbbfcf5beb1bf606bc56ad4c001b543f6d3

.PRECIOUS: $(DOWNLOAD_DIR)/tools/protoc@$(PROTOC_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/protoc@$(PROTOC_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))
	$(eval ARCH := $(subst arm64,aarch_64,$(subst amd64,x86_64,$(HOST_ARCH))))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/protocolbuffers/protobuf/releases/download/$(PROTOC_VERSION)/protoc-$(PROTOC_VERSION:v%=%)-$(OS)-$(ARCH).zip -o $(outfile).zip; \
		$(checkhash_script) $(outfile).zip $(protoc_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		unzip -p $(outfile).zip bin/protoc > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).zip

trivy_linux_amd64_SHA256SUM=546511a5514afc813c0b72e4abeea2c16a32228a13a1e5114d927c190e76b1f9
trivy_linux_arm64_SHA256SUM=e4f28390b06cdaaed94f8c49cce2c4c847938b5188aefdeb82453f2e933e57cb
trivy_darwin_amd64_SHA256SUM=4a5b936a8d89b508ecdc6edd65933b6fe3e9a368796cbdf917fd0df393f26542
trivy_darwin_arm64_SHA256SUM=6b3163667f29fc608a2ed647c1bd42023af5779349286148190a168c5b3f28f1

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

ytt_linux_amd64_SHA256SUM=490f138ae5b6864071d3c20a5a231e378cee7487cd4aeffc79dbf66718e65408
ytt_linux_arm64_SHA256SUM=7d86bd3299e43d1455201fc213d698bae7482cd88f3e05de2f935e6eab842db9
ytt_darwin_amd64_SHA256SUM=1975e52b3b97bd9be72f4efb714562da6a80cf181f036ae1f86eec215e208498
ytt_darwin_arm64_SHA256SUM=a205f49267a44cd495e4c8b245754d8a216931a28ef29c78ae161c370a9b6117

.PRECIOUS: $(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) -sSfL https://github.com/vmware-tanzu/carvel-ytt/releases/download/$(YTT_VERSION)/ytt-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(ytt_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

rclone_linux_amd64_SHA256SUM=ab9fa5877cee91c64fdfd61a27028a458cf618b39259e5c371dc2ec34a12e415
rclone_linux_arm64_SHA256SUM=e2e2efc7ed143026352d60216ef0d46d3fa4fe9d647eff1bd929e6fea498e6f1
rclone_darwin_amd64_SHA256SUM=37e50641cd736de296b8aca8149e607b9923b357d79abb902e89c4cdb1fcc790
rclone_darwin_arm64_SHA256SUM=d1cea838b618f9b4f15984748502232684e92ff0b90e3c4c8bd91ac21f4d8695

.PRECIOUS: $(DOWNLOAD_DIR)/tools/rclone@$(RCLONE_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/rclone@$(RCLONE_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/rclone/rclone/releases/download/$(RCLONE_VERSION)/rclone-$(RCLONE_VERSION)-$(OS)-$(HOST_ARCH).zip -o $(outfile).zip; \
		$(checkhash_script) $(outfile).zip $(rclone_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		unzip -p $(outfile).zip rclone-$(RCLONE_VERSION)-$(OS)-$(HOST_ARCH)/rclone > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).zip

istioctl_linux_amd64_SHA256SUM=31ba3429f6527e085a5b3630bb732f876e8ff8a433947abae2cdd886c9e59271
istioctl_linux_arm64_SHA256SUM=f1eff3bcc86dcd72ee473d8a7fbfe9eafd2337b946c9c3fd40f0c9d0e20e2561
istioctl_darwin_amd64_SHA256SUM=5cbe5c4bf72bf5e447d39626d69874e25b96578a19c40c420ec9af09eae71ccd
istioctl_darwin_arm64_SHA256SUM=593f8d58571ff4cddcd069041d2c398da4e0d6fc8055890715cad95feec09aeb

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
