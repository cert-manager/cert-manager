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

CTR ?= docker
.PHONY: __require-ctr
ifneq ($(shell command -v $(CTR) >/dev/null || echo notfound),)
__require-ctr:
	@:$(error "$(CTR) (or set CTR to a docker-compatible tool)")
endif
NEEDS_CTR = __require-ctr

tools :=
# https://github.com/helm/helm/releases
tools += helm=v3.14.4
# https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl
tools += kubectl=v1.30.0
# https://github.com/kubernetes-sigs/kind/releases
tools += kind=v0.23.0
# https://www.vaultproject.io/downloads
tools += vault=1.16.2
# https://github.com/Azure/azure-workload-identity/releases
tools += azwi=v1.2.2
# https://github.com/kyverno/kyverno/releases
tools += kyverno=v1.12.1
# https://github.com/mikefarah/yq/releases
tools += yq=v4.43.1
# https://github.com/ko-build/ko/releases
tools += ko=0.15.2
# https://github.com/protocolbuffers/protobuf/releases
tools += protoc=26.1
# https://github.com/aquasecurity/trivy/releases
tools += trivy=v0.50.4
# https://github.com/vmware-tanzu/carvel-ytt/releases
tools += ytt=v0.49.0
# https://github.com/rclone/rclone/releases
tools += rclone=v1.66.0

### go packages
# https://pkg.go.dev/sigs.k8s.io/controller-tools/cmd/controller-gen?tab=versions
tools += controller-gen=v0.15.0
# https://pkg.go.dev/golang.org/x/tools/cmd/goimports?tab=versions
tools += goimports=v0.20.0
# https://pkg.go.dev/github.com/google/go-licenses/licenses?tab=versions
tools += go-licenses=706b9c60edd424a8b6d253fe10dfb7b8e942d4a5
# https://pkg.go.dev/gotest.tools/gotestsum?tab=versions
tools += gotestsum=v1.11.0
# https://pkg.go.dev/sigs.k8s.io/kustomize/kustomize/v4?tab=versions
tools += kustomize=v4.5.7
# https://pkg.go.dev/github.com/itchyny/gojq?tab=versions
tools += gojq=v0.12.15
# https://pkg.go.dev/github.com/google/go-containerregistry/pkg/crane?tab=versions
tools += crane=v0.19.1
# https://pkg.go.dev/google.golang.org/protobuf/cmd/protoc-gen-go?tab=versions
tools += protoc-gen-go=v1.34.0
# https://pkg.go.dev/github.com/norwoodj/helm-docs/cmd/helm-docs?tab=versions
tools += helm-docs=v1.13.1
# https://pkg.go.dev/github.com/sigstore/cosign/v2/cmd/cosign?tab=versions
tools += cosign=v2.2.4
# https://pkg.go.dev/github.com/cert-manager/boilersuite?tab=versions
tools += boilersuite=v0.1.0
# https://pkg.go.dev/github.com/princjef/gomarkdoc/cmd/gomarkdoc?tab=versions
tools += gomarkdoc=v1.1.0
# https://pkg.go.dev/oras.land/oras/cmd/oras?tab=versions
tools += oras=v1.1.0
# https://pkg.go.dev/github.com/onsi/ginkgo/v2/ginkgo?tab=versions
# The gingko version should be kept in sync with the version used in code.
# If there is no go.mod file (which is only the case for the makefile-modules
# repo), then we default to a version that we know exists. We have to do this
# because otherwise the awk failure renders the whole makefile unusable.
detected_ginkgo_version := $(shell [[ -f go.mod ]] && awk '/ginkgo\/v2/ {print $$2}' go.mod || echo "v2.13.2")
tools += ginkgo=$(detected_ginkgo_version)
# https://pkg.go.dev/github.com/cert-manager/klone?tab=versions
tools += klone=v0.0.5
# https://pkg.go.dev/github.com/goreleaser/goreleaser?tab=versions
tools += goreleaser=v1.25.1
# https://pkg.go.dev/github.com/anchore/syft/cmd/syft?tab=versions
tools += syft=v0.100.0
# https://github.com/cert-manager/helm-tool
tools += helm-tool=v0.5.1
# https://github.com/cert-manager/cmctl
tools += cmctl=v2.0.0
# https://pkg.go.dev/github.com/cert-manager/release/cmd/cmrel?tab=versions
tools += cmrel=e4c3a4dc07df5c7c0379d334c5bb00e172462551
# https://github.com/golangci/golangci-lint/releases
tools += golangci-lint=v1.57.2
# https://pkg.go.dev/golang.org/x/vuln?tab=versions
tools += govulncheck=v1.1.0
# https://pkg.go.dev/github.com/operator-framework/operator-sdk/cmd/operator-sdk?tab=versions
tools += operator-sdk=v1.34.1
# https://pkg.go.dev/github.com/cli/cli/v2?tab=versions
tools += gh=v2.49.0
# https:///github.com/redhat-openshift-ecosystem/openshift-preflight/releases
tools += preflight=1.9.2
# https://github.com/daixiang0/gci/releases
tools += gci=v0.13.4
# https://github.com/google/yamlfmt/releases
tools += yamlfmt=v0.12.1

# https://pkg.go.dev/k8s.io/code-generator/cmd?tab=versions
K8S_CODEGEN_VERSION := v0.30.1
tools += client-gen=$(K8S_CODEGEN_VERSION)
tools += deepcopy-gen=$(K8S_CODEGEN_VERSION)
tools += informer-gen=$(K8S_CODEGEN_VERSION)
tools += lister-gen=$(K8S_CODEGEN_VERSION)
tools += applyconfiguration-gen=$(K8S_CODEGEN_VERSION)
tools += defaulter-gen=$(K8S_CODEGEN_VERSION)
tools += conversion-gen=$(K8S_CODEGEN_VERSION)
# https://github.com/kubernetes/kube-openapi
tools += openapi-gen=f0e62f92d13f418e2732b21c952fd17cab771c75

# https://raw.githubusercontent.com/kubernetes-sigs/controller-tools/master/envtest-releases.yaml
KUBEBUILDER_ASSETS_VERSION := v1.30.0
tools += etcd=$(KUBEBUILDER_ASSETS_VERSION)
tools += kube-apiserver=$(KUBEBUILDER_ASSETS_VERSION)

# Additional tools can be defined to reuse the tooling in this file
ADDITIONAL_TOOLS ?=
tools += $(ADDITIONAL_TOOLS)

# https://go.dev/dl/
VENDORED_GO_VERSION := 1.22.6

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
# to $(bin_dir)/tools/xxx" operation simulatiously without issues (both
# will perform the action and the second time the link will be overwritten).
LN := ln -fs

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

go_linux_amd64_SHA256SUM=999805bed7d9039ec3da1a53bfbcafc13e367da52aa823cb60b68ba22d44c616
go_linux_arm64_SHA256SUM=c15fa895341b8eaf7f219fada25c36a610eb042985dc1a912410c1c90098eaf2
go_darwin_amd64_SHA256SUM=9c3c0124b01b5365f73a1489649f78f971ecf84844ad9ca58fde133096ddb61b
go_darwin_arm64_SHA256SUM=ebac39fd44fc22feed1bb519af431c84c55776e39b30f4fd62930da9c0cfd1e3

.PRECIOUS: $(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz
$(DOWNLOAD_DIR)/tools/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz: | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://go.dev/dl/go$(VENDORED_GO_VERSION).$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile); \
		$(checkhash_script) $(outfile) $(go_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)

helm_linux_amd64_SHA256SUM=a5844ef2c38ef6ddf3b5a8f7d91e7e0e8ebc39a38bb3fc8013d629c1ef29c259
helm_linux_arm64_SHA256SUM=113ccc53b7c57c2aba0cd0aa560b5500841b18b5210d78641acfddc53dac8ab2
helm_darwin_amd64_SHA256SUM=73434aeac36ad068ce2e5582b8851a286dc628eae16494a26e2ad0b24a7199f9
helm_darwin_arm64_SHA256SUM=61e9c5455f06b2ad0a1280975bf65892e707adc19d766b0cf4e9006e3b7b4b6c

.PRECIOUS: $(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/helm@$(HELM_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://get.helm.sh/helm-$(HELM_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(helm_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz $(HOST_OS)-$(HOST_ARCH)/helm > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).tar.gz

kubectl_linux_amd64_SHA256SUM=7c3807c0f5c1b30110a2ff1e55da1d112a6d0096201f1beb81b269f582b5d1c5
kubectl_linux_arm64_SHA256SUM=669af0cf520757298ea60a8b6eb6b719ba443a9c7d35f36d3fb2fd7513e8c7d2
kubectl_darwin_amd64_SHA256SUM=bcfa57d020b8d07d0ea77235ce8012c2c28fefdfd7cb9738f33674a7b16cef08
kubectl_darwin_arm64_SHA256SUM=45cfa208151320153742062824398f22bb6bfb5a142bf6238476d55dacbd1bdd

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kubectl@$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kubectl@$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://dl.k8s.io/release/$(KUBECTL_VERSION)/bin/$(HOST_OS)/$(HOST_ARCH)/kubectl -o $(outfile); \
		$(checkhash_script) $(outfile) $(kubectl_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

kind_linux_amd64_SHA256SUM=1d86e3069ffbe3da9f1a918618aecbc778e00c75f838882d0dfa2d363bc4a68c
kind_linux_arm64_SHA256SUM=a416d6c311882337f0e56910e4a2e1f8c106ec70c22cbf0ac1dd8f33c1e284fe
kind_darwin_amd64_SHA256SUM=81c77f104b4b668812f7930659dc01ad88fa4d1cfc56900863eacdfb2731c457
kind_darwin_arm64_SHA256SUM=68ec87c1e1ea2a708df883f4b94091150d19552d7b344e80ca59f449b301c2a0

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kind@$(KIND_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kind@$(KIND_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/kubernetes-sigs/kind/releases/download/$(KIND_VERSION)/kind-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(kind_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

vault_linux_amd64_SHA256SUM=688ce462b70cb674f84fddb731f75bb710db5ad9e4e5a17659e90e1283a8b4b7
vault_linux_arm64_SHA256SUM=d5bd42227d295b1dcc4a5889c37e6a8ca945ece4795819718eaf54db87aa6d4f
vault_darwin_amd64_SHA256SUM=e4886d22273dedc579dc2382e114e7be29341049a48592f8f7be8a0020310731
vault_darwin_arm64_SHA256SUM=ca59c85e7e3d67e25b6bfa505f7e7717b418452e8bfcd602a2a717bc06d5b1ee

.PRECIOUS: $(DOWNLOAD_DIR)/tools/vault@$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/vault@$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://releases.hashicorp.com/vault/$(VAULT_VERSION)/vault_$(VAULT_VERSION)_$(HOST_OS)_$(HOST_ARCH).zip -o $(outfile).zip; \
		$(checkhash_script) $(outfile).zip $(vault_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		unzip -qq -c $(outfile).zip > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).zip

azwi_linux_amd64_SHA256SUM=d33aaedbcbcc0ef61d845b3704ab336deaafc192c854e887896e163b99097871
azwi_linux_arm64_SHA256SUM=7c4b55ef83e62f4b597885e66fbbdf0720cf0e2be3f1a16212f9b41d4b61b454
azwi_darwin_amd64_SHA256SUM=47a9e99a7e02e531967d1c9a8abf12e73134f88ce3363007f411ba9b83497fd0
azwi_darwin_arm64_SHA256SUM=19c5cf9fe4e1a7394bc01456d5e314fd898162d2d360c585fc72e46dae930659

.PRECIOUS: $(DOWNLOAD_DIR)/tools/azwi@$(AZWI_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/azwi@$(AZWI_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/Azure/azure-workload-identity/releases/download/$(AZWI_VERSION)/azwi-$(AZWI_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(azwi_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz azwi > $(outfile) && chmod 775 $(outfile); \
		rm -f $(outfile).tar.gz

kubebuilder_tools_linux_amd64_SHA256SUM=2a9792cb5f1403f524543ce94c3115e3c4a4229f0e86af55fd26c078da448164
kubebuilder_tools_linux_arm64_SHA256SUM=39cc7274a3075a650a20fcd24b9e2067375732bebaf5356088a8efb35155f068
kubebuilder_tools_darwin_amd64_SHA256SUM=85890b864330baec88f53aabfc1d5d94a8ca8c17483f34f4823dec0fae7c6e3a
kubebuilder_tools_darwin_arm64_SHA256SUM=849362d26105b64193b4142982c710306d90248272731a81fb83efac27c5a750

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

kyverno_linux_amd64_SHA256SUM=a5f6e9070c17acc47168c8ce4db78e45258376551b8bf68ad2d5ed27454cf666
kyverno_linux_arm64_SHA256SUM=007e828d622e73614365f5f7e8e107e36ae686e97e8982b1eeb53511fb2363c3
kyverno_darwin_amd64_SHA256SUM=20786eebf45238e8b4a35f4146c3f8dfea35968cf8ef6ca6d6727559f5c0156e
kyverno_darwin_arm64_SHA256SUM=3a454fb0b2bfbca6225d46ff4cc0b702fd4a63e978718c50225472b9631a8015

.PRECIOUS: $(DOWNLOAD_DIR)/tools/kyverno@$(KYVERNO_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/kyverno@$(KYVERNO_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval ARCH := $(subst amd64,x86_64,$(HOST_ARCH)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/kyverno/kyverno/releases/download/$(KYVERNO_VERSION)/kyverno-cli_$(KYVERNO_VERSION)_$(HOST_OS)_$(ARCH).tar.gz -o $(outfile).tar.gz; \
		$(checkhash_script) $(outfile).tar.gz $(kyverno_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		tar xfO $(outfile).tar.gz kyverno > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).tar.gz

yq_linux_amd64_SHA256SUM=cfbbb9ba72c9402ef4ab9d8f843439693dfb380927921740e51706d90869c7e1
yq_linux_arm64_SHA256SUM=a8186efb079673293289f8c31ee252b0d533c7bb8b1ada6a778ddd5ec0f325b6
yq_darwin_amd64_SHA256SUM=fdc42b132ac460037f4f0f48caea82138772c651d91cfbb735210075ddfdbaed
yq_darwin_arm64_SHA256SUM=9f1063d910698834cb9176593aa288471898031929138d226c2c2de9f262f8e5

.PRECIOUS: $(DOWNLOAD_DIR)/tools/yq@$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/yq@$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) https://github.com/mikefarah/yq/releases/download/$(YQ_VERSION)/yq_$(HOST_OS)_$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(yq_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

ko_linux_amd64_SHA256SUM=d11f03f23261d16f9e7802291e9d098e84f5daecc7931e8573bece9025b6a2c5
ko_linux_arm64_SHA256SUM=8294849c0f12138006cd149dd02bb580c0eea41a6031473705cbf825e021a688
ko_darwin_amd64_SHA256SUM=314c33154de941bfc4ede5e7283eb182028459bac36eb4223859e0b778254936
ko_darwin_arm64_SHA256SUM=b6ecd62eb4f9238a0ed0512d7a34648b881aea0774c3830e3e5159370eb6834f

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

protoc_linux_amd64_SHA256SUM=a7be2928c0454f132c599e25b79b7ad1b57663f2337d7f7e468a1d59b98ec1b0
protoc_linux_arm64_SHA256SUM=64a3b3b5f7dac0c8f9cf1cb85b2b1a237eb628644f6bcb0fb8f23db6e0d66181
protoc_darwin_amd64_SHA256SUM=febd8821c3a2a23f72f4641471e0ab6486f4fb07b68111490a27a31681465b3c
protoc_darwin_arm64_SHA256SUM=26a29befa8891ecc48809958c909d284f2b9539a2eb47f22cadc631fe6abe8fd

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

trivy_linux_amd64_SHA256SUM=b0d135815867246baba52f608f4af84beca90cfeb17a9ce407a21acca760ace1
trivy_linux_arm64_SHA256SUM=1be1dee3a5e013528374f25391d6ba84e2a10fda59f4e98431e30d9c4975762b
trivy_darwin_amd64_SHA256SUM=744f5e8c5c09c1e5ec6ec6a0570f779d89964c0a91ab60b4e59b284cdd3e1576
trivy_darwin_arm64_SHA256SUM=e78a0db86f6364e756d5e058316c7815a747fc7fd8e8e984e3baf5830166ec63

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

ytt_linux_amd64_SHA256SUM=357ec754446b1eda29dd529e088f617e85809726c686598ab03cfc1c79f43b56
ytt_linux_arm64_SHA256SUM=a2d195b058884c0e36a918936076965b8efb426f7e00f6b7d7b99b82737c7299
ytt_darwin_amd64_SHA256SUM=71b5ea38bfc7a9748c35ce0735fd6f806dce46bd5c9039d527050c7682e62a70
ytt_darwin_arm64_SHA256SUM=0658db4af8263ca091ca31e4b599cb40c324b75934660a4c0ed98ad9b701f7e9

.PRECIOUS: $(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/ytt@$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	@source $(lock_script) $@; \
		$(CURL) -sSfL https://github.com/vmware-tanzu/carvel-ytt/releases/download/$(YTT_VERSION)/ytt-$(HOST_OS)-$(HOST_ARCH) -o $(outfile); \
		$(checkhash_script) $(outfile) $(ytt_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		chmod +x $(outfile)

rclone_linux_amd64_SHA256SUM=b4d304b1dc76001b1d3bb820ae8d1ae60a072afbd3296be904a3ee00b3d4fab9
rclone_linux_arm64_SHA256SUM=c50a3ab93082f21788f9244393b19f2426edeeb896eec2e3e05ffb2e8727e075
rclone_darwin_amd64_SHA256SUM=5adb4c5fe0675627461000a63156001301ec7cade966c55c8c4ebcfaeb62c5ae
rclone_darwin_arm64_SHA256SUM=b5f4c4d06ff3d426aee99870ad437276c9ddaad55442f2df6a58b918115fe4cf

.PRECIOUS: $(DOWNLOAD_DIR)/tools/rclone@$(RCLONE_VERSION)_$(HOST_OS)_$(HOST_ARCH)
$(DOWNLOAD_DIR)/tools/rclone@$(RCLONE_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(DOWNLOAD_DIR)/tools
	$(eval OS := $(subst darwin,osx,$(HOST_OS)))

	@source $(lock_script) $@; \
		$(CURL) https://github.com/rclone/rclone/releases/download/$(RCLONE_VERSION)/rclone-$(RCLONE_VERSION)-$(OS)-$(HOST_ARCH).zip -o $(outfile).zip; \
		$(checkhash_script) $(outfile).zip $(rclone_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM); \
		unzip -p $(outfile).zip rclone-$(RCLONE_VERSION)-$(OS)-$(HOST_ARCH)/rclone > $(outfile); \
		chmod +x $(outfile); \
		rm -f $(outfile).zip

preflight_linux_amd64_SHA256SUM=20f31e4af2004e8e3407844afea4e973975069169d69794e0633f0cb91d45afd
preflight_linux_arm64_SHA256SUM=c42cf4132027d937da88da07760e8fd9b1a8836f9c7795a1b60513d99c6939fe

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
