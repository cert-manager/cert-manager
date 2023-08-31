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

# To make sure we use the right version of each tool, we put symlink in
# $(BINDIR)/tools, and the actual binaries are in $(BINDIR)/downloaded. When bumping
# the version of the tools, this symlink gets updated.

# Let's have $(BINDIR)/tools in front of the PATH so that we don't inavertedly
# pick up the wrong binary somewhere. Watch out, $(shell echo $$PATH) will
# still print the original PATH, since GNU make does not honor exported
# variables: https://stackoverflow.com/questions/54726457
export PATH := $(PWD)/$(BINDIR)/tools:$(PATH)

CTR=docker

TOOLS :=
# https://github.com/helm/helm/releases
TOOLS += helm=v3.12.3
# https://dl.k8s.io/release/$(curl -L -s https://dl.k8s.io/release/stable.txt)/bin/linux/amd64/kubectl
TOOLS += kubectl=v1.28.0
# https://github.com/kubernetes-sigs/kind/releases
TOOLS += kind=v0.20.0
# https://github.com/sigstore/cosign/releases
TOOLS += cosign=v2.1.0
# https://github.com/rclone/rclone/releases
TOOLS += rclone=v1.63.1
# https://github.com/aquasecurity/trivy/releases
TOOLS += trivy=v0.44.1
# https://github.com/vmware-tanzu/carvel-ytt/releases
TOOLS += ytt=v0.45.4
# https://github.com/mikefarah/yq/releases
TOOLS += yq=v4.35.1
# https://github.com/ko-build/ko/releases
TOOLS += ko=v0.14.1

### go packages
# https://pkg.go.dev/sigs.k8s.io/controller-tools/cmd/controller-gen?tab=versions
TOOLS += controller-gen=v0.12.1
# https://pkg.go.dev/github.com/cert-manager/release/cmd/cmrel?tab=versions
TOOLS += cmrel=fa10147dadc8c36718b7b08aed6d8c6418eb2
# https://pkg.go.dev/k8s.io/release/cmd/release-notes?tab=versions
TOOLS += release-notes=v0.15.1
# https://pkg.go.dev/golang.org/x/tools/cmd/goimports?tab=versions
TOOLS += goimports=v0.12.0
# https://pkg.go.dev/github.com/google/go-licenses?tab=versions
TOOLS += go-licenses=9a41918e8c1e254f6472bdd8454b6030d445b255
# https://pkg.go.dev/gotest.tools/gotestsum?tab=versions
TOOLS += gotestsum=v1.10.1
# https://pkg.go.dev/github.com/google/go-containerregistry/cmd/crane?tab=versions
TOOLS += crane=v0.16.1
# https://pkg.go.dev/github.com/cert-manager/boilersuite?tab=versions
TOOLS += boilersuite=v0.1.0
# https://pkg.go.dev/github.com/onsi/ginkgo/v2/ginkgo?tab=versions
TOOLS += ginkgo=$(shell awk '/ginkgo\/v2/ {print $$2}' go.mod)

# Version of Gateway API install bundle https://gateway-api.sigs.k8s.io/v1alpha2/guides/#installing-gateway-api
GATEWAY_API_VERSION=v0.7.1

K8S_CODEGEN_VERSION=v0.28.0

KUBEBUILDER_ASSETS_VERSION=1.28.0
TOOLS += etcd=$(KUBEBUILDER_ASSETS_VERSION)
TOOLS += kube-apiserver=$(KUBEBUILDER_ASSETS_VERSION)

VENDORED_GO_VERSION := 1.20.7

# When switching branches which use different versions of the tools, we
# need a way to re-trigger the symlinking from $(BINDIR)/downloaded to $(BINDIR)/tools.
$(BINDIR)/scratch/%_VERSION: FORCE | $(BINDIR)/scratch
	@test "$($*_VERSION)" == "$(shell cat $@ 2>/dev/null)" || echo $($*_VERSION) > $@

# The reason we don't use "go env GOOS" or "go env GOARCH" is that the "go"
# binary may not be available in the PATH yet when the Makefiles are
# evaluated. HOST_OS and HOST_ARCH only support Linux, *BSD and macOS (M1
# and Intel).
HOST_OS ?= $(shell uname -s | tr A-Z a-z)
HOST_ARCH ?= $(shell uname -m)

ifeq (x86_64, $(HOST_ARCH))
	HOST_ARCH = amd64
else ifeq (aarch64, $(HOST_ARCH))
	HOST_ARCH = arm64
endif

# --silent = don't print output like progress meters
# --show-error = but do print errors when they happen
# --fail = exit with a nonzero error code without the response from the server when there's an HTTP error
# --location = follow redirects from the server
# --retry = the number of times to retry a failed attempt to connect
# --retry-connrefused = retry even if the initial connection was refused
CURL = curl --silent --show-error --fail --location --retry 10 --retry-connrefused

# In Prow, the pod has the folder "$(BINDIR)/downloaded" mounted into the
# container. For some reason, even though the permissions are correct,
# binaries that are mounted with hostPath can't be executed. When in CI, we
# copy the binaries to work around that. Using $(LN) is only required when
# dealing with binaries. Other files and folders can be symlinked.
#
# Details on how "$(BINDIR)/downloaded" gets cached are available in the
# description of the PR https://github.com/jetstack/testing/pull/651.
#
# We use "printenv CI" instead of just "ifeq ($(CI),)" because otherwise we
# would get "warning: undefined variable 'CI'".
ifeq ($(shell printenv CI),)
LN := ln -f -s
else
LN := cp -f -r
endif

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
# - an unversioned target $(BINDIR)/tools/xxx is generated that
#   creates a copy/ link to the corresponding versioned target:
#   $(BINDIR)/tools/xxx@$(XXX_VERSION)_$(HOST_OS)_$(HOST_ARCH)
define tool_defs
TOOL_NAMES += $1

$(call UC,$1)_VERSION ?= $2
NEEDS_$(call UC,$1) := $$(BINDIR)/tools/$1
$(call UC,$1) := $$(PWD)/$$(BINDIR)/tools/$1

$$(BINDIR)/tools/$1: $$(BINDIR)/scratch/$(call UC,$1)_VERSION | $$(BINDIR)/downloaded/tools/$1@$$($(call UC,$1)_VERSION)_$$(HOST_OS)_$$(HOST_ARCH) $$(BINDIR)/tools
	cd $$(dir $$@) && $$(LN) $$(patsubst $$(BINDIR)/%,../%,$$(word 1,$$|)) $$(notdir $$@)
endef

$(foreach TOOL,$(TOOLS),$(eval $(call tool_defs,$(word 1,$(subst =, ,$(TOOL))),$(word 2,$(subst =, ,$(TOOL))))))

TOOLS_PATHS := $(TOOL_NAMES:%=$(BINDIR)/tools/%)

######
# Go #
######

# $(NEEDS_GO) is a target that is set as an order-only prerequisite in
# any target that calls $(GO), e.g.:
#
#     $(BINDIR)/tools/crane: $(NEEDS_GO)
#         $(GO) build -o $(BINDIR)/tools/crane
#
# $(NEEDS_GO) is empty most of the time, except when running "make vendor-go"
# or when "make vendor-go" was previously run, in which case $(NEEDS_GO) is set
# to $(BINDIR)/tools/go, since $(BINDIR)/tools/go is a prerequisite of
# any target depending on Go when "make vendor-go" was run.
NEEDS_GO := $(if $(findstring vendor-go,$(MAKECMDGOALS))$(shell [ -f $(BINDIR)/tools/go ] && echo yes), $(BINDIR)/tools/go,)
ifeq ($(NEEDS_GO),)
GO := go
else
export GOROOT := $(PWD)/$(BINDIR)/tools/goroot
export PATH := $(PWD)/$(BINDIR)/tools/goroot/bin:$(PATH)
GO := $(PWD)/$(BINDIR)/tools/go
endif

GOBUILD := CGO_ENABLED=$(CGO_ENABLED) GOMAXPROCS=$(GOBUILDPROCS) $(GO) build
GOTEST := CGO_ENABLED=$(CGO_ENABLED) $(GO) test

# overwrite $(GOTESTSUM) and add CGO_ENABLED variable
GOTESTSUM := CGO_ENABLED=$(CGO_ENABLED) $(GOTESTSUM)

.PHONY: vendor-go
## By default, this Makefile uses the system's Go. You can use a "vendored"
## version of Go that will get downloaded by running this command once. To
## disable vendoring, run "make unvendor-go". When vendoring is enabled,
## you will want to set the following:
##
##     export PATH="$PWD/$(BINDIR)/tools:$PATH"
##     export GOROOT="$PWD/$(BINDIR)/tools/goroot"
vendor-go: $(BINDIR)/tools/go

.PHONY: unvendor-go
unvendor-go: $(BINDIR)/tools/go
	rm -rf $(BINDIR)/tools/go $(BINDIR)/tools/goroot

.PHONY: which-go
## Print the version and path of go which will be used for building and
## testing in Makefile commands. Vendored go will have a path in ./bin
which-go: |  $(NEEDS_GO)
	@$(GO) version
	@echo "go binary used for above version information: $(GO)"

# The "_" in "_go "prevents "go mod tidy" from trying to tidy the vendored
# goroot.
$(BINDIR)/tools/go: $(BINDIR)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$(HOST_OS)-$(HOST_ARCH)/goroot/bin/go $(BINDIR)/tools/goroot $(BINDIR)/scratch/VENDORED_GO_VERSION | $(BINDIR)/tools
	cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) .
	@touch $@

$(BINDIR)/tools/goroot: $(BINDIR)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$(HOST_OS)-$(HOST_ARCH)/goroot $(BINDIR)/scratch/VENDORED_GO_VERSION | $(BINDIR)/tools
	@rm -rf $(BINDIR)/tools/goroot
	cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) .
	@touch $@

$(BINDIR)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-%/goroot $(BINDIR)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-%/goroot/bin/go: $(BINDIR)/downloaded/tools/go-$(VENDORED_GO_VERSION)-%.tar.gz
	@mkdir -p $(dir $@)
	rm -rf $(BINDIR)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$*/goroot
	tar xzf $< -C $(BINDIR)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$*
	mv $(BINDIR)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$*/go $(BINDIR)/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$*/goroot

$(BINDIR)/downloaded/tools/go-$(VENDORED_GO_VERSION)-%.tar.gz: | $(BINDIR)/downloaded/tools
	$(CURL) https://go.dev/dl/go$(VENDORED_GO_VERSION).$*.tar.gz -o $@

###################
# go dependencies #
###################

GO_DEPENDENCIES :=
GO_DEPENDENCIES += ginkgo=github.com/onsi/ginkgo/v2/ginkgo
GO_DEPENDENCIES += cmrel=github.com/cert-manager/release/cmd/cmrel
GO_DEPENDENCIES += release-notes=k8s.io/release/cmd/release-notes
GO_DEPENDENCIES += controller-gen=sigs.k8s.io/controller-tools/cmd/controller-gen
GO_DEPENDENCIES += goimports=golang.org/x/tools/cmd/goimports
GO_DEPENDENCIES += go-licenses=github.com/google/go-licenses
GO_DEPENDENCIES += gotestsum=gotest.tools/gotestsum
GO_DEPENDENCIES += crane=github.com/google/go-containerregistry/cmd/crane
GO_DEPENDENCIES += boilersuite=github.com/cert-manager/boilersuite

define go_dependency
$$(BINDIR)/downloaded/tools/$1@$($(call UC,$1)_VERSION)_%: | $$(NEEDS_GO) $$(BINDIR)/downloaded/tools
	GOBIN=$$(PWD)/$$(dir $$@) $$(GO) install $2@$($(call UC,$1)_VERSION)
	@mv $$(PWD)/$$(dir $$@)/$1 $$@
endef

$(foreach GO_DEPENDENCY,$(GO_DEPENDENCIES),$(eval $(call go_dependency,$(word 1,$(subst =, ,$(GO_DEPENDENCY))),$(word 2,$(subst =, ,$(GO_DEPENDENCY))))))

########
# Helm #
########

HELM_linux_amd64_SHA256SUM=1b2313cd198d45eab00cc37c38f6b1ca0a948ba279c29e322bdf426d406129b5
HELM_darwin_amd64_SHA256SUM=1bdbbeec5a12dd0c1cd4efd8948a156d33e1e2f51140e2a51e1e5e7b11b81d47
HELM_darwin_arm64_SHA256SUM=240b0a7da9cae208000eff3d3fb95e0fa1f4903d95be62c3f276f7630b12dae1
HELM_linux_arm64_SHA256SUM=79ef06935fb47e432c0c91bdefd140e5b543ec46376007ca14a52e5ed3023088

$(BINDIR)/downloaded/tools/helm@$(HELM_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(CURL) https://get.helm.sh/helm-$(HELM_VERSION)-$(subst _,-,$*).tar.gz -o $@.tar.gz
	./hack/util/checkhash.sh $@.tar.gz $(HELM_$*_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $@.tar.gz $(subst _,-,$*)/helm > $@
	chmod +x $@
	rm -f $@.tar.gz

###########
# kubectl #
###########

# Example commands to discover new kubectl versions and their SHAs:
# gsutil ls gs://kubernetes-release/release/
# gsutil cat gs://kubernetes-release/release/<version>/bin/<os>/<arch>/kubectl.sha256
KUBECTL_linux_amd64_SHA256SUM=4717660fd1466ec72d59000bb1d9f5cdc91fac31d491043ca62b34398e0799ce
KUBECTL_darwin_amd64_SHA256SUM=6db117a55a14a47c0dcf9144c31780c6de0c3c84ccb9a297de0d9e6fc481534d
KUBECTL_darwin_arm64_SHA256SUM=5d74042f5972b342a02636cf5969d4d73234f2d3afe84fe5ddaaa4baff79cdd8
KUBECTL_linux_arm64_SHA256SUM=f5484bd9cac66b183c653abed30226b561f537d15346c605cc81d98095f1717c

$(BINDIR)/downloaded/tools/kubectl@$(KUBECTL_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(CURL) https://storage.googleapis.com/kubernetes-release/release/$(KUBECTL_VERSION)/bin/$(subst _,/,$*)/kubectl -o $@
	./hack/util/checkhash.sh $@ $(KUBECTL_$*_SHA256SUM)
	chmod +x $@

########
# kind #
########

KIND_linux_amd64_SHA256SUM=513a7213d6d3332dd9ef27c24dab35e5ef10a04fa27274fe1c14d8a246493ded
KIND_darwin_amd64_SHA256SUM=bffd8fb2006dc89fa0d1dde5ba6bf48caacb707e4df8551528f49145ebfeb7ad
KIND_darwin_arm64_SHA256SUM=8df041a5cae55471f3b039c3c9942226eb909821af63b5677fc80904caffaabf
KIND_linux_arm64_SHA256SUM=639f7808443559aa30c3642d9913b1615d611a071e34f122340afeda97b8f422

$(BINDIR)/downloaded/tools/kind@$(KIND_VERSION)_%: | $(BINDIR)/downloaded/tools $(BINDIR)/tools
	$(CURL) https://github.com/kubernetes-sigs/kind/releases/download/$(KIND_VERSION)/kind-$(subst _,-,$*) -o $@
	./hack/util/checkhash.sh $@ $(KIND_$*_SHA256SUM)
	chmod +x $@

##########
# cosign #
##########

COSIGN_linux_amd64_SHA256SUM=c4fef1a4c7e49ce2006493b9aa894b28be247987959698b97de771c129cce8ea
COSIGN_darwin_amd64_SHA256SUM=7ba6cf7a02a203e1978464f09551164ccacb9aefcfef8d3ec73e67af46417a91
COSIGN_darwin_arm64_SHA256SUM=f795a6903daadf764a5092599bfe6945cedd7656bef37884a3049ac1a529266c
COSIGN_linux_arm64_SHA256SUM=f795a6903daadf764a5092599bfe6945cedd7656bef37884a3049ac1a529266c

# TODO: cosign also provides signatures on all of its binaries, but they can't be validated without already having cosign
# available! We could do something like "if system cosign is available, verify using that", but for now we'll skip
$(BINDIR)/downloaded/tools/cosign@$(COSIGN_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(CURL) https://github.com/sigstore/cosign/releases/download/$(COSIGN_VERSION)/cosign-$(subst _,-,$*) -o $@
	./hack/util/checkhash.sh $@ $(COSIGN_$*_SHA256SUM)
	chmod +x $@

##########
# rclone #
##########

RCLONE_linux_amd64_SHA256SUM=ca1cb4b1d9a3e45d0704aa77651b0497eacc3e415192936a5be7f7272f2c94c5
RCLONE_darwin_amd64_SHA256SUM=e6d749a36fc5258973fff424ebf1728d5c41a4482ea4a2b69a7b99ec837297e7
RCLONE_darwin_arm64_SHA256SUM=45d5b7799b90d8d6cc2d926d7920383a606842162e41303f5044058f5848892c
RCLONE_linux_arm64_SHA256SUM=eab46bfb4e6567cd42bc14502cfd207582ed611746fa51a03542c8df619cf8f8

$(BINDIR)/downloaded/tools/rclone@$(RCLONE_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(eval OS_AND_ARCH := $(subst darwin,osx,$*))
	$(CURL) https://github.com/rclone/rclone/releases/download/$(RCLONE_VERSION)/rclone-$(RCLONE_VERSION)-$(subst _,-,$(OS_AND_ARCH)).zip -o $@.zip
	./hack/util/checkhash.sh $@.zip $(RCLONE_$*_SHA256SUM)
	@# -p writes to stdout, the second file arg specifies the sole file we
	@# want to extract
	unzip -p $@.zip rclone-$(RCLONE_VERSION)-$(subst _,-,$(OS_AND_ARCH))/rclone > $@
	chmod +x $@
	rm -f $@.zip

#########
# trivy #
#########

TRIVY_linux_amd64_SHA256SUM=2012fb793e72e59c5a7d40724dc1f4d71f991396230929256ad8a5cd5470c0e6
TRIVY_darwin_amd64_SHA256SUM=2f6601873f8cdf76e9b2aaac168a3763e28ead6bd7e197a28d5757d24b10adcf
TRIVY_darwin_arm64_SHA256SUM=29318859d85e8150f2fceef24d4c8d09df92aa1fe1dccbf64983e764ba08750d
TRIVY_linux_arm64_SHA256SUM=70a56578dab1ae5f263e2843d0be52c9eb98dc8349b3cb09ca9577dad28248c6

$(BINDIR)/downloaded/tools/trivy@$(TRIVY_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(eval OS_AND_ARCH := $(subst darwin,macOS,$*))
	$(eval OS_AND_ARCH := $(subst linux,Linux,$(OS_AND_ARCH)))
	$(eval OS_AND_ARCH := $(subst arm64,ARM64,$(OS_AND_ARCH)))
	$(eval OS_AND_ARCH := $(subst amd64,64bit,$(OS_AND_ARCH)))

	$(CURL) https://github.com/aquasecurity/trivy/releases/download/$(TRIVY_VERSION)/trivy_$(patsubst v%,%,$(TRIVY_VERSION))_$(subst _,-,$(OS_AND_ARCH)).tar.gz -o $@.tar.gz
	./hack/util/checkhash.sh $@.tar.gz $(TRIVY_$*_SHA256SUM)
	tar xfO $@.tar.gz trivy > $@
	chmod +x $@
	rm $@.tar.gz

#######
# ytt #
#######

YTT_linux_amd64_SHA256SUM=9bf62175c7cc0b54f9731a5b87ee40250f0457b1fce1b0b36019c2f8d96db8f8
YTT_darwin_amd64_SHA256SUM=2b6d173dec1b6087e22690386474786fd9a2232c4479d8975cc98ae8160eea76
YTT_darwin_arm64_SHA256SUM=3e6f092bfe7a121d15126a0de6503797818c6b6745fbc97213f519d35fab08f9
YTT_linux_arm64_SHA256SUM=cbfc85f11ffd8e61d63accf799b8997caaebe46ee046290cc1c4d05ed1ab145b

$(BINDIR)/downloaded/tools/ytt@$(YTT_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(CURL) -sSfL https://github.com/vmware-tanzu/carvel-ytt/releases/download/$(YTT_VERSION)/ytt-$(subst _,-,$*) -o $@
	./hack/util/checkhash.sh $@ $(YTT_$*_SHA256SUM)
	chmod +x $@

######
# yq #
######

YQ_linux_amd64_SHA256SUM=bd695a6513f1196aeda17b174a15e9c351843fb1cef5f9be0af170f2dd744f08
YQ_darwin_amd64_SHA256SUM=b2ff70e295d02695b284755b2a41bd889cfb37454e1fa71abc3a6ec13b2676cf
YQ_darwin_arm64_SHA256SUM=e9fc15db977875de982e0174ba5dc2cf5ae4a644e18432a4262c96d4439b1686
YQ_linux_arm64_SHA256SUM=1d830254fe5cc2fb046479e6c781032976f5cf88f9d01a6385898c29182f9bed

$(BINDIR)/downloaded/tools/yq@$(YQ_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(CURL) https://github.com/mikefarah/yq/releases/download/$(YQ_VERSION)/yq_$* -o $@
	./hack/util/checkhash.sh $@ $(YQ_$*_SHA256SUM)
	chmod +x $@

######
# ko #
######

KO_linux_amd64_SHA256SUM=3f8f8e3fb4b78a4dfc0708df2b58f202c595a66c34195786f9a279ea991f4eae
KO_darwin_amd64_SHA256SUM=b879ea58255c9f2be2d4d6c4f6bd18209c78e9e0b890dbce621954ee0d63c4e5
KO_darwin_arm64_SHA256SUM=8d41c228da3e04e3de293f0f5bfe1775a4c74582ba21c86ad32244967095189f
KO_linux_arm64_SHA256SUM=9a355b8a9fe88e9d65d3aa1116d943746e3cea86944f4566e47886fd260dd3e9

$(BINDIR)/downloaded/tools/ko@$(KO_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(eval OS_AND_ARCH := $(subst darwin,Darwin,$*))
	$(eval OS_AND_ARCH := $(subst linux,Linux,$(OS_AND_ARCH)))
	$(eval OS_AND_ARCH := $(subst amd64,x86_64,$(OS_AND_ARCH)))

	$(CURL) https://github.com/ko-build/ko/releases/download/$(KO_VERSION)/ko_$(patsubst v%,%,$(KO_VERSION))_$(OS_AND_ARCH).tar.gz -o $@.tar.gz
	./hack/util/checkhash.sh $@.tar.gz $(KO_$*_SHA256SUM)
	tar xfO $@.tar.gz ko > $@
	chmod +x $@
	rm $@.tar.gz

#####################
# k8s codegen tools #
#####################

K8S_CODEGEN_TOOLS := client-gen conversion-gen deepcopy-gen defaulter-gen informer-gen lister-gen openapi-gen
K8S_CODEGEN_TOOLS_PATHS := $(K8S_CODEGEN_TOOLS:%=$(BINDIR)/tools/%)
K8S_CODEGEN_TOOLS_DOWNLOADS := $(K8S_CODEGEN_TOOLS:%=$(BINDIR)/downloaded/tools/%@$(K8S_CODEGEN_VERSION))

.PHONY: k8s-codegen-tools
k8s-codegen-tools: $(K8S_CODEGEN_TOOLS_PATHS)

$(K8S_CODEGEN_TOOLS_PATHS): $(BINDIR)/tools/%-gen: $(BINDIR)/scratch/K8S_CODEGEN_VERSION | $(BINDIR)/downloaded/tools/%-gen@$(K8S_CODEGEN_VERSION) $(BINDIR)/tools
	cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$(word 1,$|)) $(notdir $@)

$(K8S_CODEGEN_TOOLS_DOWNLOADS): $(BINDIR)/downloaded/tools/%-gen@$(K8S_CODEGEN_VERSION): $(NEEDS_GO) | $(BINDIR)/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install k8s.io/code-generator/cmd/$(notdir $@)
	@mv $(subst @$(K8S_CODEGEN_VERSION),,$@) $@

############################
# kubebuilder-tools assets #
# kube-apiserver / etcd    #
# The SHAs for the same version of kubebuilder tools can change as new versions are published for changes merged to https://github.com/kubernetes-sigs/kubebuilder/tree/tools-releases #
# You can use ./hack/latest-kubebuilder-shas.sh <version> to get latest SHAs for a particular version of kubebuilder tools #
############################

# Kubebuilder tools can get re-pushed for the same version of Kubernetes, so it
# is possible that these SHAs change, whilst the version does not. To verify the
# change that has been made to the tools look at
# https://github.com/kubernetes-sigs/kubebuilder/tree/tools-releases
KUBEBUILDER_TOOLS_linux_amd64_SHA256SUM=8c816871604cbe119ca9dd8072b576552ae369b96eebc3cdaaf50edd7e3c0c7b
KUBEBUILDER_TOOLS_darwin_amd64_SHA256SUM=a02e33a3981712c8d2702520f95357bd6c7d03d24b83a4f8ac1c89a9ba4d78c1
KUBEBUILDER_TOOLS_darwin_arm64_SHA256SUM=c87c6b3c0aec4233e68a12dc9690bcbe2f8d6cd72c23e670602b17b2d7118325
KUBEBUILDER_TOOLS_linux_arm64_SHA256SUM=69bfcdfa468a066d005b0207a07347078f4546f89060f7d9a6131d305d229aad

$(BINDIR)/downloaded/tools/etcd@$(KUBEBUILDER_ASSETS_VERSION)_%: $(BINDIR)/downloaded/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_%.tar.gz | $(BINDIR)/downloaded/tools
	./hack/util/checkhash.sh $< $(KUBEBUILDER_TOOLS_$*_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $< kubebuilder/bin/etcd > $@ && chmod 775 $@

$(BINDIR)/downloaded/tools/kube-apiserver@$(KUBEBUILDER_ASSETS_VERSION)_%: $(BINDIR)/downloaded/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_%.tar.gz | $(BINDIR)/downloaded/tools
	./hack/util/checkhash.sh $< $(KUBEBUILDER_TOOLS_$*_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $< kubebuilder/bin/kube-apiserver > $@ && chmod 775 $@

$(BINDIR)/downloaded/tools/kubebuilder_tools_$(KUBEBUILDER_ASSETS_VERSION)_$(HOST_OS)_$(HOST_ARCH).tar.gz: | $(BINDIR)/downloaded/tools
	$(CURL) https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-$(KUBEBUILDER_ASSETS_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $@

##############
# gatewayapi #
##############

GATEWAY_API_SHA256SUM=717e1a63ca20a1b3206129c13b7da3c3badf3be227989aa80faeadc921b9bbac

$(BINDIR)/downloaded/gateway-api-$(GATEWAY_API_VERSION).yaml: | $(BINDIR)/downloaded
	$(CURL) https://github.com/kubernetes-sigs/gateway-api/releases/download/$(GATEWAY_API_VERSION)/experimental-install.yaml -o $@
	./hack/util/checkhash.sh $(BINDIR)/downloaded/gateway-api-$(GATEWAY_API_VERSION).yaml $(GATEWAY_API_SHA256SUM)

#################
# Other Targets #
#################

$(BINDIR) $(BINDIR)/tools $(BINDIR)/downloaded $(BINDIR)/downloaded/tools:
	@mkdir -p $@

# Although we "vendor" most tools in $(BINDIR)/tools, we still require some binaries
# to be available on the system. The vendor-go MAKECMDGOALS trick prevents the
# check for the presence of Go when 'make vendor-go' is run.

# Gotcha warning: MAKECMDGOALS only contains what the _top level_ make invocation used, and doesn't look at target dependencies
# i.e. if we have a target "abc: vendor-go test" and run "make abc", we'll get an error
# about go being missing even though abc itself depends on vendor-go!
# That means we need to pass vendor-go at the top level if go is not installed (i.e. "make vendor-go abc")

MISSING=$(shell (command -v curl >/dev/null || echo curl) \
             && (command -v jq >/dev/null || echo jq) \
             && (command -v sha256sum >/dev/null || echo sha256sum) \
             && (command -v git >/dev/null || echo git) \
             && ([ -n "$(findstring vendor-go,$(MAKECMDGOALS),)" ] \
                || command -v $(GO) >/dev/null || echo "$(GO) (or run 'make vendor-go')") \
             && (command -v $(CTR) >/dev/null || echo "$(CTR) (or set CTR to a docker-compatible tool)"))
ifneq ($(MISSING),)
$(error Missing required tools: $(MISSING))
endif

.PHONY: tools
tools: $(TOOLS_PATHS) $(K8S_CODEGEN_TOOLS_PATHS) ## install all tools

.PHONY: update-kind-images
update-kind-images: $(BINDIR)/tools/crane
	CRANE=./$(BINDIR)/tools/crane ./hack/latest-kind-images.sh

.PHONY: update-base-images
update-base-images: $(BINDIR)/tools/crane
	CRANE=./$(BINDIR)/tools/crane ./hack/latest-base-images.sh

.PHONY: tidy
## Run "go mod tidy" on each module in this repo
##
## @category Development
tidy:
	go mod tidy
	cd cmd/acmesolver && go mod tidy
	cd cmd/cainjector && go mod tidy
	cd cmd/controller && go mod tidy
	cd cmd/ctl && go mod tidy
	cd cmd/webhook && go mod tidy
	cd test/integration && go mod tidy
	cd test/e2e && go mod tidy

.PHONY: go-workspace
go-workspace: export GOWORK?=$(abspath go.work)
## Create a go.work file in the repository root (or GOWORK)
##
## @category Development
go-workspace:
	@rm -f $(GOWORK)
	go work init
	go work use . ./cmd/acmesolver ./cmd/cainjector ./cmd/controller ./cmd/ctl ./cmd/webhook ./test/integration ./test/e2e

.PHONY: learn-sha-tools
## Re-download all tools and update the tools.mk file with the
## sha256sums of the downloaded tools. This is useful when you
## update the version of a tool in the Makefile, and want to
## automatically update the sha256sums in the tools.mk file.
##
## @category Development
learn-sha-tools:
	rm -rf ./$(BINDIR)
	mkdir ./$(BINDIR)
	$(eval export LEARN_FILE=$(PWD)/$(BINDIR)/learn_file)
	echo -n "" > "$(LEARN_FILE)"

	HOST_OS=linux HOST_ARCH=amd64 $(MAKE) tools
	HOST_OS=linux HOST_ARCH=arm64 $(MAKE) tools
	HOST_OS=darwin HOST_ARCH=amd64 $(MAKE) tools
	HOST_OS=darwin HOST_ARCH=arm64 $(MAKE) tools

	while read p; do \
		sed -i "$$p" ./make/tools.mk; \
	done <"$(LEARN_FILE)"
