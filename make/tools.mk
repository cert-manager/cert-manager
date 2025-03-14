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
TOOLS += helm=v3.11.2
TOOLS += kubectl=v1.29.7
TOOLS += kind=v0.20.0
TOOLS += controller-gen=v0.17.2
TOOLS += cosign=v1.12.1
TOOLS += cmrel=fa10147dadc8c36718b7b08aed6d8c6418eb2
TOOLS += release-notes=v0.14.0
TOOLS += goimports=v0.1.12
# https://pkg.go.dev/github.com/google/go-licenses?tab=versions
# This uses a hash because the upstream project has been slow to release
# We want the latest changes which massively speed up license checking
TOOLS += go-licenses=9a41918e8c1e254f6472bdd8454b6030d445b255
TOOLS += gotestsum=v1.8.2
TOOLS += rclone=v1.59.2
TOOLS += trivy=v0.32.0
TOOLS += ytt=v0.43.0
TOOLS += yq=v4.27.5
TOOLS += crane=v0.11.0
TOOLS += boilersuite=v0.1.0
TOOLS += ginkgo=$(shell awk '/ginkgo\/v2/ {print $$2}' go.mod)
TOOLS += ko=v0.13.0

# Version of Gateway API install bundle https://gateway-api.sigs.k8s.io/v1alpha2/guides/#installing-gateway-api
GATEWAY_API_VERSION=v0.6.2

K8S_CODEGEN_VERSION=v0.29.7

KUBEBUILDER_ASSETS_VERSION=1.27.1
TOOLS += etcd=$(KUBEBUILDER_ASSETS_VERSION)
TOOLS += kube-apiserver=$(KUBEBUILDER_ASSETS_VERSION)

VENDORED_GO_VERSION := 1.23.7

# When switching branches which use different versions of the tools, we
# need a way to re-trigger the symlinking from $(BINDIR)/downloaded to $(BINDIR)/tools.
$(BINDIR)/scratch/%_VERSION: FORCE | $(BINDIR)/scratch
	@test "$($*_VERSION)" == "$(shell cat $@ 2>/dev/null)" || echo $($*_VERSION) > $@

# The reason we don't use "go env GOOS" or "go env GOARCH" is that the "go"
# binary may not be available in the PATH yet when the Makefiles are
# evaluated. HOST_OS and HOST_ARCH only support Linux, *BSD and macOS (M1
# and Intel).
HOST_OS := $(shell uname -s | tr A-Z a-z)
HOST_ARCH = $(shell uname -m)

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

GOBUILD := CGO_ENABLED=$(CGO_ENABLED) GOEXPERIMENT=$(GOEXPERIMENT) GOMAXPROCS=$(GOBUILDPROCS) $(GO) build
GOTEST := CGO_ENABLED=$(CGO_ENABLED) GOEXPERIMENT=$(GOEXPERIMENT) $(GO) test

# overwrite $(GOTESTSUM) and add relevant environment variables
GOTESTSUM := CGO_ENABLED=$(CGO_ENABLED) GOEXPERIMENT=$(GOEXPERIMENT) $(GOTESTSUM)

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

$(BINDIR)/tools/go: $(BINDIR)/scratch/VENDORED_GO_VERSION | $(BINDIR)/tools/goroot $(BINDIR)/tools
	cd $(dir $@) && $(LN) ./goroot/bin/go $(notdir $@)
	@touch $@ # making sure the target of the symlink is newer than *_VERSION

# The "_" in "_bin" prevents "go mod tidy" from trying to tidy the vendored goroot.
$(BINDIR)/tools/goroot: $(BINDIR)/scratch/VENDORED_GO_VERSION | $(BINDIR)/go_vendor/go@$(VENDORED_GO_VERSION)_$(HOST_OS)_$(HOST_ARCH)/goroot $(BINDIR)/tools
	@rm -rf $(BINDIR)/tools/goroot
	cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$(word 1,$|)) $(notdir $@)
	@touch $@ # making sure the target of the symlink is newer than *_VERSION

# Extract the tar to the _bin/go directory, this directory is not cached across CI runs.
$(BINDIR)/go_vendor/go@$(VENDORED_GO_VERSION)_%/goroot: | $(BINDIR)/downloaded/tools/go@$(VENDORED_GO_VERSION)_%.tar.gz
	@rm -rf $@ && mkdir -p $(dir $@)
	tar xzf $| -C $(dir $@)
	mv $(dir $@)/go $(dir $@)/goroot

# Keep the downloaded tar so it is cached across CI runs.
.PRECIOUS: $(BINDIR)/downloaded/tools/go@$(VENDORED_GO_VERSION)_%.tar.gz
$(BINDIR)/downloaded/tools/go@$(VENDORED_GO_VERSION)_%.tar.gz: | $(BINDIR)/downloaded/tools
	$(CURL) https://go.dev/dl/go$(VENDORED_GO_VERSION).$(subst _,-,$*).tar.gz -o $@

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

HELM_linux_amd64_SHA256SUM=781d826daec584f9d50a01f0f7dadfd25a3312217a14aa2fbb85107b014ac8ca
HELM_darwin_amd64_SHA256SUM=404938fd2c6eff9e0dab830b0db943fca9e1572cd3d7ee40904705760faa390f
HELM_darwin_arm64_SHA256SUM=f61a3aa55827de2d8c64a2063fd744b618b443ed063871b79f52069e90813151
HELM_linux_arm64_SHA256SUM=0a60baac83c3106017666864e664f52a4e16fbd578ac009f9a85456a9241c5db
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
# gsutil cp gs://kubernetes-release/release/<version>/bin/<os>/<arch>/kubectl
# sha256sum kubelet
KUBECTL_linux_amd64_SHA256SUM=e3df008ef60ea50286ea93c3c40a020e178a338cea64a185b4e21792d88c75d6
KUBECTL_darwin_amd64_SHA256SUM=e747b90725ebdac7b8a88621fc48ee56fabf5319da3080fa5855712e81fc88f8
KUBECTL_darwin_arm64_SHA256SUM=f987c6a8cb769ec5062024ef27e2255bf8bc290d47f41b0fb974bb58094e11a7
KUBECTL_linux_arm64_SHA256SUM=7b6649aaa298be728c5fb7ccb65f98738a4e8bda0741afbd5a9ed9e488c0e725
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

COSIGN_linux_amd64_SHA256SUM=b30fdc7d9aab246bc2f6a760ed8eff063bd37935389302c963c07018e5d48a12
COSIGN_darwin_amd64_SHA256SUM=87a7e93b1539d988fefe0d00fd5a5a0e02ef43f5f977c2a701170c502a17980d
COSIGN_darwin_arm64_SHA256SUM=41bc69dae9f06f58e8e61446907b7e53a4db41ef341b235172d3745c937f1777

# TODO: cosign also provides signatures on all of its binaries, but they can't be validated without already having cosign
# available! We could do something like "if system cosign is available, verify using that", but for now we'll skip
$(BINDIR)/downloaded/tools/cosign@$(COSIGN_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(CURL) https://github.com/sigstore/cosign/releases/download/$(COSIGN_VERSION)/cosign-$(subst _,-,$*) -o $@
	./hack/util/checkhash.sh $@ $(COSIGN_$*_SHA256SUM)
	chmod +x $@

##########
# rclone #
##########

RCLONE_linux_amd64_SHA256SUM=81e7be456369f5957713463e3624023e9159c1cae756e807937046ebc9394383
RCLONE_darwin_amd64_SHA256SUM=d0a70241212198566028cd3154c418e35cbe73a6cd22c2d851341e88cb650cb7
RCLONE_darwin_arm64_SHA256SUM=8b98893fa34aa790ae23dd2417e8c9a200326c05feb26101dff09cda479aeb1f

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

TRIVY_linux_amd64_SHA256SUM=e6e1c4767881ab1e40da5f3bb499b1c9176892021c7cb209405078fc096d94d8
TRIVY_darwin_amd64_SHA256SUM=1cc8b2301f696b71c488d99c917a21a191ab26e1c093287c20112e8bb517ac4c
TRIVY_darwin_arm64_SHA256SUM=41a3d4c12cd227cf95db6b30144b85e571541f587837f2f3814e2339dd81a21a
TRIVY_linux_arm64_SHA256SUM=fd6e4b8f9ce7ad138b8fd46c7db308d1343f27ee8029766c939c5f66c5bef048
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

YTT_linux_amd64_SHA256SUM=29e647beeacbcc2be5f2f481e405c73bcd6d7563bd229ff924a7997b6f2edd5f
YTT_darwin_amd64_SHA256SUM=579012ac80cc0d55c3a6dde2dfc0ff5bf8a4f74c775295be99faf691cc18595e
YTT_darwin_arm64_SHA256SUM=bd8781e76e833c848ecc80580b3588b4ce8f38d8697802ec83c07aae7cf7a66f

$(BINDIR)/downloaded/tools/ytt@$(YTT_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(CURL) -sSfL https://github.com/vmware-tanzu/carvel-ytt/releases/download/$(YTT_VERSION)/ytt-$(subst _,-,$*) -o $@
	./hack/util/checkhash.sh $@ $(YTT_$*_SHA256SUM)
	chmod +x $@

######
# yq #
######

YQ_linux_amd64_SHA256SUM=9a54846e81720ae22814941905cd3b056ebdffb76bf09acffa30f5e90b22d615
YQ_darwin_amd64_SHA256SUM=79a55533b683c5eabdc35b00336aa4c107d7d719db0639a31892fc35d1436cdc
YQ_darwin_arm64_SHA256SUM=40547a5049f15a1103268fd871baaa34a31ad30136ee27a829cf697737f392be
YQ_linux_arm64_SHA256SUM=ea360a0ecdff30c8625ccd0b97f8714b8308a429fd839cf8ccc481f311e217c6
$(BINDIR)/downloaded/tools/yq@$(YQ_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(CURL) https://github.com/mikefarah/yq/releases/download/$(YQ_VERSION)/yq_$* -o $@
	./hack/util/checkhash.sh $@ $(YQ_$*_SHA256SUM)
	chmod +x $@

######
# ko #
######

KO_linux_amd64_SHA256SUM=80f3e3148fabd5b839cc367ac56bb4794f90e7262b01911316c670b210b574cc
KO_darwin_amd64_SHA256SUM=8d9daea9bcf25c790f705ea115d1c0a0193cb3d9759e937ab2959c71f88ce29c
KO_darwin_arm64_SHA256SUM=8b6ad2ca95de9e9a5f697f6a653301ef5405a643b09bdd10628bac0f77eaadff

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
KUBEBUILDER_TOOLS_linux_amd64_SHA256SUM=f9699df7b021f71a1ab55329b36b48a798e6ae3a44d2132255fc7e46c6790d4d
KUBEBUILDER_TOOLS_darwin_amd64_SHA256SUM=e1913674bacaa70c067e15649237e1f67d891ba53f367c0a50786b4a274ee047
KUBEBUILDER_TOOLS_darwin_arm64_SHA256SUM=0422632a2bbb0d4d14d7d8b0f05497a4d041c11d770a07b7a55c44bcc5e8ce66
KUBEBUILDER_TOOLS_linux_arm64_SHA256SUM=9d2803e8ca85c465b33c12b06d0b2eba3ddb64b53a468628f741e50b462c46ad

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

GATEWAY_API_SHA256SUM=732c370b6e3eb2d2ebf4dbaaeb4b2ac003c39a52e255e85f1e5be13e8dff8e95

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
	@# Deprecated and will fail. See comments in script.
	./hack/latest-kind-images.sh

.PHONY: update-base-images
update-base-images: $(BINDIR)/tools/crane
	CRANE=./$(BINDIR)/tools/crane ./hack/latest-base-images.sh

.PHONY: tidy
## Run "go mod tidy" on each module in this repo
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
## @category Development
go-workspace:
	@rm -f $(GOWORK)
	go work init
	go work use . ./cmd/acmesolver ./cmd/cainjector ./cmd/controller ./cmd/ctl ./cmd/webhook ./test/integration ./test/e2e
