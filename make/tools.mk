# To make sure we use the right version of each tool, we put symlink in
# bin/tools, and the actual binaries are in bin/downloaded. When bumping
# the version of the tools, this symlink gets updated. The only limitation
# is that moving from a version to another version that you previously
# already had in cache won't work, and you will need to remove the
# previously downloaded version first.

# Let's have bin/tools in front of the PATH so that we don't inavertedly
# pick up the wrong binary somewhere. Watch out, $(shell echo $$PATH) will
# still print the original PATH, since GNU make does not honor exported
# variables: https://stackoverflow.com/questions/54726457
export PATH := $(PWD)/bin/tools:$(PATH)

CTR=docker

HELM_VERSION=3.8.0
KUBECTL_VERSION=1.22.1
KIND_VERSION=0.11.1
CONTROLLER_GEN_VERSION=0.8.0
COSIGN_VERSION=1.3.1
CMREL_VERSION=a1e2bad95be9688794fd0571c4c40e88cccf9173
K8S_RELEASE_NOTES_VERSION=0.7.0
GOIMPORTS_VERSION=0.1.8
GOTESTSUM_VERSION=1.7.0
YTT_VERSION=0.36.0
YQ_VERSION=4.11.2
CRANE_VERSION=0.8.0
GINKGO_VERSION=$(shell awk '/ginkgo/ {print $$2}' go.mod)

# This is a temporary special case; k8s.io/code-generator makes its tags on
# version-based branches (so v0.23.1 would be on a branch called release-1.23)
# but those version-based branches don't backport changes to gomod. For module-aware
# codegen, we need k8s.io/gengo at least version v0.0.0-20211115164449-b448ea381d54
# but that version hasn't been used on anything except master, and there are no tags
# on master for us to refer to. So, we refer to the latest commit on master at the time
# of writing here; when k8s 1.24 is released, presumably the go.mod on the release-1.24
# branch will be updated and so we'll be able to use a v0.24.x tag rather than a hash
# of a commit on master.

# A alternative workaround for this is to use "go get" to install the binaries, but that's
# deprecated and will be removed in go 1.18. Referring to a commit on master here seems
# a lesser evil than blocking our potential future upgrade to go 1.18 behind the release
# of k8s 1.24
K8S_CODEGEN_VERSION=5915ef051dfa0658ffebb9af39679e52c31762bf

KUBEBUILDER_ASSETS_VERSION=1.22.0

# The reason we don't use "go env GOOS" or "go env GOARCH" is that the "go"
# binary may not be available in the PATH yet when the Makefiles are
# evaluated. HOST_OS and HOST_ARCH only support Linux, *BSD and macOS (M1
# and Intel).
HOST_OS := $(shell uname -s | tr A-Z a-z)
HOST_ARCH = $(shell uname -m)
ifeq (x86_64, $(HOST_ARCH))
	HOST_ARCH = amd64
endif

.PHONY: tools
tools: bin/tools/helm bin/tools/kubectl bin/tools/kind bin/tools/cosign bin/tools/ginkgo bin/tools/cmrel bin/tools/release-notes bin/tools/controller-gen k8s-codegen-tools bin/tools/goimports bin/tools/gotestsum bin/tools/ytt bin/tools/yq

######
# Go #
######

GO = go
CGO_ENABLED ?= 0

# DEPENDS_ON_GO is a target that is set as an order-only prerequisite in
# any target that calls $(GO), e.g.:
#
#     bin/tools/crane: $(DEPENDS_ON_GO)
#         $(GO) build -o bin/tools/crane
#
# DEPENDS_ON_GO is empty most of the time, except when running "make
# vendor-go" or when "make vendor-go" was previously run, in which case
# DEPENDS_ON_GO is set to bin/tools/go, since bin/tools/go is a
# prerequisite of any target depending on Go when "make vendor-go" was run.
DEPENDS_ON_GO := $(if $(findstring vendor-go,$(MAKECMDGOALS))$(shell [ -f bin/tools/go ] && echo yes), bin/tools/go,)
ifneq ($(DEPENDS_ON_GO),)
export GOROOT := $(PWD)/bin/tools/goroot
export PATH := $(PWD)/bin/tools/goroot/bin:$(PATH)
GO := $(PWD)/bin/tools/go
endif

GOBUILD=CGO_ENABLED=$(CGO_ENABLED) GOMAXPROCS=$(GOBUILDPROCS) $(GO) build
GOTEST=CGO_ENABLED=$(CGO_ENABLED) $(GO) test

GOTESTSUM=CGO_ENABLED=$(CGO_ENABLED) ./bin/tools/gotestsum

VENDORED_GO_VERSION := 1.17.8

.PHONY: vendor-go
## By default, this Makefile uses the system's Go. You can use a "vendored"
## version of Go that will get downloaded by running this command once. To
## disable vendoring, run "make unvendor-go". When vendoring is enabled,
## you will want to set the following:
##
##     export PATH="$PWD/bin/tools:$PATH"
##     export GOROOT="$PWD/bin/tools/goroot"
vendor-go: bin/tools/go

.PHONY: unvendor-go
unvendor-go: bin/tools/go
	rm -rf bin/tools/go bin/tools/goroot

# In Prow, the pod has the folder "bin/downloaded" mounted into the
# container. For some reason, even though the permissions are correct,
# binaries that are mounted with hostPath can't be executed. When in CI, we
# copy the binaries to work around that. Using $(LN) is only required when
# dealing with binaries. Other files and folders can be symlinked.
#
# Details on how "bin/downloaded" gets cached are available in the
# description of the PR https://github.com/jetstack/testing/pull/651.
ifeq ($(CI),)
LN := ln -f -s
else
LN := cp -f -r
endif

# The "_" in "_go "prevents "go mod tidy" from trying to tidy the vendored
# goroot.
bin/tools/go: bin/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$(HOST_OS)-$(HOST_ARCH)/goroot/bin/go bin/tools/goroot | bin/tools
	cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) .
	@touch $@

bin/tools/goroot: bin/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$(HOST_OS)-$(HOST_ARCH)/goroot | bin/tools
	@rm -rf bin/tools/goroot
	cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) .
	@touch $@

bin/downloaded/tools/_go-$(VENDORED_GO_VERSION)-%/goroot bin/downloaded/tools/_go-$(VENDORED_GO_VERSION)-%/goroot/bin/go: bin/downloaded/tools/go-$(VENDORED_GO_VERSION)-%.tar.gz
	@mkdir -p $(dir $@)
	rm -rf bin/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$*/goroot
	tar xzf $< -C bin/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$*
	mv bin/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$*/go bin/downloaded/tools/_go-$(VENDORED_GO_VERSION)-$*/goroot

bin/downloaded/tools/go-$(VENDORED_GO_VERSION)-%.tar.gz: | bin/downloaded/tools
	curl -sSfL https://go.dev/dl/go$(VENDORED_GO_VERSION).$*.tar.gz -o $@

########
# Helm #
########

HELM_linux_amd64_SHA256SUM=8408c91e846c5b9ba15eb6b1a5a79fc22dd4d33ac6ea63388e5698d1b2320c8b
HELM_darwin_amd64_SHA256SUM=532ddd6213891084873e5c2dcafa577f425ca662a6594a3389e288fc48dc2089
HELM_darwin_arm64_SHA256SUM=751348f1a4a876ffe089fd68df6aea310fd05fe3b163ab76aa62632e327122f3

bin/tools/helm: bin/downloaded/tools/helm-v$(HELM_VERSION)-$(HOST_OS)-$(HOST_ARCH) | bin/tools
	@cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) $(notdir $@)

bin/downloaded/tools/helm-v$(HELM_VERSION)-%: | bin/downloaded/tools
	curl -sSfL https://get.helm.sh/helm-v$(HELM_VERSION)-$*.tar.gz > $@.tar.gz
	./hack/util/checkhash.sh $@.tar.gz $(HELM_$(subst -,_,$*)_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $@.tar.gz $*/helm > $@
	chmod +x $@
	rm $@.tar.gz

###########
# kubectl #
###########

KUBECTL_linux_amd64_SHA256SUM=78178a8337fc6c76780f60541fca7199f0f1a2e9c41806bded280a4a5ef665c9
KUBECTL_darwin_amd64_SHA256SUM=00bb3947ac6ff15690f90ee1a732d0a9a44360fc7743dbfee4cba5a8f6a31413
KUBECTL_darwin_arm64_SHA256SUM=c81a314ab7f0827a5376f8ffd6d47f913df046275d44c562915a822229819d77

bin/tools/kubectl: bin/downloaded/tools/kubectl_$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH) | bin/tools
	@cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) $(notdir $@)

bin/downloaded/tools/kubectl_$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH): | bin/downloaded/tools
	curl -sSfL https://storage.googleapis.com/kubernetes-release/release/v$(KUBECTL_VERSION)/bin/$(HOST_OS)/$(HOST_ARCH)/kubectl > $@
	./hack/util/checkhash.sh $@ $(KUBECTL_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)
	chmod +x $@

########
# kind #
########

KIND_linux_amd64_SHA256SUM=949f81b3c30ca03a3d4effdecda04f100fa3edc07a28b19400f72ede7c5f0491
KIND_darwin_amd64_SHA256SUM=432bef555a70e9360b44661c759658265b9eaaf7f75f1beec4c4d1e6bbf97ce3
KIND_darwin_arm64_SHA256SUM=4f019c578600c087908ac59dd0c4ce1791574f153a70608adb372d5abc58cd47

bin/tools/kind: bin/downloaded/tools/kind_$(KIND_VERSION)_$(HOST_OS)_$(HOST_ARCH) | bin/tools
	@cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) $(notdir $@)

bin/downloaded/tools/kind_$(KIND_VERSION)_%: | bin/downloaded/tools bin/tools
	curl -sSfL https://github.com/kubernetes-sigs/kind/releases/download/v$(KIND_VERSION)/kind-$(subst _,-,$*) > $@
	./hack/util/checkhash.sh $@ $(KIND_$*_SHA256SUM)
	chmod +x $@

##########
# cosign #
##########

COSIGN_linux_amd64_SHA256SUM=1227b270e5d7d21d09469253cce17b72a14f6b7c9036dfc09698c853b31e8fc8
COSIGN_darwin_amd64_SHA256SUM=bcffa19e80f3e94d70e1fb1b0f591b0dec08926b31d3609fe3d25a1cc0389a0a
COSIGN_darwin_arm64_SHA256SUM=eda58f090d8f4f1db5a0e3a0d2d8845626181fe8aa1cea1791e0afa87fee7b5c

bin/tools/cosign: bin/downloaded/tools/cosign_$(COSIGN_VERSION)_$(HOST_OS)_$(HOST_ARCH) | bin/tools
	@cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) $(notdir $@)

# TODO: cosign also provides signatures on all of its binaries, but they can't be validated without already having cosign
# available! We could do something like "if system cosign is available, verify using that", but for now we'll skip
bin/downloaded/tools/cosign_$(COSIGN_VERSION)_%: | bin/downloaded/tools
	curl -sSfL https://github.com/sigstore/cosign/releases/download/v$(COSIGN_VERSION)/cosign-$(subst _,-,$*) > $@
	./hack/util/checkhash.sh $@ $(COSIGN_$*_SHA256SUM)
	chmod +x $@

##########
# ginkgo #
##########

bin/tools/ginkgo: bin/downloaded/tools/ginkgo@$(GINKGO_VERSION) | bin/tools
	@cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) $(notdir $@)

bin/downloaded/tools/ginkgo@$(GINKGO_VERSION): $(DEPENDS_ON_GO) | bin/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install github.com/onsi/ginkgo/ginkgo@$(GINKGO_VERSION)
	@mv $(subst @$(GINKGO_VERSION),,$@) $@

#########
# cmrel #
#########

bin/tools/cmrel: bin/downloaded/tools/cmrel@$(CMREL_VERSION) | bin/tools
	@cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) $(notdir $@)

bin/downloaded/tools/cmrel@$(CMREL_VERSION): $(DEPENDS_ON_GO) | bin/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install github.com/cert-manager/release/cmd/cmrel@$(CMREL_VERSION)
	@mv $(subst @$(CMREL_VERSION),,$@) $@

#################
# release-notes #
#################

bin/tools/release-notes: bin/downloaded/tools/release-notes@$(K8S_RELEASE_NOTES_VERSION) | bin/tools
	@cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) $(notdir $@)

bin/downloaded/tools/release-notes@$(K8S_RELEASE_NOTES_VERSION): $(DEPENDS_ON_GO) | bin/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install k8s.io/release/cmd/release-notes@v$(K8S_RELEASE_NOTES_VERSION)
	@mv $(subst @$(K8S_RELEASE_NOTES_VERSION),,$@) $@

##################
# controller-gen #
##################

bin/tools/controller-gen: bin/downloaded/tools/controller-gen@$(CONTROLLER_GEN_VERSION) | bin/tools
	@cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) $(notdir $@)

bin/downloaded/tools/controller-gen@$(CONTROLLER_GEN_VERSION): $(DEPENDS_ON_GO) | bin/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install sigs.k8s.io/controller-tools/cmd/controller-gen@v$(CONTROLLER_GEN_VERSION)
	@mv $(subst @$(CONTROLLER_GEN_VERSION),,$@) $@

#####################
# k8s codegen tools #
#####################

.PHONY: k8s-codegen-tools
k8s-codegen-tools: bin/tools/client-gen bin/tools/conversion-gen bin/tools/deepcopy-gen bin/tools/defaulter-gen bin/tools/informer-gen bin/tools/lister-gen

bin/tools/client-gen bin/tools/conversion-gen bin/tools/deepcopy-gen bin/tools/defaulter-gen bin/tools/informer-gen bin/tools/lister-gen: bin/tools/%-gen: bin/downloaded/tools/%-gen@$(K8S_CODEGEN_VERSION) | bin/tools
	@cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) $(notdir $@)

bin/downloaded/tools/%-gen@$(K8S_CODEGEN_VERSION): $(DEPENDS_ON_GO) | bin/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install k8s.io/code-generator/cmd/$(notdir $@)
	@mv $(subst @$(K8S_CODEGEN_VERSION),,$@) $@

#############
# goimports #
#############

bin/tools/goimports: bin/downloaded/tools/goimports@$(GOIMPORTS_VERSION) | bin/tools
	@cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) $(notdir $@)

bin/downloaded/tools/goimports@$(GOIMPORTS_VERSION): $(DEPENDS_ON_GO) | bin/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install golang.org/x/tools/cmd/goimports@v$(GOIMPORTS_VERSION)
	@mv $(subst @$(GOIMPORTS_VERSION),,$@) $@

#############
# gotestsum #
#############

bin/tools/gotestsum: bin/downloaded/tools/gotestsum@$(GOTESTSUM_VERSION) | bin/tools
	@cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) $(notdir $@)

bin/downloaded/tools/gotestsum@$(GOTESTSUM_VERSION): $(DEPENDS_ON_GO) | bin/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install gotest.tools/gotestsum@v$(GOTESTSUM_VERSION)
	@mv $(subst @$(GOTESTSUM_VERSION),,$@) $@

#########
# crane #
#########

bin/tools/crane: bin/downloaded/tools/crane@$(CRANE_VERSION) | bin/tools
	@cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) $(notdir $@)

bin/downloaded/tools/crane@$(CRANE_VERSION): $(DEPENDS_ON_GO) | bin/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install github.com/google/go-containerregistry/cmd/crane@v$(CRANE_VERSION)
	@mv $(subst @$(CRANE_VERSION),,$@) $@

#######
# ytt #
#######

YTT_linux_amd64_SHA256SUM=d81ecf6c47209f6ac527e503a6fd85e999c3c2f8369e972794047bddc7e5fbe2
YTT_darwin_amd64_SHA256SUM=9662e3f8e30333726a03f7a5ae6231fbfb2cebb6c1aa3f545b253d7c695487e6
YTT_darwin_arm64_SHA256SUM=c970b2c13d4059f0bee3bf3ceaa09bd0674a62c24550453d90b284d885a06b7b

bin/tools/ytt: bin/downloaded/tools/ytt_$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH) | bin/tools
	@cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) $(notdir $@)

bin/downloaded/tools/ytt_$(YTT_VERSION)_%: | bin/downloaded/tools
	curl -sSfL https://github.com/vmware-tanzu/carvel-ytt/releases/download/v$(YTT_VERSION)/ytt-$(subst _,-,$*) > $@
	./hack/util/checkhash.sh $@ $(YTT_$*_SHA256SUM)
	chmod +x $@

######
# yq #
######

YQ_linux_amd64_SHA256SUM=6b891fd5bb13820b2f6c1027b613220a690ce0ef4fc2b6c76ec5f643d5535e61
YQ_darwin_amd64_SHA256SUM=5af6162d858b1adc4ad23ef11dff19ede5565d8841ac611b09500f6741ff7f46
YQ_darwin_arm64_SHA256SUM=665ae1af7c73866cba74dd878c12ac49c091b66e46c9ed57d168b43955f5dd69

bin/tools/yq: bin/downloaded/tools/yq_$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH) | bin/tools
	@cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) $(notdir $@)

bin/downloaded/tools/yq_$(YQ_VERSION)_%: | bin/downloaded/tools
	curl -sSfL https://github.com/mikefarah/yq/releases/download/v$(YQ_VERSION)/yq_$* > $@
	./hack/util/checkhash.sh $@ $(YQ_$*_SHA256SUM)
	chmod +x $@

############################
# kubebuilder-tools assets #
# kube-apiserver / etcd    #
############################

KUBEBUILDER_TOOLS_linux_amd64_SHA256SUM=25daf3c5d7e8b63ea933e11cd6ca157868d71a12885aba97d1e7e1a15510713e
KUBEBUILDER_TOOLS_darwin_amd64_SHA256SUM=bb27efb1d2ee43749475293408fc80b923324ab876e5da54e58594bbe2969c42

# We get our testing binaries from kubebuilder-tools, but they don't currently
# publish darwin/arm64 binaries because of a lack of etcd / kube-apiserver support;
# as such, we install the amd64 versions and hope that Rosetta sorts the problem
# out for us. This means that the hash we expect is the same as the amd64 hash.
KUBEBUILDER_TOOLS_darwin_arm64_SHA256SUM=$(KUBEBUILDER_TOOLS_darwin_amd64_SHA256SUM)

bin/tools/etcd: bin/downloaded/tools/etcd-$(HOST_OS)-$(HOST_ARCH) | bin/tools
	@cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) $(notdir $@)

bin/downloaded/tools/etcd-%: bin/downloaded/tools/kubebuilder-tools-$(KUBEBUILDER_ASSETS_VERSION)-%.tar.gz | bin/downloaded/tools
	./hack/util/checkhash.sh $< $(KUBEBUILDER_TOOLS_$(subst -,_,$*)_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $< kubebuilder/bin/etcd > $@ && chmod 775 $@

bin/tools/kube-apiserver: bin/downloaded/tools/kube-apiserver-$(HOST_OS)-$(HOST_ARCH) | bin/tools
	@cd $(dir $@) && $(LN) $(patsubst bin/%,../%,$<) $(notdir $@)

bin/downloaded/tools/kube-apiserver-%: bin/downloaded/tools/kubebuilder-tools-$(KUBEBUILDER_ASSETS_VERSION)-%.tar.gz | bin/downloaded/tools
	./hack/util/checkhash.sh $< $(KUBEBUILDER_TOOLS_$(subst -,_,$*)_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $< kubebuilder/bin/kube-apiserver > $@ && chmod 775 $@

bin/downloaded/tools/kubebuilder-tools-$(KUBEBUILDER_ASSETS_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz: | bin/downloaded/tools
ifeq ($(HOST_OS)-$(HOST_ARCH),darwin-arm64)
	@$(eval KUBEBUILDER_ARCH := amd64)
	$(warning Downloading amd64 kubebuilder-tools for integration tests since darwin/arm64 isn't currently packaged. This will require rosetta in order to work)
else
	@$(eval KUBEBUILDER_ARCH := $(HOST_ARCH))
endif
	curl -sSfL https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-$(KUBEBUILDER_ASSETS_VERSION)-$(HOST_OS)-$(KUBEBUILDER_ARCH).tar.gz > $@

bin/downloaded/gatewayapi-v%: | bin/downloaded
	@mkdir -p $@
	curl -sSfL https://github.com/kubernetes-sigs/gateway-api/archive/refs/tags/v$*.tar.gz | tar xz -C $@

bin bin/tools bin/downloaded bin/downloaded/tools:
	@mkdir -p $@

# The targets (verify_deps, verify_chart, verify_upgrade, and cluster) are
# temorary and exist to keep the compatibility with the following Prow jobs:
#
#   pull-cert-manager-chart
#   pull-cert-manager-deps
#   pull-cert-manager-upgrade
#
# Until we have removed these Bazel-based targets, we must disable the check
# of the system tools since the Bazel targets don't rely on those, and the image
#
#   eu.gcr.io/jetstack-build-infra-images/bazelbuild
#
# doesn't have these tools.
BAZEL_TARGET := $(filter verify verify_deps verify_chart verify_upgrade cluster,$(MAKECMDGOALS))
ifneq ($(BAZEL_TARGET),)
$(warning Not checking whether the system tools are present since Bazel already takes care of that in the target $(MAKECMDGOALS). .)
else
# Although we "vendor" most tools in bin/tools, we still require some binaries
# to be available on the system. The vendor-go MAKECMDGOALS trick prevents the
# check for the presence of Go when 'make vendor-go' is run.
MISSING=$(shell (command -v curl >/dev/null || echo curl) \
             && (command -v python3 >/dev/null || echo python3) \
             && (command -v perl >/dev/null || echo perl) \
             && (command -v jq >/dev/null || echo jq) \
             && (command -v sha256sum >/dev/null || echo sha256sum) \
             && (command -v git >/dev/null || echo git) \
             && ([ -n "$(findstring vendor-go,$(MAKECMDGOALS),)" ] \
                || command -v $(GO) >/dev/null || echo $(GO)) \
             && (command -v $(CTR) >/dev/null || echo $(CTR)))
ifneq ($(MISSING),)
$(error Missing required tools: $(MISSING))
endif
endif
