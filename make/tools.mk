# To make sure we use the right version of each tool, we put symlink in
# $(BINDIR)/tools, and the actual binaries are in $(BINDIR)/downloaded. When bumping
# the version of the tools, this symlink gets updated.

# Let's have $(BINDIR)/tools in front of the PATH so that we don't inavertedly
# pick up the wrong binary somewhere. Watch out, $(shell echo $$PATH) will
# still print the original PATH, since GNU make does not honor exported
# variables: https://stackoverflow.com/questions/54726457
export PATH := $(PWD)/$(BINDIR)/tools:$(PATH)

CTR=docker

# We have a variable for cmrel since one of the targets which uses it
# requires an absolute path to the tool.
CMREL=$(PWD)/$(BINDIR)/tools/cmrel

HELM_VERSION=3.8.0
KUBECTL_VERSION=1.24.2
KIND_VERSION=0.14.0
CONTROLLER_GEN_VERSION=0.8.0
COSIGN_VERSION=1.3.1
CMREL_VERSION=a1e2bad95be9688794fd0571c4c40e88cccf9173
K8S_RELEASE_NOTES_VERSION=0.7.0
GATEWAY_API_VERSION = 0.4.1
GOIMPORTS_VERSION=0.1.8
GOLICENSES_VERSION=1.2.1
GOTESTSUM_VERSION=1.7.0
RCLONE_VERSION=1.58.1
YTT_VERSION=0.36.0
YQ_VERSION=4.25.3
CRANE_VERSION=0.8.0
GINKGO_VERSION=$(shell awk '/ginkgo/ {print $$2}' go.mod)

K8S_CODEGEN_VERSION=v0.24.2

KUBEBUILDER_ASSETS_VERSION=1.24.2

VENDORED_GO_VERSION := 1.18.3

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
endif

# --silent = don't print output like progress meters
# --show-error = but do print errors when they happen
# --fail = exit with a nonzero error code without the response from the server when there's an HTTP error
# --location = follow redirects from the server
# --retry = the number of times to retry a failed attempt to connect
# --retry-connrefused = retry even if the initial connection was refused
CURL = curl --silent --show-error --fail --location --retry 10 --retry-connrefused

.PHONY: tools
tools: $(BINDIR)/tools/helm $(BINDIR)/tools/kubectl $(BINDIR)/tools/kind $(BINDIR)/tools/cosign $(BINDIR)/tools/ginkgo $(BINDIR)/tools/cmrel $(BINDIR)/tools/release-notes $(BINDIR)/tools/controller-gen k8s-codegen-tools $(BINDIR)/tools/goimports $(BINDIR)/tools/go-licenses $(BINDIR)/tools/gotestsum $(BINDIR)/tools/rclone $(BINDIR)/tools/ytt $(BINDIR)/tools/yq

######
# Go #
######

GO = go

# DEPENDS_ON_GO is a target that is set as an order-only prerequisite in
# any target that calls $(GO), e.g.:
#
#     $(BINDIR)/tools/crane: $(DEPENDS_ON_GO)
#         $(GO) build -o $(BINDIR)/tools/crane
#
# DEPENDS_ON_GO is empty most of the time, except when running "make
# vendor-go" or when "make vendor-go" was previously run, in which case
# DEPENDS_ON_GO is set to $(BINDIR)/tools/go, since $(BINDIR)/tools/go is a
# prerequisite of any target depending on Go when "make vendor-go" was run.
DEPENDS_ON_GO := $(if $(findstring vendor-go,$(MAKECMDGOALS))$(shell [ -f $(BINDIR)/tools/go ] && echo yes), $(BINDIR)/tools/go,)
ifneq ($(DEPENDS_ON_GO),)
export GOROOT := $(PWD)/$(BINDIR)/tools/goroot
export PATH := $(PWD)/$(BINDIR)/tools/goroot/bin:$(PATH)
GO := $(PWD)/$(BINDIR)/tools/go
endif

GOBUILD=CGO_ENABLED=$(CGO_ENABLED) GOMAXPROCS=$(GOBUILDPROCS) $(GO) build
GOTEST=CGO_ENABLED=$(CGO_ENABLED) $(GO) test

GOTESTSUM=CGO_ENABLED=$(CGO_ENABLED) ./$(BINDIR)/tools/gotestsum

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
which-go: |  $(DEPENDS_ON_GO)
	@$(GO) version
	@echo "go binary used for above version information: $(GO)"

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

########
# Helm #
########

HELM_linux_amd64_SHA256SUM=8408c91e846c5b9ba15eb6b1a5a79fc22dd4d33ac6ea63388e5698d1b2320c8b
HELM_darwin_amd64_SHA256SUM=532ddd6213891084873e5c2dcafa577f425ca662a6594a3389e288fc48dc2089
HELM_darwin_arm64_SHA256SUM=751348f1a4a876ffe089fd68df6aea310fd05fe3b163ab76aa62632e327122f3

$(BINDIR)/tools/helm: $(BINDIR)/downloaded/tools/helm-v$(HELM_VERSION)-$(HOST_OS)-$(HOST_ARCH) $(BINDIR)/scratch/HELM_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

$(BINDIR)/downloaded/tools/helm-v$(HELM_VERSION)-%: | $(BINDIR)/downloaded/tools
	$(CURL) https://get.helm.sh/helm-v$(HELM_VERSION)-$*.tar.gz -o $@.tar.gz
	./hack/util/checkhash.sh $@.tar.gz $(HELM_$(subst -,_,$*)_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $@.tar.gz $*/helm > $@
	chmod +x $@
	rm -f $@.tar.gz

###########
# kubectl #
###########

KUBECTL_linux_amd64_SHA256SUM=f15fb430afd79f79ef7cf94a4e402cd212f02d8ec5a5e6a7ba9c3d5a2f954542
KUBECTL_darwin_amd64_SHA256SUM=50598bf557113300c925e53140f53fc5d0fb8783e8033f73561d873ee6ff2fea
KUBECTL_darwin_arm64_SHA256SUM=a9c33de9b14e565ec380e3a7034040bf9a0561937c55c859253271ff7e45813c

$(BINDIR)/tools/kubectl: $(BINDIR)/downloaded/tools/kubectl_$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH) $(BINDIR)/scratch/KUBECTL_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

$(BINDIR)/downloaded/tools/kubectl_$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH): | $(BINDIR)/downloaded/tools
	$(CURL) https://storage.googleapis.com/kubernetes-release/release/v$(KUBECTL_VERSION)/bin/$(HOST_OS)/$(HOST_ARCH)/kubectl -o $@
	./hack/util/checkhash.sh $@ $(KUBECTL_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)
	chmod +x $@

########
# kind #
########

KIND_linux_amd64_SHA256SUM=af5e8331f2165feab52ec2ae07c427c7b66f4ad044d09f253004a20252524c8b
KIND_darwin_amd64_SHA256SUM=fdf7209e5f92651ee5d55b78eb4ee5efded0d28c3f3ab8a4a163b6ffd92becfd
KIND_darwin_arm64_SHA256SUM=bdbb6e94bc8c846b0a6a1df9f962fe58950d92b26852fd6ebdc48fabb229932c

$(BINDIR)/tools/kind: $(BINDIR)/downloaded/tools/kind_$(KIND_VERSION)_$(HOST_OS)_$(HOST_ARCH) $(BINDIR)/scratch/KIND_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

$(BINDIR)/downloaded/tools/kind_$(KIND_VERSION)_%: | $(BINDIR)/downloaded/tools $(BINDIR)/tools
	$(CURL) -sSfL https://github.com/kubernetes-sigs/kind/releases/download/v$(KIND_VERSION)/kind-$(subst _,-,$*) -o $@
	./hack/util/checkhash.sh $@ $(KIND_$*_SHA256SUM)
	chmod +x $@

##########
# cosign #
##########

COSIGN_linux_amd64_SHA256SUM=1227b270e5d7d21d09469253cce17b72a14f6b7c9036dfc09698c853b31e8fc8
COSIGN_darwin_amd64_SHA256SUM=bcffa19e80f3e94d70e1fb1b0f591b0dec08926b31d3609fe3d25a1cc0389a0a
COSIGN_darwin_arm64_SHA256SUM=eda58f090d8f4f1db5a0e3a0d2d8845626181fe8aa1cea1791e0afa87fee7b5c

$(BINDIR)/tools/cosign: $(BINDIR)/downloaded/tools/cosign_$(COSIGN_VERSION)_$(HOST_OS)_$(HOST_ARCH) $(BINDIR)/scratch/COSIGN_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

# TODO: cosign also provides signatures on all of its binaries, but they can't be validated without already having cosign
# available! We could do something like "if system cosign is available, verify using that", but for now we'll skip
$(BINDIR)/downloaded/tools/cosign_$(COSIGN_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(CURL) https://github.com/sigstore/cosign/releases/download/v$(COSIGN_VERSION)/cosign-$(subst _,-,$*) -o $@
	./hack/util/checkhash.sh $@ $(COSIGN_$*_SHA256SUM)
	chmod +x $@

##########
# ginkgo #
##########

$(BINDIR)/tools/ginkgo: $(BINDIR)/downloaded/tools/ginkgo@$(GINKGO_VERSION) $(BINDIR)/scratch/GINKGO_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

$(BINDIR)/downloaded/tools/ginkgo@$(GINKGO_VERSION): $(DEPENDS_ON_GO) | $(BINDIR)/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install github.com/onsi/ginkgo/ginkgo@$(GINKGO_VERSION)
	@mv $(subst @$(GINKGO_VERSION),,$@) $@

#########
# cmrel #
#########

$(BINDIR)/tools/cmrel: $(BINDIR)/downloaded/tools/cmrel@$(CMREL_VERSION) $(BINDIR)/scratch/CMREL_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

$(BINDIR)/downloaded/tools/cmrel@$(CMREL_VERSION): $(DEPENDS_ON_GO) | $(BINDIR)/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install github.com/cert-manager/release/cmd/cmrel@$(CMREL_VERSION)
	@mv $(subst @$(CMREL_VERSION),,$@) $@

#################
# release-notes #
#################

$(BINDIR)/tools/release-notes: $(BINDIR)/downloaded/tools/release-notes@$(K8S_RELEASE_NOTES_VERSION) $(BINDIR)/scratch/K8S_RELEASE_NOTES_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

$(BINDIR)/downloaded/tools/release-notes@$(K8S_RELEASE_NOTES_VERSION): $(DEPENDS_ON_GO) | $(BINDIR)/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install k8s.io/release/cmd/release-notes@v$(K8S_RELEASE_NOTES_VERSION)
	@mv $(subst @$(K8S_RELEASE_NOTES_VERSION),,$@) $@

##################
# controller-gen #
##################

$(BINDIR)/tools/controller-gen: $(BINDIR)/downloaded/tools/controller-gen@$(CONTROLLER_GEN_VERSION) $(BINDIR)/scratch/CONTROLLER_GEN_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

$(BINDIR)/downloaded/tools/controller-gen@$(CONTROLLER_GEN_VERSION): $(DEPENDS_ON_GO) | $(BINDIR)/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install sigs.k8s.io/controller-tools/cmd/controller-gen@v$(CONTROLLER_GEN_VERSION)
	@mv $(subst @$(CONTROLLER_GEN_VERSION),,$@) $@

#####################
# k8s codegen tools #
#####################

.PHONY: k8s-codegen-tools
k8s-codegen-tools: $(BINDIR)/tools/client-gen $(BINDIR)/tools/conversion-gen $(BINDIR)/tools/deepcopy-gen $(BINDIR)/tools/defaulter-gen $(BINDIR)/tools/informer-gen $(BINDIR)/tools/lister-gen

$(BINDIR)/tools/client-gen $(BINDIR)/tools/conversion-gen $(BINDIR)/tools/deepcopy-gen $(BINDIR)/tools/defaulter-gen $(BINDIR)/tools/informer-gen $(BINDIR)/tools/lister-gen: $(BINDIR)/tools/%-gen: $(BINDIR)/downloaded/tools/%-gen@$(K8S_CODEGEN_VERSION) $(BINDIR)/scratch/K8S_CODEGEN_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

$(BINDIR)/downloaded/tools/%-gen@$(K8S_CODEGEN_VERSION): $(DEPENDS_ON_GO) | $(BINDIR)/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install k8s.io/code-generator/cmd/$(notdir $@)
	@mv $(subst @$(K8S_CODEGEN_VERSION),,$@) $@

#############
# goimports #
#############

$(BINDIR)/tools/goimports: $(BINDIR)/downloaded/tools/goimports@$(GOIMPORTS_VERSION) $(BINDIR)/scratch/GOIMPORTS_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

$(BINDIR)/downloaded/tools/goimports@$(GOIMPORTS_VERSION): $(DEPENDS_ON_GO) | $(BINDIR)/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install golang.org/x/tools/cmd/goimports@v$(GOIMPORTS_VERSION)
	@mv $(subst @$(GOIMPORTS_VERSION),,$@) $@

###############
# go-licenses #
###############

$(BINDIR)/tools/go-licenses: $(BINDIR)/downloaded/tools/go-licenses@$(GOLICENSES_VERSION) $(BINDIR)/scratch/GOLICENSES_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

$(BINDIR)/downloaded/tools/go-licenses@$(GOLICENSES_VERSION): $(DEPENDS_ON_GO) | $(BINDIR)/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install github.com/google/go-licenses@v$(GOLICENSES_VERSION)
	@mv $(subst @$(GOLICENSES_VERSION),,$@) $@

#############
# gotestsum #
#############

$(BINDIR)/tools/gotestsum: $(BINDIR)/downloaded/tools/gotestsum@$(GOTESTSUM_VERSION) $(BINDIR)/scratch/GOTESTSUM_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

$(BINDIR)/downloaded/tools/gotestsum@$(GOTESTSUM_VERSION): $(DEPENDS_ON_GO) | $(BINDIR)/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install gotest.tools/gotestsum@v$(GOTESTSUM_VERSION)
	@mv $(subst @$(GOTESTSUM_VERSION),,$@) $@

#########
# crane #
#########

$(BINDIR)/tools/crane: $(BINDIR)/downloaded/tools/crane@$(CRANE_VERSION) $(BINDIR)/scratch/CRANE_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

$(BINDIR)/downloaded/tools/crane@$(CRANE_VERSION): $(DEPENDS_ON_GO) | $(BINDIR)/downloaded/tools
	GOBIN=$(PWD)/$(dir $@) $(GO) install github.com/google/go-containerregistry/cmd/crane@v$(CRANE_VERSION)
	@mv $(subst @$(CRANE_VERSION),,$@) $@

##########
# rclone #
##########

RCLONE_OS := $(HOST_OS)
ifeq (darwin, $(HOST_OS))
	# rclone calls macOS "osx" not "darwin"
	RCLONE_OS = osx
endif

RCLONE_linux_amd64_SHA256SUM=135a4a0965cb58eafb07941f2013a82282c44c28fea9595587778e969d9ed035
RCLONE_osx_amd64_SHA256SUM=03b104accc26d5aec14088c253ea5a6bba3263ae00fc403737cabceecad9eae9
RCLONE_osx_arm64_SHA256SUM=eb547bd0ef2037118a01003bed6cf00a1d6e6975b6f0a73cb811f882a3c3de72

$(BINDIR)/tools/rclone: $(BINDIR)/downloaded/tools/rclone-v$(RCLONE_VERSION)-$(RCLONE_OS)-$(HOST_ARCH) $(BINDIR)/scratch/RCLONE_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

$(BINDIR)/downloaded/tools/rclone-v$(RCLONE_VERSION)-%: | $(BINDIR)/downloaded/tools
	$(CURL) https://github.com/rclone/rclone/releases/download/v$(RCLONE_VERSION)/rclone-v$(RCLONE_VERSION)-$*.zip -o $@.zip
	./hack/util/checkhash.sh $@.zip $(RCLONE_$(subst -,_,$*)_SHA256SUM)
	@# -p writes to stdout, the second file arg specifies the sole file we
	@# want to extract
	unzip -p $@.zip $(notdir $@)/rclone > $@
	chmod +x $@
	rm -f $@.zip

#######
# ytt #
#######

YTT_linux_amd64_SHA256SUM=d81ecf6c47209f6ac527e503a6fd85e999c3c2f8369e972794047bddc7e5fbe2
YTT_darwin_amd64_SHA256SUM=9662e3f8e30333726a03f7a5ae6231fbfb2cebb6c1aa3f545b253d7c695487e6
YTT_darwin_arm64_SHA256SUM=c970b2c13d4059f0bee3bf3ceaa09bd0674a62c24550453d90b284d885a06b7b

$(BINDIR)/tools/ytt: $(BINDIR)/downloaded/tools/ytt_$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH) $(BINDIR)/scratch/YTT_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

$(BINDIR)/downloaded/tools/ytt_$(YTT_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(CURL) -sSfL https://github.com/vmware-tanzu/carvel-ytt/releases/download/v$(YTT_VERSION)/ytt-$(subst _,-,$*) -o $@
	./hack/util/checkhash.sh $@ $(YTT_$*_SHA256SUM)
	chmod +x $@

######
# yq #
######

YQ_linux_amd64_SHA256SUM=cb66f4382a65d0443824f0a0fcda9c5c5f7b6bd4e4346539b2f0abc647ecf0ea
YQ_darwin_amd64_SHA256SUM=3b80429a6118defa8726629a801e0f5f49e544b7279e3dde526b99bab5b6b5bd
YQ_darwin_arm64_SHA256SUM=db9be0f73e7fbcba1039e405abc2a834cdc64ac3f90c7b79090b242e0002193c

$(BINDIR)/tools/yq: $(BINDIR)/downloaded/tools/yq_$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH) $(BINDIR)/scratch/YQ_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

$(BINDIR)/downloaded/tools/yq_$(YQ_VERSION)_%: | $(BINDIR)/downloaded/tools
	$(CURL) https://github.com/mikefarah/yq/releases/download/v$(YQ_VERSION)/yq_$* -o $@
	./hack/util/checkhash.sh $@ $(YQ_$*_SHA256SUM)
	chmod +x $@

############################
# kubebuilder-tools assets #
# kube-apiserver / etcd    #
############################

KUBEBUILDER_TOOLS_linux_amd64_SHA256SUM=6d9f0a6ab0119c5060799b4b8cbd0a030562da70b7ad4125c218eaf028c6cc28
KUBEBUILDER_TOOLS_darwin_amd64_SHA256SUM=3367987e2b40dadb5081a92a59d82664bee923eeeea77017ec88daf735e26cae
KUBEBUILDER_TOOLS_darwin_arm64_SHA256SUM=4b440713e32ca496a0a96c8e6cdc531afe9f9c2cc8d7e8e4eddfb5eb9bdc779f

$(BINDIR)/tools/etcd: $(BINDIR)/downloaded/tools/etcd-kubebuilder-$(KUBEBUILDER_ASSETS_VERSION)-$(HOST_OS)-$(HOST_ARCH) $(BINDIR)/scratch/KUBEBUILDER_ASSETS_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

$(BINDIR)/downloaded/tools/etcd-kubebuilder-$(KUBEBUILDER_ASSETS_VERSION)-%: $(BINDIR)/downloaded/tools/kubebuilder-tools-$(KUBEBUILDER_ASSETS_VERSION)-%.tar.gz | $(BINDIR)/downloaded/tools
	./hack/util/checkhash.sh $< $(KUBEBUILDER_TOOLS_$(subst -,_,$*)_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $< kubebuilder/bin/etcd > $@ && chmod 775 $@

$(BINDIR)/tools/kube-apiserver: $(BINDIR)/downloaded/tools/kube-apiserver-kubebuilder-$(KUBEBUILDER_ASSETS_VERSION)-$(HOST_OS)-$(HOST_ARCH) $(BINDIR)/scratch/KUBEBUILDER_ASSETS_VERSION | $(BINDIR)/tools
	@cd $(dir $@) && $(LN) $(patsubst $(BINDIR)/%,../%,$<) $(notdir $@)

$(BINDIR)/downloaded/tools/kube-apiserver-kubebuilder-$(KUBEBUILDER_ASSETS_VERSION)-%: $(BINDIR)/downloaded/tools/kubebuilder-tools-$(KUBEBUILDER_ASSETS_VERSION)-%.tar.gz | $(BINDIR)/downloaded/tools
	./hack/util/checkhash.sh $< $(KUBEBUILDER_TOOLS_$(subst -,_,$*)_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $< kubebuilder/bin/kube-apiserver > $@ && chmod 775 $@

$(BINDIR)/downloaded/tools/kubebuilder-tools-$(KUBEBUILDER_ASSETS_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz: | $(BINDIR)/downloaded/tools
	$(CURL) https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-$(KUBEBUILDER_ASSETS_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz -o $@

##############
# gatewayapi #
##############

GATEWAY_API_SHA256SUM=0eed80ad85850a6cbd17ab705aea59e49641c7bf1e6d3fbed1fc0156ffd62734

$(BINDIR)/downloaded/gatewayapi-v$(GATEWAY_API_VERSION): $(BINDIR)/downloaded/gatewayapi-v$(GATEWAY_API_VERSION).tar.gz | $(BINDIR)/downloaded
	./hack/util/checkhash.sh $< $(GATEWAY_API_SHA256SUM)
	@mkdir -p $@
	tar xz -C $@ -f $<

$(BINDIR)/downloaded/gatewayapi-v$(GATEWAY_API_VERSION).tar.gz: | $(BINDIR)/downloaded
	$(CURL) https://github.com/kubernetes-sigs/gateway-api/archive/refs/tags/v$(GATEWAY_API_VERSION).tar.gz -o $@

#################
# Other Targets #
#################

$(BINDIR)/tools $(BINDIR)/downloaded $(BINDIR)/downloaded/tools:
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

.PHONY: update-kind-images
update-kind-images: $(BINDIR)/tools/crane
	CRANE=./$(BINDIR)/tools/crane ./hack/latest-kind-images.sh
