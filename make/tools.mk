GO=go
CGO_ENABLED ?= 0

GOBUILD=CGO_ENABLED=$(CGO_ENABLED) GOMAXPROCS=$(GOBUILDPROCS) $(GO) build
GOTEST=CGO_ENABLED=$(CGO_ENABLED) $(GO) test

GOTESTSUM=CGO_ENABLED=$(CGO_ENABLED) ./bin/tools/gotestsum

CTR=docker

WORKDIR=$(shell pwd)
HELM=$(WORKDIR)/bin/tools/helm
COSIGN=$(WORKDIR)/bin/tools/cosign
CMREL=$(WORKDIR)/bin/tools/cmrel
YQ=$(WORKDIR)/bin/tools/yq

HELM_VERSION=3.6.3
KUBECTL_VERSION=1.22.1
KIND_VERSION=0.11.1
COSIGN_VERSION=1.3.1
CMREL_VERSION=a1e2bad95be9688794fd0571c4c40e88cccf9173
K8S_RELEASE_NOTES_VERSION=0.7.0
GOIMPORTS_VERSION=0.1.8
GOTESTSUM_VERSION=1.7.0
YTT_VERSION=0.36.0
YQ_VERSION=4.11.2

KUBEBUILDER_ASSETS_VERSION=1.22.0

bin/tools:
	@mkdir -p $@

bin/scratch/tools:
	@mkdir -p $@

.PHONY: tools
tools: bin/tools/helm bin/tools/kubectl bin/tools/kind bin/tools/cosign bin/tools/ginkgo bin/tools/cmrel bin/tools/release-notes bin/tools/goimports bin/tools/gotestsum bin/tools/ytt bin/tools/yq

.PHONY: integration-test-tools
integration-test-tools: bin/tools/etcd bin/tools/kubectl bin/tools/kube-apiserver

########
# Helm #
########

HELM_linux_amd64_SHA256SUM=07c100849925623dc1913209cd1a30f0a9b80a5b4d6ff2153c609d11b043e262
HELM_darwin_amd64_SHA256SUM=84a1ff17dd03340652d96e8be5172a921c97825fd278a2113c8233a4e8db5236
HELM_darwin_arm64_SHA256SUM=a50b499dbd0bbec90761d50974bf1e67cc6d503ea20d03b4a1275884065b7e9e

bin/tools/helm: bin/scratch/tools/helm-v$(HELM_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz | bin/tools
	./hack/util/checkhash.sh $< $(HELM_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $< $(HOST_OS)-$(HOST_ARCH)/helm > $@
	chmod +x $@

bin/scratch/tools/helm-v$(HELM_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz: | bin/scratch/tools
	curl -sSfL https://get.helm.sh/helm-v$(HELM_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz > $@

###########
# kubectl #
###########

KUBECTL_linux_amd64_SHA256SUM=78178a8337fc6c76780f60541fca7199f0f1a2e9c41806bded280a4a5ef665c9
KUBECTL_darwin_amd64_SHA256SUM=00bb3947ac6ff15690f90ee1a732d0a9a44360fc7743dbfee4cba5a8f6a31413
KUBECTL_darwin_arm64_SHA256SUM=c81a314ab7f0827a5376f8ffd6d47f913df046275d44c562915a822229819d77

bin/tools/kubectl: bin/scratch/tools/kubectl_$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH) | bin/tools
	./hack/util/checkhash.sh $< $(KUBECTL_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)
	cp $< $@
	chmod +x $@

bin/scratch/tools/kubectl_$(KUBECTL_VERSION)_$(HOST_OS)_$(HOST_ARCH): | bin/scratch/tools
	curl -sSfL https://storage.googleapis.com/kubernetes-release/release/v$(KUBECTL_VERSION)/bin/$(HOST_OS)/$(HOST_ARCH)/kubectl > $@

########
# kind #
########

KIND_linux_amd64_SHA256SUM=949f81b3c30ca03a3d4effdecda04f100fa3edc07a28b19400f72ede7c5f0491
KIND_darwin_amd64_SHA256SUM=432bef555a70e9360b44661c759658265b9eaaf7f75f1beec4c4d1e6bbf97ce3
KIND_darwin_arm64_SHA256SUM=4f019c578600c087908ac59dd0c4ce1791574f153a70608adb372d5abc58cd47

bin/tools/kind: bin/scratch/tools/kind_$(KIND_VERSION)_$(HOST_OS)_$(HOST_ARCH) | bin/tools
	./hack/util/checkhash.sh $< $(KIND_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)
	cp $< $@
	chmod +x $@

bin/scratch/tools/kind_$(KIND_VERSION)_$(HOST_OS)_$(HOST_ARCH): | bin/scratch/tools
	curl -sSfL https://github.com/kubernetes-sigs/kind/releases/download/v$(KIND_VERSION)/kind-$(HOST_OS)-$(HOST_ARCH) > $@

##########
# cosign #
##########

COSIGN_linux_amd64_SHA256SUM=1227b270e5d7d21d09469253cce17b72a14f6b7c9036dfc09698c853b31e8fc8
COSIGN_darwin_amd64_SHA256SUM=bcffa19e80f3e94d70e1fb1b0f591b0dec08926b31d3609fe3d25a1cc0389a0a
COSIGN_darwin_arm64_SHA256SUM=eda58f090d8f4f1db5a0e3a0d2d8845626181fe8aa1cea1791e0afa87fee7b5c

bin/tools/cosign: bin/scratch/tools/cosign_$(COSIGN_VERSION)_$(HOST_OS)_$(HOST_ARCH) | bin/tools
	./hack/util/checkhash.sh $< $(COSIGN_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)
	cp $< $@
	chmod +x $@

# TODO: cosign also provides signatures on all of its binaries, but they can't be validated without already having cosign
# available! We could do something like "if system cosign is available, verify using that", but for now we'll skip
bin/scratch/tools/cosign_$(COSIGN_VERSION)_$(HOST_OS)_$(HOST_ARCH): | bin/scratch/tools
	curl -sSfL https://github.com/sigstore/cosign/releases/download/v$(COSIGN_VERSION)/cosign-$(HOST_OS)-$(HOST_ARCH) > $@

##########
# ginkgo #
##########

# We don't specify a version number here because we want to use the version in cert-manager's go.mod
bin/tools/ginkgo: go.mod go.sum | bin/tools
	GOBIN=$(shell pwd)/$(dir $@) go install github.com/onsi/ginkgo/ginkgo

#########
# cmrel #
#########

bin/tools/cmrel: | bin/tools
	GOBIN=$(shell pwd)/$(dir $@) go install github.com/cert-manager/release/cmd/cmrel@$(CMREL_VERSION)

#################
# release-notes #
#################

bin/tools/release-notes: | bin/tools
	GOBIN=$(shell pwd)/$(dir $@) go install k8s.io/release/cmd/release-notes@v$(K8S_RELEASE_NOTES_VERSION)

#############
# goimports #
#############

bin/tools/goimports: | bin/tools
	GOBIN=$(shell pwd)/$(dir $@) go install golang.org/x/tools/cmd/goimports@v$(GOIMPORTS_VERSION)

#############
# gotestsum #
#############

bin/tools/gotestsum : | bin/tools
	GOBIN=$(shell pwd)/$(dir $@) go install gotest.tools/gotestsum@v$(GOTESTSUM_VERSION)

#######
# ytt #
#######

YTT_linux_amd64_SHA256SUM=d81ecf6c47209f6ac527e503a6fd85e999c3c2f8369e972794047bddc7e5fbe2
YTT_darwin_amd64_SHA256SUM=9662e3f8e30333726a03f7a5ae6231fbfb2cebb6c1aa3f545b253d7c695487e6
YTT_darwin_arm64_SHA256SUM=c970b2c13d4059f0bee3bf3ceaa09bd0674a62c24550453d90b284d885a06b7b

bin/tools/ytt: bin/scratch/tools/ytt_$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH) | bin/tools
	./hack/util/checkhash.sh $< $(YTT_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)
	cp $< $@
	chmod +x $@

bin/scratch/tools/ytt_$(YTT_VERSION)_$(HOST_OS)_$(HOST_ARCH): | bin/scratch/tools
	curl -sSfL https://github.com/vmware-tanzu/carvel-ytt/releases/download/v$(YTT_VERSION)/ytt-$(HOST_OS)-$(HOST_ARCH) > $@

######
# yq #
######

YQ_linux_amd64_SHA256SUM=6b891fd5bb13820b2f6c1027b613220a690ce0ef4fc2b6c76ec5f643d5535e61
YQ_darwin_amd64_SHA256SUM=5af6162d858b1adc4ad23ef11dff19ede5565d8841ac611b09500f6741ff7f46
YQ_darwin_arm64_SHA256SUM=665ae1af7c73866cba74dd878c12ac49c091b66e46c9ed57d168b43955f5dd69

bin/tools/yq: bin/scratch/tools/yq_$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH) | bin/tools
	./hack/util/checkhash.sh $< $(YQ_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)
	cp $< $@
	chmod +x $@

bin/scratch/tools/yq_$(YQ_VERSION)_$(HOST_OS)_$(HOST_ARCH): | bin/scratch/tools
	curl -sSfL https://github.com/mikefarah/yq/releases/download/v$(YQ_VERSION)/yq_$(HOST_OS)_$(HOST_ARCH) > $@

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

bin/tools/etcd: bin/scratch/tools/kubebuilder-tools-$(KUBEBUILDER_ASSETS_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz | bin/tools
	./hack/util/checkhash.sh $< $(KUBEBUILDER_TOOLS_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $< kubebuilder/bin/etcd > $@ && chmod 775 $@

bin/tools/kube-apiserver: bin/scratch/tools/kubebuilder-tools-$(KUBEBUILDER_ASSETS_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz | bin/tools
	./hack/util/checkhash.sh $< $(KUBEBUILDER_TOOLS_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)
	@# O writes the specified file to stdout
	tar xfO $< kubebuilder/bin/kube-apiserver > $@ && chmod 775 $@

bin/scratch/tools/kubebuilder-tools-$(KUBEBUILDER_ASSETS_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz: | bin/scratch/tools
ifeq ($(HOST_OS)-$(HOST_ARCH),darwin-arm64)
	$(eval KUBEBUILDER_ARCH := amd64)
	$(warning Downloading amd64 kubebuilder-tools for integration tests since darwin/arm64 isn't currently packaged. This will require rosetta in order to work)
else
	$(eval KUBEBUILDER_ARCH := $(HOST_ARCH))
endif
	curl -sSfL https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-$(KUBEBUILDER_ASSETS_VERSION)-$(HOST_OS)-$(KUBEBUILDER_ARCH).tar.gz > $@
