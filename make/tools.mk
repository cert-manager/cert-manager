GO=go
CGO_ENABLED ?= 0
GOBUILD=CGO_ENABLED=$(CGO_ENABLED) GOMAXPROCS=$(GOBUILDPROCS) $(GO) build

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
YTT_VERSION=0.36.0
YQ_VERSION=4.11.2

bin/tools:
	@mkdir -p $@

bin/scratch/tools:
	@mkdir -p $@

.PHONY: tools
tools: bin/tools/helm bin/tools/kubectl bin/tools/kind bin/tools/cosign bin/tools/release-notes bin/tools/cmrel bin/tools/ytt bin/tools/yq

########
# Helm #
########

HELM_linux_amd64_SHA256SUM=07c100849925623dc1913209cd1a30f0a9b80a5b4d6ff2153c609d11b043e262
HELM_darwin_amd64_SHA256SUM=84a1ff17dd03340652d96e8be5172a921c97825fd278a2113c8233a4e8db5236
HELM_darwin_arm64_SHA256SUM=a50b499dbd0bbec90761d50974bf1e67cc6d503ea20d03b4a1275884065b7e9e

bin/tools/helm: bin/scratch/tools/helm-v$(HELM_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz | bin/tools
	@# O writes the specified file to stdout
	tar xfO $< $(HOST_OS)-$(HOST_ARCH)/helm > $@
	chmod +x $@

bin/scratch/tools/helm-v$(HELM_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz: | bin/scratch/tools
	curl -sSfL https://get.helm.sh/helm-v$(HELM_VERSION)-$(HOST_OS)-$(HOST_ARCH).tar.gz > $@
	./hack/util/checkhash.sh $@ $(HELM_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)

###########
# kubectl #
###########

KUBECTL_linux_amd64_SHA256SUM=78178a8337fc6c76780f60541fca7199f0f1a2e9c41806bded280a4a5ef665c9
KUBECTL_darwin_amd64_SHA256SUM=00bb3947ac6ff15690f90ee1a732d0a9a44360fc7743dbfee4cba5a8f6a31413
KUBECTL_darwin_arm64_SHA256SUM=c81a314ab7f0827a5376f8ffd6d47f913df046275d44c562915a822229819d77

bin/tools/kubectl: bin/scratch/tools/kubectl_$(HOST_OS)_$(HOST_ARCH) | bin/tools
	cp $< $@
	chmod +x $@

bin/scratch/tools/kubectl_$(HOST_OS)_$(HOST_ARCH): | bin/scratch/tools
	curl -sSfL https://storage.googleapis.com/kubernetes-release/release/v$(KUBECTL_VERSION)/bin/$(HOST_OS)/$(HOST_ARCH)/kubectl > $@
	./hack/util/checkhash.sh $@ $(KUBECTL_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)

########
# kind #
########

KIND_linux_amd64_SHA256SUM=949f81b3c30ca03a3d4effdecda04f100fa3edc07a28b19400f72ede7c5f0491
KIND_darwin_amd64_SHA256SUM=432bef555a70e9360b44661c759658265b9eaaf7f75f1beec4c4d1e6bbf97ce3
KIND_darwin_arm64_SHA256SUM=4f019c578600c087908ac59dd0c4ce1791574f153a70608adb372d5abc58cd47

bin/tools/kind: bin/scratch/tools/kind_$(HOST_OS)_$(HOST_ARCH) | bin/tools
	cp $< $@
	chmod +x $@

bin/scratch/tools/kind_$(HOST_OS)_$(HOST_ARCH): | bin/scratch/tools
	curl -sSfL https://github.com/kubernetes-sigs/kind/releases/download/v$(KIND_VERSION)/kind-$(HOST_OS)-$(HOST_ARCH) > $@
	./hack/util/checkhash.sh $@ $(KIND_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)

##########
# cosign #
##########

COSIGN_linux_amd64_SHA256SUM=1227b270e5d7d21d09469253cce17b72a14f6b7c9036dfc09698c853b31e8fc8
COSIGN_darwin_amd64_SHA256SUM=bcffa19e80f3e94d70e1fb1b0f591b0dec08926b31d3609fe3d25a1cc0389a0a
COSIGN_darwin_arm64_SHA256SUM=eda58f090d8f4f1db5a0e3a0d2d8845626181fe8aa1cea1791e0afa87fee7b5c

bin/tools/cosign: bin/scratch/tools/cosign_$(HOST_OS)_$(HOST_ARCH) | bin/tools
	cp $< $@
	chmod +x $@

# TODO: cosign also provides signatures on all of its binaries, but they can't be validated without already having cosign
# available! We could do something like "if system cosign is available, verify using that", but for now we'll skip
bin/scratch/tools/cosign_$(HOST_OS)_$(HOST_ARCH): | bin/scratch/tools
	curl -sSfL https://github.com/sigstore/cosign/releases/download/v$(COSIGN_VERSION)/cosign-$(HOST_OS)-$(HOST_ARCH) > $@
	./hack/util/checkhash.sh $@ $(COSIGN_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)

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

#######
# ytt #
#######

YTT_linux_amd64_SHA256SUM=d81ecf6c47209f6ac527e503a6fd85e999c3c2f8369e972794047bddc7e5fbe2
YTT_darwin_amd64_SHA256SUM=9662e3f8e30333726a03f7a5ae6231fbfb2cebb6c1aa3f545b253d7c695487e6
YTT_darwin_arm64_SHA256SUM=c970b2c13d4059f0bee3bf3ceaa09bd0674a62c24550453d90b284d885a06b7b

bin/tools/ytt: bin/scratch/tools/ytt_$(HOST_OS)_$(HOST_ARCH) | bin/tools
	cp $< $@
	chmod +x $@

bin/scratch/tools/ytt_$(HOST_OS)_$(HOST_ARCH): | bin/scratch/tools
	curl -sSfL https://github.com/vmware-tanzu/carvel-ytt/releases/download/v$(YTT_VERSION)/ytt-$(HOST_OS)-$(HOST_ARCH) > $@
	./hack/util/checkhash.sh $@ $(YTT_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)

######
# yq #
######

YQ_linux_amd64_SHA256SUM=6b891fd5bb13820b2f6c1027b613220a690ce0ef4fc2b6c76ec5f643d5535e61
YQ_darwin_amd64_SHA256SUM=5af6162d858b1adc4ad23ef11dff19ede5565d8841ac611b09500f6741ff7f46
YQ_darwin_arm64_SHA256SUM=665ae1af7c73866cba74dd878c12ac49c091b66e46c9ed57d168b43955f5dd69

bin/tools/yq: bin/scratch/tools/yq_$(HOST_OS)_$(HOST_ARCH) | bin/tools
	cp $< $@
	chmod +x $@

bin/scratch/tools/yq_$(HOST_OS)_$(HOST_ARCH): | bin/scratch/tools
	curl -sSfL https://github.com/mikefarah/yq/releases/download/v$(YQ_VERSION)/yq_$(HOST_OS)_$(HOST_ARCH) > $@
	./hack/util/checkhash.sh $@ $(YQ_$(HOST_OS)_$(HOST_ARCH)_SHA256SUM)
