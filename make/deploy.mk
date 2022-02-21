# On arm64, you can force the use of amd64 images:
#
#   make deploy CRI_ARCH=amd64
#   make kind-load CRI_ARCH=amd64
#
CRI_ARCH ?= $(HOST_ARCH)

# The commas in FEATURE_GATES have been kept for backwards compatibility with
# our previous Bazel/scripts.
FEATURE_GATES ?= AdditionalCertificateOutputFormats=true,ExperimentalCertificateSigningRequestControllers=true,ExperimentalGatewayAPISupport=true,ServerSideApply=true

# In make, there is no way to escape commas or spaces. So we use the variables
# $(space) and $(comma) instead.
null  =
space = $(null) #
comma = ,

FEATURE_GATES_CONTROLLER = $(subst $(space),$(comma),$(filter AllAlpha=% AllBeta=% AdditionalCertificateOutputFormats=% ValidateCAA=% ExperimentalCertificateSigningRequestControllers=% ExperimentalGatewayAPISupport=% ServerSideApply=%, $(subst $(comma),$(space),$(FEATURE_GATES))))
FEATURE_GATES_WEBHOOK = $(subst $(space),$(comma),$(filter AllAlpha=% AllBeta=% AdditionalCertificateOutputFormats=% , $(subst $(comma),$(space),$(FEATURE_GATES))))
FEATURE_GATES_CAINJECTOR = $(subst $(space),$(comma),$(filter AllAlpha=% AllBeta=%, $(subst $(comma),$(space),$(FEATURE_GATES))))

K8S_VERSION = 1.23

IMAGE_ingressnginx_amd64=k8s.gcr.io/ingress-nginx/controller:v1.1.0@sha256:7464dc90abfaa084204176bcc0728f182b0611849395787143f6854dc6c38c8
IMAGE_kyverno_amd64=ghcr.io/kyverno/kyverno:v1.3.6@sha256:7d7972e7d9ed2a6da27b06ccb1c3c5d3544838d6cedb67a050ba7d655461ef52
IMAGE_kyvernopre_amd64=ghcr.io/kyverno/kyvernopre:v1.3.6@sha256:94fc7f204917a86dcdbc18977e843701854aa9f84c215adce36c26de2adf13df
IMAGE_traefik_amd64=docker.io/traefik:2.4.9@sha256:bfba2ddb60cea5ebe8bea579a4a18be0bf9cac323783216f83ca268ce0004252
IMAGE_vault_amd64=index.docker.io/library/vault:1.2.3@sha256:b1c86c9e173f15bb4a926e4144a63f7779531c30554ac7aee9b2a408b22b2c01
IMAGE_bind_amd64=index.docker.io/sameersbn/bind:9.11.3-20190706@sha256:b8e84f9a9fe0c05c3a963606c3d0170622be9c5e8800431ffcaadb0c79a3ff75
IMAGE_sampleexternalissuer_amd64=ghcr.io/wallrj/sample-external-issuer/controller:v0.0.0-30-gf333b9e@sha256:609a12fca03554a186e516ef065b4152f02596fba697e3cc45f3593654c87a86

# The contents of the included file, which is generated, looks like this:
#
#  KIND_IMAGE_SHA_K8S_119=sha256:f4bcc97a0ad6e7abaf3f643d890add7efe6ee4ab90baeb374b4f41a4c95567eb
#  KIND_IMAGE_SHA_K8S_120=sha256:f4bcc97a0ad6e7abaf3f643d890add7efe6ee4ab90baeb374b4f41a4c95567eb
#                     ^^^ The Kubernetes version
#
# We use these variables in the target "kind-cluster".
include devel/cluster/kind_cluster_node_versions.sh

# Creates a Kind cluster and wait for all nodes to be ready.
KIND_CLUSTER_NAME ?= kind
.PHONY: kind-cluster
kind-cluster: devel/cluster/config/v1beta2.yaml | ${KIND} ${KUBECTL}
	@if [ -z "${KIND_IMAGE_SHA_K8S_$(subst .,,$(K8S_VERSION))}" ]; then echo "this K8S_VERSION is not supported"; exit 1; fi
	@${KIND} get clusters | grep -q ${KIND_CLUSTER_NAME} || \
		${KIND} create cluster --config $< --name ${KIND_CLUSTER_NAME} --wait 5m --image docker.io/kindest/node@${KIND_IMAGE_SHA_K8S_$(K8S_VERSION)}
	@if test "$$(kubectl config current-context 2>/dev/null)" != kind-${KIND_CLUSTER_NAME}; then \
		printf "$(Y)$(WARN)Warning$(E): your current kubectl context isn't equal to kind-${KIND_CLUSTER_NAME}. Run the following command:\n" >&2; \
		printf "    $(C)kubectl config use-context kind-${KIND_CLUSTER_NAME}$(E)\n" >&2; \
		exit 1; \
	fi

# Checks that the locally-built images are available in the Kind cluster. The
# Kind cluster can be created with:
#
#   make kind-cluster
#
# Note that "docker" is not considered as a dependency that we would need to
# fetch in tools.mk because Kind itself depends on the docker binary.
.PHONY: image-check
image-check: bin/containers/cert-manager-controller-linux-$(CRI_ARCH).tar.gz bin/containers/cert-manager-acmesolver-linux-$(CRI_ARCH).tar.gz bin/containers/cert-manager-cainjector-linux-$(CRI_ARCH).tar.gz bin/containers/cert-manager-webhook-linux-$(CRI_ARCH).tar.gz bin/containers/cert-manager-ctl-linux-$(CRI_ARCH).tar.gz | ${KUBECTL}
	@$(eval export IMAGES = $(foreach tar,$^,$(shell tar xzfO $(tar) manifest.json | jq '.[0].RepoTags[0]' -r)))
	@if ! (${KUBECTL} get nodes -ojson | jq '.items[0].spec.providerID' -r | grep -q ^kind 2>/dev/null && \
			docker exec $$(${KUBECTL} get nodes -ojson | jq '.items[0].metadata.name' -r) crictl inspecti $(IMAGES) >/dev/null); then \
		printf "$(R)$(REDCROSS)Error$(E): an image wasn't found (note that only Kind is supported). Try running:\n">&2; \
		printf "    $(C)make kind-load$(E)\n" >&2; \
		exit 1; \
	fi

.PHONY: kind-load
kind-load: bin/containers/cert-manager-controller-linux-$(CRI_ARCH).tar.gz bin/containers/cert-manager-acmesolver-linux-$(CRI_ARCH).tar.gz bin/containers/cert-manager-cainjector-linux-$(CRI_ARCH).tar.gz bin/containers/cert-manager-webhook-linux-$(CRI_ARCH).tar.gz bin/containers/cert-manager-ctl-linux-$(CRI_ARCH).tar.gz | ${KIND} ${KUBECTL}
	@if ! ${KUBECTL} get nodes -ojson | jq '.items[0].spec.providerID' -r | grep -q ^kind 2>/dev/null; then \
		printf "$(R)$(REDCROSS)Error$(E): the current context is not a Kind cluster. Try running:\n">&2; \
		printf "    $(C)make kind-cluster$(E)\n" >&2; \
		exit 1; \
	fi
	tr ' ' '\n' <<<"$^" | xargs -I@ -P$(words $^) sh -c "gzip -c -d @ | ${KIND} load image-archive /dev/stdin --name $$(kubectl get nodes -ojson | jq '.items[0].spec.providerID' -r | cut -d/ -f4)"

bin/containers/%.manifest.json: bin/containers/%.tar.gz
	cd $(dir $@) && tar zxf ../../$< manifest.json
	touch $@

.PHONY: deploy
deploy: bin/cert-manager-$(RELEASE_VERSION).tgz image-check
	${KUBECTL} kustomize "github.com/kubernetes-sigs/gateway-api/config/crd?ref=v0.3.0" | kubectl apply -f - >/dev/null
	${HELM_CMD} upgrade --install --wait --create-namespace --namespace cert-manager \
	 	--set installCRDs=true \
	 	--set image.repository=cert-manager-controller-amd64 \
	 	--set cainjector.image.repository=cert-manager-cainjector-amd64 \
	 	--set webhook.image.repository=cert-manager-webhook-amd64 \
	 	--set startupapicheck.image.repository=cert-manager-ctl-amd64 \
	 	--set image.tag=$(RELEASE_VERSION) \
	 	--set cainjector.image.tag=$(RELEASE_VERSION) \
	 	--set webhook.image.tag=$(RELEASE_VERSION) \
	 	--set startupapicheck.image.tag=$(RELEASE_VERSION) \
	 	--set featureGates="$(subst $(comma),\$(comma),$(FEATURE_GATES_CONTROLLER))" \
	 	--set "webhook.extraArgs={--feature-gates=$(FEATURE_GATES_WEBHOOK)}" \
	 	--set "cainjector.extraArgs={--feature-gates=$(FEATURE_GATES_CAINJECTOR)}"\
	 	--set "extraArgs={--dns01-recursive-nameservers=10.0.0.16:53,--dns01-recursive-nameservers-only=true}" \
	 	cert-manager $<

.PHONY: deploy-bind
deploy-bind:
	${KUBECTL} get ns bind 2>/dev/null >&2 || ${KUBECTL} create ns bind
	sed "s/{SERVICE_IP_PREFIX}/10.0.0/g" make/deploy/addon/bind/*.yaml | kubectl apply -n bind -f - >/dev/null

$(foreach i,ingressnginx kyverno kyvernopre traefik vault bind sampleexternalissuer,bin/tools/$(i).tar.gz):
	docker pull $(IMAGE_$*_amd64)
	docker save $(IMAGE_$*_amd64) | gzip > $@

# If you would prefer the ANSI color characters and emojis not to appear, you
# can set NO_COLOR=1 (https://no-color.org/).
ifeq ($(NO_COLOR),)
R=\033[0;31m
G=\033[0;32m
Y=\033[0;33m
# C = cyan
C=\033[0;36m
# B = white bold
B=\033[0;37m
GR=\033[0;90m
# E is the "end" marker.
E=\033[0m
WARN=⚠️  #
WAIT=⏳️  #
GREENCHECK=✅  #
REDCROSS=❌  #
endif

