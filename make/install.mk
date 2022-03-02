# On arm64, you can force the use of amd64 images:
#
#   make deploy CRI_ARCH=amd64
#   make kind-load CRI_ARCH=amd64
#
CRI_ARCH ?= $(HOST_ARCH)

K8S_VERSION = 1.23

IMAGE_haproxyingress_amd64=quay.io/jcmoraisjr/haproxy-ingress:v0.13.6@sha256:f19dc8a8865a765d12f7553f961fc1d3768867c930f50bfd2fcafeaf57983e83
IMAGE_ingressnginxprev1_amd64=k8s.gcr.io/ingress-nginx/controller:v0.49.3@sha256:c47ed90d1685cb6e3b556353d7afb2aced2be7095066edfc90dd81f3e9014747
IMAGE_ingressnginxpostv1_amd64=k8s.gcr.io/ingress-nginx/controller:v1.1.0@sha256:7464dc90abfaa084204176bcc0728f182b0611849395787143f6854dc6c38c85
IMAGE_kyverno_amd64=ghcr.io/kyverno/kyverno:v1.3.6@sha256:7d7972e7d9ed2a6da27b06ccb1c3c5d3544838d6cedb67a050ba7d655461ef52
IMAGE_kyvernopre_amd64=ghcr.io/kyverno/kyvernopre:v1.3.6@sha256:94fc7f204917a86dcdbc18977e843701854aa9f84c215adce36c26de2adf13df
IMAGE_traefik_amd64=docker.io/traefik:2.4.9@sha256:bfba2ddb60cea5ebe8bea579a4a18be0bf9cac323783216f83ca268ce0004252
IMAGE_vault_amd64=index.docker.io/library/vault:1.2.3@sha256:b1c86c9e173f15bb4a926e4144a63f7779531c30554ac7aee9b2a408b22b2c01
IMAGE_bind_amd64=index.docker.io/sameersbn/bind:9.11.3-20190706@sha256:b8e84f9a9fe0c05c3a963606c3d0170622be9c5e8800431ffcaadb0c79a3ff75
IMAGE_sampleexternalissuer_amd64=ghcr.io/wallrj/sample-external-issuer/controller:v0.0.0-30-gf333b9e@sha256:609a12fca03554a186e516ef065b4152f02596fba697e3cc45f3593654c87a86
IMAGE_projectcontour_amd64=index.docker.io/bitnami/contour:1.20.1-debian-10-r2@sha256:08233320e825bc1673fead865eac627e8427157e09868ebf98191c217efc8877
IMAGE_pebble_amd64=local/pebble:local
IMAGE_vaultretagged_amd64=local/vault:local

IMAGE_haproxyingress_amd64=quay.io/jcmoraisjr/haproxy-ingress:v0.13.6@sha256:53a38f53c5c005ac9b18adf9c1111601368bb3d73fe23cb99445b6d6bc0bab67
IMAGE_ingressnginxprev1_arm64=k8s.gcr.io/ingress-nginx/controller:v0.49.3@sha256:9138968b41c238118a36eba32433704f5246afcf987f2245b5c1aa429995392d
IMAGE_ingressnginxpostv1_arm64=k8s.gcr.io/ingress-nginx/controller:v1.1.0@sha256:86be28e506653cbe29214cb272d60e7c8841ddaf530da29aa22b1b1017faa956
IMAGE_kyverno_arm64=ghcr.io/kyverno/kyverno:v1.3.6@sha256:sha256:fa1e44e927433f217ef507299aeebf27f9b24a21a5f27d07b3b8acf26b48d5e6
IMAGE_kyvernopre_arm64=ghcr.io/kyverno/kyvernopre:v1.3.6@sha256:f1a85fb6a95ccc9770e668116e0252c7e7c42b6403f3451047e154b8367cb987
IMAGE_traefik_arm64=docker.io/traefik:2.4.9@sha256:837615ad42a24e097bf554e4da8931b906cd50ecddf6ad934dd7882925b9c32a
IMAGE_vault_arm64=index.docker.io/library/vault:1.2.3@sha256:226a269b83c4b28ff8a512e76f1e7b707eccea012e4c3ab4c7af7fff1777ca2d
IMAGE_bind_arm64= # 🚧 NOT AVAILABLE 🚧
IMAGE_sampleexternalissuer_arm64= # 🚧 NOT AVAILABLE 🚧
IMAGE_projectcontour_arm64= #🚧 NOT AVAILABLE 🚧
IMAGE_pebble_arm64=local/pebble:local
IMAGE_vaultretagged_arm64=local/vault:local

GATEWAY_API_VERSION = 0.4.1

# Get the tarball path for a given addon, such as "traefik".
# Example: $(call image-tar,traefik)
#
# Since ":" can't be used in make prerequisites and "+" won't interfere
# with docker image names since "+" isn't a valid char in image names, we
# use "+" to replace the forbidden ":".
define image-tar
bin/scratch/addon/$(CRI_ARCH)/$(subst :,+,$(IMAGE_$(1)_$(CRI_ARCH))).tar
endef

.PHONY: install-all
install: install-haproxyingress install-ingressnginx install-kyverno install-traefik install-vault install-bind install-sampleexternalissuer install-projectcontour install-pebble install-vault

LOAD_TARGETS=load-$(call image-tar,ingressnginxprev1) load-$(call image-tar,ingressnginxpostv1) load-$(call image-tar,haproxyingress) load-$(call image-tar,kyverno) load-$(call image-tar,kyvernopre) load-$(call image-tar,traefik) load-$(call image-tar,vault) load-$(call image-tar,bind) load-$(call image-tar,projectcontour) load-$(call image-tar,sampleexternalissuer) load-$(call image-tar,vaultretagged) load-bin/scratch/addon/$(CRI_ARCH)/pebble.tar load-bin/scratch/addon/$(CRI_ARCH)/samplewebhook.tar
.PHONY: $(LOAD_TARGETS)
$(LOAD_TARGETS): load-%: % |
	bin/tools/kind load image-archive --name=${KIND_CLUSTER_NAME} $*

# We use crane instead of docker when pulling images, which saves some time
# since we don't care about having the image available to docker.
#
# We don't pull using both the digest and tag because crane replaces the
# tag with "i-was-a-digest". We still check that the downloaded image
# matches the digest.
$(call image-tar,kyverno) $(call image-tar,kyvernopre) $(call image-tar,bind) $(call image-tar,projectcontour) $(call image-tar,sampleexternalissuer) $(call image-tar,traefik) $(call image-tar,vault) $(call image-tar,haproxyingress) $(call image-tar,ingressnginxpostv1) $(call image-tar,ingressnginxprev1): bin/scratch/addon/$(CRI_ARCH)/%.tar: | bin/tools/crane
	@$(eval IMAGE=$(subst +,:,$*))
	@$(eval IMAGE_WITHOUT_DIGEST=$(shell cut -d@ -f1 <<<"$(IMAGE)"))
	@$(eval DIGEST=$(subst $(IMAGE_WITHOUT_DIGEST)@,,$(IMAGE)))
	@mkdir -p $(dir $@)
	diff <(echo "$(DIGEST)  -" | cut -d: -f2) <(bin/tools/crane manifest --platform=linux/$(CRI_ARCH) $(IMAGE) | sha256sum)
	bin/tools/crane pull $(IMAGE_WITHOUT_DIGEST) $@ --platform=linux/$(CRI_ARCH)

# Since we dynamically install Vault via Helm during the end-to-end tests,
# we need its image to be retagged to a well-known tag "local/vault:local".
$(call image-tar,vaultretagged): $(call image-tar,vault)
	@mkdir -p /tmp/vault $(dir $@)
	tar xf $< -C /tmp/vault
	cat /tmp/vault/manifest.json | jq '.[0].RepoTags |= ["local/vault:local"]' -r > /tmp/vault/temp
	mv /tmp/vault/temp /tmp/vault/manifest.json
	tar cf $@ -C /tmp/vault .
	@rm -rf /tmp/vault

# Creates a Kind cluster and wait for all nodes to be ready.
KIND_CLUSTER_NAME ?= kind
.PHONY: kind
kind: devel/cluster/config/v1beta2.yaml | bin/tools/kind bin/tools/kubectl
	./devel/cluster/create-kind.sh

.PHONY: install-certmanager
install-certmanager: bin/cert-manager.tgz $(foreach bin,controller acmesolver cainjector webhook ctl,bin/containers/cert-manager-$(bin)-linux-$(CRI_ARCH).tar) install-gatewayapi devel/addon/certmanager/install.sh | ${KUBECTL} ${KIND}
	./devel/addon/certmanager/install.sh --chart $< --images $(filter bin/containers/%,$^)

.PHONY: install-bind
install-bind: load-$(call image-tar,bind) $(wildcard devel/addon/bind/manifests/*.yaml) | bin/tools/kubectl
	@$(eval SERVICE_IP_PREFIX = $(shell bin/tools/kubectl cluster-info dump | grep -m1 ip-range | cut -d= -f2 | cut -d. -f1,2,3))
	bin/tools/kubectl get ns bind 2>/dev/null >&2 || ${KUBECTL} create ns bind
	sed "s/{SERVICE_IP_PREFIX}/$(SERVICE_IP_PREFIX)/g" devel/addon/bind/manifests/*.yaml | bin/tools/kubectl apply -n bind -f - >/dev/null

.PHONY: install-gatewayapi
install-gatewayapi: bin/scratch/gatewayapi-v$(GATEWAY_API_VERSION) | bin/tools/kubectl
	bin/tools/kubectl kustomize $</*/config/crd | bin/tools/kubectl apply -f - >/dev/null

.PHONY: install-haproxyingress
install-haproxyingress: $(call image-tar,haproxyingress) load-$(call image-tar,haproxyingress) install-gatewayapi
	helm repo add haproxy-ingress --force-update https://haproxy-ingress.github.io/charts >/dev/null
	@$(eval SERVICE_IP_PREFIX = $(shell bin/tools/kubectl cluster-info dump | grep -m1 ip-range | cut -d= -f2 | cut -d. -f1,2,3))
	@$(eval TAG=$(shell tar xfO $< manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f2))
	helm upgrade \
		--install \
		--wait \
		--namespace haproxy-ingress \
		--create-namespace \
		--version 0.13.6 \
		--set controller.extraArgs.watch-gateway=true \
		--set controller.extraArgs.configmap=haproxy-ingress/haproxy-ingress-config \
		--set controller.service.type=ClusterIP \
		--set controller.service.clusterIP=$(SERVICE_IP_PREFIX).14 \
		--set controller.image.tag=$(TAG) \
		--set controller.image.pullPolicy=Never \
			haproxy-ingress haproxy-ingress/haproxy-ingress >/dev/null

# We need to install different versions of Ingress depending on which
# version of Kubernetes we are running as the NGINX Ingress controller does
# not have a release where they would support both v1 and v1beta1 versions
# of networking API.
#
# We don't use ifeq because that would require running the kubectl command
# for every make invokation.
.PHONY: install-ingressnginx
install-ingressnginx: | bin/tools/kubectl bin/tools/yq
	@$(eval k8s_version = $(shell bin/tools/kubectl version -oyaml | bin/tools/yq e '.serverVersion | .major +"."+ .minor' -))
	@if [[ "$(k8s_version)" =~ 1\.18 ]]; then \
		make --no-print-directory -f make/Makefile install-ingressnginxprev1; \
	else \
		make --no-print-directory -f make/Makefile install-ingressnginxpostv1; \
	fi

# Ingress v1+ versions only support Kubernetes v1 networking API which is
# only available from Kubernetes v1.19 onwards.
#
# TODO: Remove this target once the oldest version of Kubernetes supported
# by cert-manager is v1.19.
.PHONY: install-ingressnginxprev1
install-ingressnginxprev1: $(call image-tar,ingressnginxprev1) load-$(call image-tar,ingressnginxprev1) | bin/tools/kubectl bin/tools/helm
	@$(eval SERVICE_IP_PREFIX = $(shell bin/tools/kubectl cluster-info dump | grep -m1 ip-range | cut -d= -f2 | cut -d. -f1,2,3))
	@$(eval TAG=$(shell tar xfO $< manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f2))
	helm repo add ingress-nginx --force-update https://kubernetes.github.io/ingress-nginx >/dev/null
	helm upgrade \
		--install \
		--wait \
		--version 3.40.0 \
		--namespace ingress-nginx \
		--create-namespace \
		--set controller.image.tar=$(TAG) \
		--set controller.image.digest= \
		--set controller.image.pullPolicy=Never \
		--set controller.service.clusterIP=${SERVICE_IP_PREFIX}.15 \
		--set controller.service.type=ClusterIP \
		--set controller.config.no-tls-redirect-locations= \
		--set admissionWebhooks.enabled=false \
		--set controller.admissionWebhooks.enabled=false \
		--set controller.watchIngressWithoutClass=true \
		ingress-nginx \
		ingress-nginx/ingress-nginx >/dev/null

# v1 NGINX-Ingress by default only watches Ingresses with Ingress class
# defined. When configuring solver block for ACME HTTTP01 challenge on an
# ACME issuer, cert-manager users can currently specify either an Ingress
# name or a class. We also e2e test these two ways of creating Ingresses
# with ingress-shim. For the ingress controller to watch our Ingresses that
# don't have a class, we pass a --watch-ingress-without-class flag:
# https://github.com/kubernetes/ingress-nginx/blob/main/charts/ingress-nginx/values.yaml#L64-L67
.PHONY: install-ingressnginxpostv1
install-ingressnginxpostv1: $(call image-tar,ingressnginxpostv1) load-$(call image-tar,ingressnginxpostv1) | bin/tools/helm
	@$(eval SERVICE_IP_PREFIX = $(shell bin/tools/kubectl cluster-info dump | grep -m1 ip-range | cut -d= -f2 | cut -d. -f1,2,3))
	@$(eval TAG=$(shell tar xfO $< manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f2))
	helm repo add ingress-nginx --force-update https://kubernetes.github.io/ingress-nginx >/dev/null
	helm upgrade \
		--install \
		--wait \
		--version 4.0.10 \
		--namespace ingress-nginx \
		--create-namespace \
		--set controller.image.tag=$(TAG) \
		--set controller.image.digest= \
		--set controller.image.pullPolicy=Never \
		--set controller.service.clusterIP=${SERVICE_IP_PREFIX}.15 \
		--set controller.service.type=ClusterIP \
		--set controller.config.no-tls-redirect-locations= \
		--set admissionWebhooks.enabled=false \
		--set controller.admissionWebhooks.enabled=true \
		--set controller.watchIngressWithoutClass=true \
		ingress-nginx \
		ingress-nginx/ingress-nginx >/dev/null

.PHONY: install-kyverno
install-kyverno: $(call image-tar,kyverno) $(call image-tar,kyvernopre) load-$(call image-tar,kyverno) load-$(call image-tar,kyvernopre) devel/addon/kyverno/policy.yaml | bin/tools/kubectl bin/tools/helm
	@$(eval TAG=$(shell tar xfO $< manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f2))
	bin/tools/helm repo add kyverno --force-update https://kyverno.github.io/kyverno/ >/dev/null
	bin/tools/helm upgrade \
		--install \
		--wait \
		--namespace kyverno \
		--create-namespace \
		--version v1.3.6 \
		--set image.tag=v1.3.6 \
		--set initImage.tag=v1.3.6 \
		--set image.pullPolicy=Never \
		--set initImage.pullPolicy=Never \
		kyverno \
		kyverno/kyverno >/dev/null
	@bin/tools/kubectl create ns cert-manager >/dev/null 2>&1 || true
	bin/tools/kubectl apply -f devel/addon/kyverno/policy.yaml >/dev/null

bin/scratch/addon/$(CRI_ARCH)/pebble/pebble: | bin/tools/go
	@mkdir -p $(dir $@)
	GOOS=linux GOARCH=$(CRI_ARCH) CGO_ENABLED=$(CGO_ENABLED) GOMAXPROCS=$(GOBUILDPROCS) $(GO) install $(GOFLAGS) github.com/letsencrypt/pebble/cmd/pebble@ba5f81d
	mv $(shell go env GOPATH)/bin/pebble $@

bin/scratch/addon/$(CRI_ARCH)/pebble.tar: bin/scratch/addon/$(CRI_ARCH)/pebble/pebble devel/addon/pebble/Containerfile.pebble
	$(eval BASE := BASE_IMAGE_controller-linux-$(CRI_ARCH))
	$(CTR) build --quiet \
		-f devel/addon/pebble/Containerfile.pebble \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t local/pebble:local \
		$(dir $<) >/dev/null
	$(CTR) save local/pebble:local -o $@ >/dev/null

.PHONY: install-pebble
install-pebble: load-bin/scratch/addon/$(CRI_ARCH)/pebble.tar | bin/tools/helm
	bin/tools/helm upgrade \
		--install \
		--wait \
		--namespace pebble \
		--create-namespace \
		pebble \
		devel/addon/pebble/chart >/dev/null

bin/scratch/addon/$(CRI_ARCH)/samplewebhook/samplewebhook: devel/addon/samplewebhook/sample/main.go bin/tools/go
	@mkdir -p $(dir $@)
	GOOS=linux GOARCH=$(CRI_ARCH) $(GOBUILD) -o $@ $(GOFLAGS) devel/addon/samplewebhook/sample/main.go

bin/scratch/addon/$(CRI_ARCH)/samplewebhook.tar: bin/scratch/addon/$(CRI_ARCH)/samplewebhook/samplewebhook devel/addon/samplewebhook/Containerfile.samplewebhook
	$(eval BASE := BASE_IMAGE_controller-linux-$(CRI_ARCH))
	$(CTR) build --quiet \
		-f devel/addon/samplewebhook/Containerfile.samplewebhook \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t local/samplewebhook:local \
		$(dir $<) >/dev/null
	$(CTR) save local/samplewebhook:local -o $@ >/dev/null

.PHONY: install-samplewebhook
install-samplewebhook: load-bin/scratch/addon/$(CRI_ARCH)/samplewebhook.tar install-certmanager | bin/tools/helm
	bin/tools/helm upgrade \
		--install \
		--wait \
		--namespace samplewebhook \
		--create-namespace \
		samplewebhook \
		devel/addon/samplewebhook/chart >/dev/null

.PHONY: install-projectcontour
install-projectcontour: load-$(call image-tar,projectcontour) devel/addon/projectcontour/contour-gateway.yaml devel/addon/projectcontour/gateway.yaml | bin/tools/kubectl
	@$(eval SERVICE_IP_PREFIX = $(shell bin/tools/kubectl cluster-info dump | grep -m1 ip-range | cut -d= -f2 | cut -d. -f1,2,3))
	sed 's|{CLUSTER_IP}|$(SERVICE_IP_PREFIX).17|' devel/addon/projectcontour/contour-gateway.yaml | bin/tools/kubectl apply -f- >/dev/null
	bin/tools/kubectl apply -f devel/addon/projectcontour/gateway.yaml >/dev/null

.PHONY: install-sampleexternalissuer
install-sampleexternalissuer: load-$(call image-tar,sampleexternalissuer) | bin/tools/kubectl
	bin/tools/kubectl apply -n sample-external-issuer-system -f https://github.com/cert-manager/sample-external-issuer/releases/download/v0.1.1/install.yaml >/dev/null
	bin/tools/kubectl patch -n sample-external-issuer-system deployments.apps sample-external-issuer-controller-manager --type=json -p='[{"op": "add", "path": "/spec/template/spec/containers/1/imagePullPolicy", "value": "Never"}]' >/dev/null

.PHONY: install-traefik
install-traefik: load-$(call image-tar,traefik) devel/addon/traefik/traefik-values.yaml devel/addon/traefik/gateway.yaml install-gatewayapi | bin/tools/kubectl
	@$(eval SERVICE_IP_PREFIX = $(shell bin/tools/kubectl cluster-info dump | grep -m1 ip-range | cut -d= -f2 | cut -d. -f1,2,3))
	bin/tools/helm repo add traefik --force-update https://helm.traefik.io/traefik >/dev/null
	bin/tools/helm upgrade \
		--install \
		--version 10.1.1 \
		--create-namespace \
		--namespace traefik \
		--values=devel/addon/traefik/traefik-values.yaml \
		--set image.tag=2.4.9 \
		--set service.type=ClusterIP \
		--set service.spec.clusterIP=$(SERVICE_IP_PREFIX).13 \
		traefik traefik/traefik >/dev/null
	bin/tools/kubectl apply -f devel/addon/traefik/gateway.yaml >/dev/null

# Note that the end-to-end tests are dealing with the Helm installation. We
# do not need to Helm install here.
.PHONY: install-vault
install-vault: load-$(call image-tar,vaultretagged) | bin/tools/helm
