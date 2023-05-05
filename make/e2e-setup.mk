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

# CRI_ARCH is meant for M1 users. By default, the images loaded into the local
# cluster when running 'make -j e2e-setup' will match the architecture detected
# by "uname -m" (e.g., arm64). Note that images that don't have an arm64
# version are loaded as amd64. To force the use of amd64 images for all the
# images, use:
#
#   make install CRI_ARCH=amd64
#
CRI_ARCH := $(HOST_ARCH)

# TODO: this version is also defaulted in ./make/cluster.sh. Make it so that it
# is set in one place only.
K8S_VERSION := 1.27

IMAGE_ingressnginx_amd64 := registry.k8s.io/ingress-nginx/controller:v1.1.0@sha256:7464dc90abfaa084204176bcc0728f182b0611849395787143f6854dc6c38c85
IMAGE_kyverno_amd64 := ghcr.io/kyverno/kyverno:v1.7.1@sha256:aec4b029660d47aea025336150fdc2822c991f592d5170d754b6acaf158b513e
IMAGE_kyvernopre_amd64 := ghcr.io/kyverno/kyvernopre:v1.7.1@sha256:1bcec6bc854720e22f439c6dcea02fcf689f31976babcf03a449d750c2b1f34a
IMAGE_vault_amd64 := docker.io/hashicorp/vault:1.13.1@sha256:46b978105f46fa5c28851b1ea679f74c2ecbd24a6f92e6c7611c558e44f3baab
IMAGE_bind_amd64 := docker.io/eafxx/bind:latest-9f74179f@sha256:0b8c766f5bedbcbe559c7970c8e923aa0c4ca771e62fcf8dba64ffab980c9a51
IMAGE_sampleexternalissuer_amd64 := ghcr.io/cert-manager/sample-external-issuer/controller:v0.3.0@sha256:6f7c87979b1e3bd92dc3ab54d037f80628547d7b58a8cb2b3bfa06c006b1ed9d
IMAGE_projectcontour_amd64 := ghcr.io/projectcontour/contour:v1.24.1@sha256:39a804ce4b896de168915ae41358932c219443fd4ceffe37296a63f9adef0597

IMAGE_ingressnginx_arm64 := registry.k8s.io/ingress-nginx/controller:v1.1.0@sha256:86be28e506653cbe29214cb272d60e7c8841ddaf530da29aa22b1b1017faa956
IMAGE_kyverno_arm64 := ghcr.io/kyverno/kyverno:v1.7.1@sha256:4355f1f65ea5e952886e929a15628f0c6704905035b4741c6f560378871c9335
IMAGE_kyvernopre_arm64 := ghcr.io/kyverno/kyvernopre:v1.7.1@sha256:141234fb74242155c7b843180b90ee5fb6a20c9e77598bd9c138c687059cdafd
IMAGE_vault_arm64 := docker.io/hashicorp/vault:1.13.1@sha256:77a343a0cc93281fc4d476afbe65c2f39d7878c0a2bdc9e513ec3d19461828c5
IMAGE_bind_arm64 := docker.io/eafxx/bind:latest-9f74179f@sha256:85de273f24762c0445035d36290a440e8c5a6a64e9ae6227d92e8b0b0dc7dd6d
IMAGE_sampleexternalissuer_arm64 := ghcr.io/cert-manager/sample-external-issuer/controller:v0.3.0@sha256:4a99caed209cf76fc15e37ad153d20d8b905a895021c799d360bba3402c66392
IMAGE_projectcontour_arm64 := ghcr.io/projectcontour/contour:v1.24.1@sha256:fee2b24db85c3ed3487e0e2a325806323997171a2ed722252f8ca85d0bee919d

PEBBLE_COMMIT = ba5f81dd80fa870cbc19326f2d5a46f45f0b5ee3

LOCALIMAGE_pebble := local/pebble:local
LOCALIMAGE_vaultretagged := local/vault:local
LOCALIMAGE_samplewebhook := local/samplewebhook:local

IMAGE_kind_amd64 := $(shell make/cluster.sh --show-image)
IMAGE_kind_arm64 := $(IMAGE_kind_amd64)

# TODO: considering moving the installation commands in this file to separate scripts for readability
# Once that is done, we can consume this variable from ./make/config/lib.sh
SERVICE_IP_PREFIX = 10.0.0

.PHONY: e2e-setup-kind
## Create a Kubernetes cluster using Kind, which is required for `make e2e`.
## The Kind image is pre-pulled to avoid 'kind create' from blocking other make
## targets.
##
##	make [KIND_CLUSTER_NAME=name] [K8S_VERSION=<kubernetes_version>] e2e-setup-kind
##
## @category Development
e2e-setup-kind: kind-exists
	@printf "✅  \033[0;32mReady\033[0;0m. The next step is to install cert-manager and the addons with the command:\n" >&2
	@printf "    \033[0;36mmake -j e2e-setup\033[0;0m\n" >&2

# This is the actual target that creates the kind cluster.
#
# The presence of the file $(BINDIR)/scratch/kind-exists indicates that your kube
# config's current context points to a kind cluster. The file contains the
# name of the kind cluster.
#
# We use FORCE instead of .PHONY because this is a real file that can be
# used as a prerequisite. If we were to use .PHONY, then the file's
# timestamp would not be used to check whether targets should be rebuilt,
# and they would get constantly rebuilt.
$(BINDIR)/scratch/kind-exists: make/config/kind/cluster.yaml preload-kind-image make/cluster.sh FORCE | $(BINDIR)/scratch $(NEEDS_KIND) $(NEEDS_KUBECTL) $(NEEDS_YQ)
	@$(eval KIND_CLUSTER_NAME ?= kind)
	@make/cluster.sh --name $(KIND_CLUSTER_NAME)
	@if [ "$(shell cat $@ 2>/dev/null)" != kind ]; then echo kind > $@; else touch $@; fi

.PHONY: kind-exists
kind-exists: $(BINDIR)/scratch/kind-exists

#  Component                Used in                   IP                     A record in bind
#  ---------                -------                   --                     ----------------
#  e2e-setup-bind           DNS-01 tests              SERVICE_IP_PREFIX.16
#  e2e-setup-ingressnginx   HTTP-01 Ingress tests     SERVICE_IP_PREFIX.15   *.ingress-nginx.db.http01.example.com
#  e2e-setup-projectcontour HTTP-01 GatewayAPI tests  SERVICE_IP_PREFIX.14   *.gateway.db.http01.example.com
.PHONY: e2e-setup
## Installs cert-manager as well as components required for running the
## end-to-end tests. If the kind cluster does not already exist, it will be
## created.
##
## @category Development
e2e-setup: e2e-setup-gatewayapi e2e-setup-certmanager e2e-setup-vault e2e-setup-bind e2e-setup-sampleexternalissuer e2e-setup-samplewebhook e2e-setup-pebble e2e-setup-ingressnginx e2e-setup-projectcontour

# The function "image-tar" returns the path to the image tarball for a given
# image name. For example:
#
#     $(call image-tar, kyverno)
#
# returns the following path:
#
#     $(BINDIR)/downloaded/containers/amd64/docker.io/traefik+2.4.9@sha256+bfba204252.tar
#                                     <---> <--------------------------------------->
#                                   CRI_ARCH         IMAGE_kyverno_amd64
#                                                (with ":" replaced with "+")
#
# Note the "+" signs. We replace all the "+" with ":" because ":" can't be used
# in make targets. The "+" replacement is safe since it isn't a valid character
# in image names.
#
# When an image isn't available, i.e., IMAGE_imagename_arm64 is empty, we still
# return a string of the form "$(BINDIR)/downloaded/containers/amd64/missing-imagename.tar".
define image-tar
$(BINDIR)/downloaded/containers/$(CRI_ARCH)/$(if $(IMAGE_$(1)_$(CRI_ARCH)),$(subst :,+,$(IMAGE_$(1)_$(CRI_ARCH))),missing-$(1)).tar
endef

# The function "local-image-tar" returns the path to the image tarball for a given local
# image name. For example:
#
#     $(call local-image-tar, samplewebhook)
#
# returns the following path:
#
#     $(BINDIR)/containers/samplewebhook+local.tar
#                          <--------------------->
#                          LOCALIMAGE_samplewebhook
#                        (with ":" replaced with "+")
#
# Note the "+" signs. We replace all the "+" with ":" because ":" can't be used
# in make targets. The "+" replacement is safe since it isn't a valid character
# in image names.
#
# When an image isn't available, i.e., IMAGE_imagename is empty, we still
# return a string of the form "$(BINDIR)/containers/missing-imagename.tar".
define local-image-tar
$(BINDIR)/containers/$(if $(LOCALIMAGE_$(1)),$(subst :,+,$(LOCALIMAGE_$(1))),missing-$(1)).tar
endef

# Let's separate the pulling of the Kind image so that more tasks can be
# run in parallel when running "make -j e2e-setup". In CI, the Docker
# engine being stripped on every job, we save the kind image to
# "$(BINDIR)/downloads". Side note: we don't use "$(CI)" directly since we would
# get the message "warning: undefined variable 'CI'".
.PHONY: preload-kind-image
ifeq ($(shell printenv CI),)
preload-kind-image: | $(NEEDS_CRANE)
	@$(CTR) inspect $(IMAGE_kind_$(CRI_ARCH)) 2>/dev/null >&2 || (set -x; $(CTR) pull $(IMAGE_kind_$(CRI_ARCH)))
else
preload-kind-image: $(call image-tar,kind) | $(NEEDS_CRANE)
	$(CTR) inspect $(IMAGE_kind_$(CRI_ARCH)) 2>/dev/null >&2 || $(CTR) load -i $<
endif

LOAD_TARGETS=load-$(call image-tar,ingressnginx) load-$(call image-tar,kyverno) load-$(call image-tar,kyvernopre) load-$(call image-tar,bind) load-$(call image-tar,projectcontour) load-$(call image-tar,sampleexternalissuer) load-$(call local-image-tar,vaultretagged) load-$(call local-image-tar,pebble) load-$(call local-image-tar,samplewebhook) load-$(BINDIR)/containers/cert-manager-controller-linux-$(CRI_ARCH).tar load-$(BINDIR)/containers/cert-manager-acmesolver-linux-$(CRI_ARCH).tar load-$(BINDIR)/containers/cert-manager-cainjector-linux-$(CRI_ARCH).tar load-$(BINDIR)/containers/cert-manager-webhook-linux-$(CRI_ARCH).tar load-$(BINDIR)/containers/cert-manager-ctl-linux-$(CRI_ARCH).tar
.PHONY: $(LOAD_TARGETS)
$(LOAD_TARGETS): load-%: % $(BINDIR)/scratch/kind-exists | $(NEEDS_KIND)
	$(KIND) load image-archive --name=$(shell cat $(BINDIR)/scratch/kind-exists) $*

# We use crane instead of docker when pulling images, which saves some time
# since we don't care about having the image available to docker.
#
# We don't pull using both the digest and tag because crane replaces the
# tag with "i-was-a-digest". We still check that the downloaded image
# matches the digest.
$(call image-tar,kyverno) $(call image-tar,kyvernopre) $(call image-tar,bind) $(call image-tar,projectcontour) $(call image-tar,sampleexternalissuer) $(call image-tar,ingressnginx): $(BINDIR)/downloaded/containers/$(CRI_ARCH)/%.tar: | $(NEEDS_CRANE)
	@$(eval IMAGE=$(subst +,:,$*))
	@$(eval IMAGE_WITHOUT_DIGEST=$(shell cut -d@ -f1 <<<"$(IMAGE)"))
	@$(eval DIGEST=$(subst $(IMAGE_WITHOUT_DIGEST)@,,$(IMAGE)))
	@mkdir -p $(dir $@)
	diff <(echo "$(DIGEST)  -" | cut -d: -f2) <($(CRANE) manifest --platform=linux/$(CRI_ARCH) $(IMAGE) | sha256sum)
	$(CRANE) pull $(IMAGE_WITHOUT_DIGEST) $@ --platform=linux/$(CRI_ARCH)

# Same as above, except it supports multiarch images.
$(call image-tar,kind) $(call image-tar,vault): $(BINDIR)/downloaded/containers/$(CRI_ARCH)/%.tar: | $(NEEDS_CRANE)
	@$(eval IMAGE=$(subst +,:,$*))
	@$(eval IMAGE_WITHOUT_DIGEST=$(shell cut -d@ -f1 <<<"$(IMAGE)"))
	@$(eval DIGEST=$(subst $(IMAGE_WITHOUT_DIGEST)@,,$(IMAGE)))
	@mkdir -p $(dir $@)
	diff <(echo "$(DIGEST)  -" | cut -d: -f2) <($(CRANE) manifest $(IMAGE) | sha256sum)
	$(CRANE) pull $(IMAGE_WITHOUT_DIGEST) $@ --platform=linux/$(CRI_ARCH)

# Since we dynamically install Vault via Helm during the end-to-end tests,
# we need its image to be retagged to a well-known tag "local/vault:local".
$(call local-image-tar,vaultretagged): $(call image-tar,vault)
	@mkdir -p /tmp/vault $(dir $@)
	tar xf $< -C /tmp/vault
	cat /tmp/vault/manifest.json | jq '.[0].RepoTags |= ["local/vault:local"]' -r > /tmp/vault/temp
	mv /tmp/vault/temp /tmp/vault/manifest.json
	tar cf $@ -C /tmp/vault .
	@rm -rf /tmp/vault

FEATURE_GATES ?= AdditionalCertificateOutputFormats=true,ExperimentalCertificateSigningRequestControllers=true,ExperimentalGatewayAPISupport=true,ServerSideApply=true,LiteralCertificateSubject=true,UseCertificateRequestBasicConstraints=true

## Set this environment variable to a non empty string to cause cert-manager to
## be installed using best-practice configuration settings, and to install
## Kyverno with a policy that will cause cert-manager installation to fail
## unless it conforms to the documented best-practices.
## See https://cert-manager.io/docs/installation/best-practice/ for context.
##
##	make E2E_SETUP_OPTION_BESTPRACTICE=true e2e-setup
##
## @category Development
E2E_SETUP_OPTION_BESTPRACTICE ?=
## The URL of the Helm values file containing best-practice configuration values
## which will allow cert-manager to be installed and used in a cluster where
## Kyverno and the policies in make/config/kyverno have been applied.
##
## @category Development
E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_URL ?= https://raw.githubusercontent.com/cert-manager/website/f0cc0f3b88846969dd7e9894cddd43391a3135d1/public/docs/installation/best-practice/values.best-practice.yaml
E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_URL_SUM := $(shell sha256sum <<<$(E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_URL) | cut -d ' ' -f 1)

## A local Helm values file containing best-practice configuration values.
## It will be downloaded from E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_URL if
## it does not exist.
##
## @category Development
E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_FILE ?= $(BINDIR)/scratch/values-bestpractice-$(E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_URL_SUM).yaml
$(E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_FILE): | $(BINDIR)/scratch
	$(CURL) $(E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_URL) -o $@

# Dependencies which will be added to e2e-setup-certmanager depending on the
# supplied E2E_SETUP_OPTION_ variables.
E2E_SETUP_OPTION_DEPENDENCIES := $(if $(E2E_SETUP_OPTION_BESTPRACTICE),e2e-setup-kyverno $(E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_FILE))

# In make, there is no way to escape commas or spaces. So we use the
# variables $(space) and $(comma) instead.
null  =
space = $(null) #
comma = ,

# Helm's "--set" interprets commas, which means we want to escape commas
# for "--set featureGates". That's why we have "\$(comma)".
feature_gates_controller := $(subst $(space),\$(comma),$(filter AllAlpha=% AllBeta=% AdditionalCertificateOutputFormats=% ValidateCAA=% ExperimentalCertificateSigningRequestControllers=% ExperimentalGatewayAPISupport=% ServerSideApply=% LiteralCertificateSubject=% UseCertificateRequestBasicConstraints=% SecretsFilteredCaching=%, $(subst $(comma),$(space),$(FEATURE_GATES))))
feature_gates_webhook := $(subst $(space),\$(comma),$(filter AllAlpha=% AllBeta=% AdditionalCertificateOutputFormats=% LiteralCertificateSubject=%,   $(subst $(comma),$(space),$(FEATURE_GATES))))
feature_gates_cainjector := $(subst $(space),\$(comma),$(filter AllAlpha=% AllBeta=% ServerSideApply=%, $(subst $(comma),$(space),$(FEATURE_GATES))))

# Install cert-manager with E2E specific images and deployment settings.
# The values.best-practice.yaml file is applied for compliance with the
# Kyverno policy which has been installed in a pre-requisite target.
#
# TODO: move these commands to separate scripts for readability
#
# ⚠ The following components are installed *before* cert-manager:
# * GatewayAPI: so that cert-manager can watch those CRs.
# * Kyverno: so that it can check the cert-manager manifests against the policy in `config/kyverno/`
#		(only installed if E2E_SETUP_OPTION_BESTPRACTICE is set).
.PHONY: e2e-setup-certmanager
e2e-setup-certmanager: $(BINDIR)/cert-manager.tgz $(foreach binaryname,controller acmesolver cainjector webhook ctl,$(BINDIR)/containers/cert-manager-$(binaryname)-linux-$(CRI_ARCH).tar) $(foreach binaryname,controller acmesolver cainjector webhook ctl,load-$(BINDIR)/containers/cert-manager-$(binaryname)-linux-$(CRI_ARCH).tar) e2e-setup-gatewayapi $(E2E_SETUP_OPTION_DEPENDENCIES) $(BINDIR)/scratch/kind-exists | $(NEEDS_KUBECTL) $(NEEDS_KIND) $(NEEDS_HELM)
	@$(eval TAG = $(shell tar xfO $(BINDIR)/containers/cert-manager-controller-linux-$(CRI_ARCH).tar manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f2))
	$(HELM) upgrade \
		--install \
		--create-namespace \
		--wait \
		--namespace cert-manager \
		--set image.repository="$(shell tar xfO $(BINDIR)/containers/cert-manager-controller-linux-$(CRI_ARCH).tar manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f1)" \
		--set cainjector.image.repository="$(shell tar xfO $(BINDIR)/containers/cert-manager-cainjector-linux-$(CRI_ARCH).tar manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f1)" \
		--set webhook.image.repository="$(shell tar xfO $(BINDIR)/containers/cert-manager-webhook-linux-$(CRI_ARCH).tar manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f1)" \
		--set acmesolver.image.repository="$(shell tar xfO $(BINDIR)/containers/cert-manager-acmesolver-linux-$(CRI_ARCH).tar manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f1)" \
		--set startupapicheck.image.repository="$(shell tar xfO $(BINDIR)/containers/cert-manager-ctl-linux-$(CRI_ARCH).tar manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f1)" \
		--set image.tag="$(TAG)" \
		--set cainjector.image.tag="$(TAG)" \
		--set webhook.image.tag="$(TAG)" \
		--set acmesolver.image.tag="$(TAG)" \
		--set startupapicheck.image.tag="$(TAG)" \
		--set installCRDs=true \
		--set featureGates="$(feature_gates_controller)" \
		--set "extraArgs={--kube-api-qps=9000,--kube-api-burst=9000,--concurrent-workers=200}" \
		--set "webhook.extraArgs={--feature-gates=$(feature_gates_webhook)}" \
		--set "cainjector.extraArgs={--feature-gates=$(feature_gates_cainjector)}" \
		--set "dns01RecursiveNameservers=$(SERVICE_IP_PREFIX).16:53" \
		--set "dns01RecursiveNameserversOnly=true" \
		$(if $(E2E_SETUP_OPTION_BESTPRACTICE),--values=$(E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_FILE)) \
		cert-manager $< >/dev/null

.PHONY: e2e-setup-bind
e2e-setup-bind: $(call image-tar,bind) load-$(call image-tar,bind) $(wildcard make/config/bind/*.yaml) $(BINDIR)/scratch/kind-exists | $(NEEDS_KUBECTL)
	@$(eval IMAGE = $(shell tar xfO $< manifest.json | jq '.[0].RepoTags[0]' -r))
	$(KUBECTL) get ns bind 2>/dev/null >&2 || $(KUBECTL) create ns bind
	sed -e "s|{SERVICE_IP_PREFIX}|$(SERVICE_IP_PREFIX)|g" -e "s|{IMAGE}|$(IMAGE)|g" make/config/bind/*.yaml | $(KUBECTL) apply -n bind -f - >/dev/null

.PHONY: e2e-setup-gatewayapi
e2e-setup-gatewayapi: $(BINDIR)/downloaded/gateway-api-$(GATEWAY_API_VERSION).yaml $(BINDIR)/scratch/kind-exists $(NEEDS_KUBECTL)
	$(KUBECTL) apply --server-side -f $(BINDIR)/downloaded/gateway-api-$(GATEWAY_API_VERSION).yaml > /dev/null


# v1 NGINX-Ingress by default only watches Ingresses with Ingress class
# defined. When configuring solver block for ACME HTTTP01 challenge on an
# ACME issuer, cert-manager users can currently specify either an Ingress
# name or a class. We also e2e test these two ways of creating Ingresses
# with ingress-shim. For the ingress controller to watch our Ingresses that
# don't have a class, we pass a --watch-ingress-without-class flag:
# https://github.com/kubernetes/ingress-nginx/blob/main/charts/ingress-nginx/values.yaml#L64-L67
.PHONY: e2e-setup-ingressnginx
e2e-setup-ingressnginx: $(call image-tar,ingressnginx) load-$(call image-tar,ingressnginx) | $(NEEDS_HELM)
	@$(eval TAG=$(shell tar xfO $< manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f2))
	$(HELM) repo add ingress-nginx --force-update https://kubernetes.github.io/ingress-nginx >/dev/null
	$(HELM) upgrade \
		--install \
		--wait \
		--version 4.0.10 \
		--namespace ingress-nginx \
		--create-namespace \
		--set controller.image.tag=$(TAG) \
		--set controller.image.registry=registry.k8s.io \
		--set controller.image.digest= \
		--set controller.image.pullPolicy=Never \
		--set controller.service.clusterIP=${SERVICE_IP_PREFIX}.15 \
		--set controller.service.type=ClusterIP \
		--set controller.config.no-tls-redirect-locations= \
		--set admissionWebhooks.enabled=false \
		--set controller.admissionWebhooks.enabled=true \
		--set controller.watchIngressWithoutClass=true \
		ingress-nginx ingress-nginx/ingress-nginx >/dev/null

.PHONY: e2e-setup-kyverno
e2e-setup-kyverno: $(call image-tar,kyverno) $(call image-tar,kyvernopre) load-$(call image-tar,kyverno) load-$(call image-tar,kyvernopre) make/config/kyverno/policy.yaml $(BINDIR)/scratch/kind-exists | $(NEEDS_KUBECTL) $(NEEDS_HELM)
	@$(eval TAG=$(shell tar xfO $< manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f2))
	$(HELM) repo add kyverno --force-update https://kyverno.github.io/kyverno/ >/dev/null
	$(HELM) upgrade \
		--install \
		--wait \
		--namespace kyverno \
		--create-namespace \
		--version v2.5.1 \
		--set image.tag=v1.7.1 \
		--set initImage.tag=v1.7.1 \
		--set image.pullPolicy=Never \
		--set initImage.pullPolicy=Never \
		kyverno kyverno/kyverno >/dev/null
	@$(KUBECTL) create ns cert-manager >/dev/null 2>&1 || true
	$(KUBECTL) apply --server-side -f make/config/kyverno/policy.yaml >/dev/null

$(BINDIR)/downloaded/pebble-$(PEBBLE_COMMIT).tar.gz: | $(BINDIR)/downloaded
	$(CURL) https://github.com/letsencrypt/pebble/archive/$(PEBBLE_COMMIT).tar.gz -o $@

# We can't use GOBIN with "go install" because cross-compilation is not
# possible with go install. That's a problem when cross-compiling for
# linux/arm64 when running on darwin/arm64.
$(call local-image-tar,pebble).dir/pebble: $(BINDIR)/downloaded/pebble-$(PEBBLE_COMMIT).tar.gz | $(NEEDS_GO)
	@mkdir -p $(dir $@)
	tar xzf $< -C /tmp
	cd /tmp/pebble-$(PEBBLE_COMMIT) && GOOS=linux GOARCH=$(CRI_ARCH) CGO_ENABLED=$(CGO_ENABLED) GOMAXPROCS=$(GOBUILDPROCS) $(GOBUILD) $(GOFLAGS) -o $(CURDIR)/$@ ./cmd/pebble

$(call local-image-tar,pebble): $(call local-image-tar,pebble).dir/pebble make/config/pebble/Containerfile.pebble
	@$(eval BASE := BASE_IMAGE_controller-linux-$(CRI_ARCH))
	$(CTR) build --quiet \
		-f make/config/pebble/Containerfile.pebble \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t local/pebble:local \
		$(dir $<) >/dev/null
	$(CTR) save local/pebble:local -o $@ >/dev/null

.PHONY: e2e-setup-pebble
e2e-setup-pebble: load-$(call local-image-tar,pebble) $(BINDIR)/scratch/kind-exists | $(NEEDS_HELM)
	$(HELM) upgrade \
		--install \
		--wait \
		--namespace pebble \
		--create-namespace \
		pebble make/config/pebble/chart >/dev/null

$(call local-image-tar,samplewebhook).dir/samplewebhook: make/config/samplewebhook/sample/main.go | $(NEEDS_GO)
	@mkdir -p $(dir $@)
	GOOS=linux GOARCH=$(CRI_ARCH) $(GOBUILD) -o $@ $(GOFLAGS) make/config/samplewebhook/sample/main.go

$(call local-image-tar,samplewebhook): $(call local-image-tar,samplewebhook).dir/samplewebhook make/config/samplewebhook/Containerfile.samplewebhook
	@$(eval BASE := BASE_IMAGE_controller-linux-$(CRI_ARCH))
	$(CTR) build --quiet \
		-f make/config/samplewebhook/Containerfile.samplewebhook \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t local/samplewebhook:local \
		$(dir $<) >/dev/null
	$(CTR) save local/samplewebhook:local -o $@ >/dev/null

.PHONY: e2e-setup-samplewebhook
e2e-setup-samplewebhook: load-$(call local-image-tar,samplewebhook) e2e-setup-certmanager $(BINDIR)/scratch/kind-exists | $(NEEDS_HELM)
	$(HELM) upgrade \
		--install \
		--wait \
		--namespace samplewebhook \
		--create-namespace \
		samplewebhook make/config/samplewebhook/chart >/dev/null

.PHONY: e2e-setup-projectcontour
e2e-setup-projectcontour: $(call image-tar,projectcontour) load-$(call image-tar,projectcontour) make/config/projectcontour/gateway.yaml make/config/projectcontour/contour.yaml $(BINDIR)/scratch/kind-exists | $(NEEDS_HELM) $(NEEDS_KUBECTL)
	@$(eval TAG=$(shell tar xfO $< manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f2))
	$(HELM) repo add bitnami --force-update https://charts.bitnami.com/bitnami >/dev/null
	# Warning: When upgrading the version of this helm chart, bear in mind that the IMAGE_projectcontour_* images above might need to be updated, too.
	# Each helm chart version in the bitnami repo corresponds to an underlying application version. Check application versions and chart versions with:
	# $$ helm search repo bitnami -l | grep -E "contour[^-]"
	$(HELM) upgrade \
		--install \
		--wait \
		--version 11.0.0 \
		--namespace projectcontour \
		--create-namespace \
		--set contour.ingressClass.create=false \
		--set contour.ingressClass.default=false \
		--set image.tag=$(TAG) \
		--set image.pullPolicy=Never \
		--set contour.service.type=ClusterIP \
		--set contour.service.externalTrafficPolicy="" \
		--set envoy.service.type=ClusterIP \
		--set envoy.service.externalTrafficPolicy="" \
		--set envoy.service.clusterIP=${SERVICE_IP_PREFIX}.14 \
		--set-file configInline=make/config/projectcontour/contour.yaml \
		projectcontour bitnami/contour >/dev/null
	$(KUBECTL) apply --server-side -f make/config/projectcontour/gateway.yaml

.PHONY: e2e-setup-sampleexternalissuer
e2e-setup-sampleexternalissuer: load-$(call image-tar,sampleexternalissuer) $(BINDIR)/scratch/kind-exists | $(NEEDS_KUBECTL)
	$(KUBECTL) apply -n sample-external-issuer-system -f https://github.com/cert-manager/sample-external-issuer/releases/download/v0.3.0/install.yaml >/dev/null
	$(KUBECTL) patch -n sample-external-issuer-system deployments.apps sample-external-issuer-controller-manager --type=json -p='[{"op": "add", "path": "/spec/template/spec/containers/1/imagePullPolicy", "value": "Never"}]' >/dev/null

# Note that the end-to-end tests are dealing with the Helm installation. We
# do not need to Helm install here.
.PHONY: e2e-setup-vault
e2e-setup-vault: load-$(call local-image-tar,vaultretagged) $(BINDIR)/scratch/kind-exists | $(NEEDS_HELM)

# Exported because it needs to flow down to make/e2e.sh.
export ARTIFACTS ?= $(shell pwd)/$(BINDIR)/artifacts

.PHONY: kind-logs
kind-logs: $(BINDIR)/scratch/kind-exists | $(NEEDS_KIND)
	rm -rf $(ARTIFACTS)/cert-manager-e2e-logs
	mkdir -p $(ARTIFACTS)/cert-manager-e2e-logs
	$(KIND) export logs $(ARTIFACTS)/cert-manager-e2e-logs --name=$(shell cat $(BINDIR)/scratch/kind-exists)

$(BINDIR)/scratch:
	@mkdir -p $@
