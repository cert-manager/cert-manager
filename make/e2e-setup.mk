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
K8S_VERSION := 1.30

IMAGE_ingressnginx_amd64 := registry.k8s.io/ingress-nginx/controller:v1.9.4@sha256:0115d7e01987c13e1be90b09c223c3e0d8e9a92e97c0421e712ad3577e2d78e5
IMAGE_kyverno_amd64 := ghcr.io/kyverno/kyverno:v1.10.3@sha256:031d2da484f3d89c78007cbb1cf1d7ae992e069683a2cdca0a0efb63a63fc735
IMAGE_kyvernopre_amd64 := ghcr.io/kyverno/kyvernopre:v1.10.3@sha256:5371ead07ebd09ff858f568a07b6807e8568772af61e626c9a0a5137bd7e62db
IMAGE_vault_amd64 := docker.io/hashicorp/vault:1.14.1@sha256:436d056e8e2a96c7356720069c29229970466f4f686886289dcc94dfa21d3155
IMAGE_bind_amd64 := docker.io/eafxx/bind:latest-ccf145d3@sha256:b6ea4da6cb689985a6729f20a1a2775b9211bdaebd2c956f22871624d4925db2
IMAGE_sampleexternalissuer_amd64 := ghcr.io/cert-manager/sample-external-issuer/controller:v0.4.0@sha256:964b378fe0dda7fc38ce3f211c3b24c780e44cef13c39d3206de985bad67f294
IMAGE_projectcontour_amd64 := ghcr.io/projectcontour/contour:v1.25.2@sha256:1570f04e96fb5e0ad71c2de61fee71c8d55b2fe5b7c827ce65e81bf7cc99bcbd

IMAGE_ingressnginx_arm64 := registry.k8s.io/ingress-nginx/controller:v1.9.4@sha256:3cdc716f0395886008c5e49972297adf1af87eeef472f71ff8de11bf53f25766
IMAGE_kyverno_arm64 := ghcr.io/kyverno/kyverno:v1.10.3@sha256:acf77f4fd08056941b5640d9489d46f2a1777e29d574e51926eac5250144dbd2
IMAGE_kyvernopre_arm64 := ghcr.io/kyverno/kyvernopre:v1.10.3@sha256:3ec997a6a26f600e4c2e439c3671e9f21c83a73bf486134eb6732481d0e371ca
IMAGE_vault_arm64 := docker.io/hashicorp/vault:1.14.1@sha256:27dd264f3813c71a66792191db5382f0cf9eeaf1ae91770634911facfcfe4837
IMAGE_bind_arm64 := docker.io/eafxx/bind:latest-ccf145d3@sha256:a302cff9f7ecfac0c3cfde1b53a614a81d16f93a247c838d3dac43384fefd9b4
IMAGE_sampleexternalissuer_arm64 := ghcr.io/cert-manager/sample-external-issuer/controller:v0.4.0@sha256:bdff00089ec7581c0d12414ce5ad1c6ccf5b6cacbfb0b0804fefe5043a1cb849
IMAGE_projectcontour_arm64 := ghcr.io/projectcontour/contour:v1.25.2@sha256:abbb2b7fee8eafddfd4ebd8e45510e6c1d86937461bc6934470ffb57211a9a8b

PEBBLE_COMMIT = ba5f81dd80fa870cbc19326f2d5a46f45f0b5ee3

LOCALIMAGE_pebble := local/pebble:local
LOCALIMAGE_vaultretagged := local/vault:local
LOCALIMAGE_samplewebhook := local/samplewebhook:local

IMAGE_kind_amd64 := $(shell make/cluster.sh --show-image)
IMAGE_kind_arm64 := $(IMAGE_kind_amd64)

# TODO: considering moving the installation commands in this file to separate scripts for readability
# Once that is done, we can consume this variable from ./make/config/lib.sh
SERVICE_IP_PREFIX = 10.0.0

# This variable is exported so that the Vault add-on in the E2E tests can set
# the image reference of the locally loaded Docker image when it installs the
# Vault Helm chart.
# The Vault Docker image is loaded into kind by `make e2e-setup`.
export E2E_VAULT_IMAGE := $(LOCALIMAGE_vaultretagged)

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
# The presence of the file $(bin_dir)/scratch/kind-exists indicates that your kube
# config's current context points to a kind cluster. The file contains the
# name of the kind cluster.
#
# We use FORCE instead of .PHONY because this is a real file that can be
# used as a prerequisite. If we were to use .PHONY, then the file's
# timestamp would not be used to check whether targets should be rebuilt,
# and they would get constantly rebuilt.
$(bin_dir)/scratch/kind-exists: make/config/kind/cluster.yaml preload-kind-image make/cluster.sh FORCE | $(bin_dir)/scratch $(NEEDS_KIND) $(NEEDS_KUBECTL) $(NEEDS_YQ)
	@$(eval KIND_CLUSTER_NAME ?= kind)
	@make/cluster.sh --name $(KIND_CLUSTER_NAME)
	@if [ "$(shell cat $@ 2>/dev/null)" != $(KIND_CLUSTER_NAME) ]; then echo $(KIND_CLUSTER_NAME) > $@; else touch $@; fi

.PHONY: kind-exists
kind-exists: $(bin_dir)/scratch/kind-exists

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
#     $(bin_dir)/downloaded/containers/amd64/docker.io/traefik+2.4.9@sha256+bfba204252.tar
#                                     <---> <--------------------------------------->
#                                   CRI_ARCH         IMAGE_kyverno_amd64
#                                                (with ":" replaced with "+")
#
# Note the "+" signs. We replace all the "+" with ":" because ":" can't be used
# in make targets. The "+" replacement is safe since it isn't a valid character
# in image names.
#
# When an image isn't available, i.e., IMAGE_imagename_arm64 is empty, we still
# return a string of the form "$(bin_dir)/downloaded/containers/amd64/missing-imagename.tar".
define image-tar
$(bin_dir)/downloaded/containers/$(CRI_ARCH)/$(if $(IMAGE_$(1)_$(CRI_ARCH)),$(subst :,+,$(IMAGE_$(1)_$(CRI_ARCH))),missing-$(1)).tar
endef

# The function "local-image-tar" returns the path to the image tarball for a given local
# image name. For example:
#
#     $(call local-image-tar, samplewebhook)
#
# returns the following path:
#
#     $(bin_dir)/containers/samplewebhook+local.tar
#                          <--------------------->
#                          LOCALIMAGE_samplewebhook
#                        (with ":" replaced with "+")
#
# Note the "+" signs. We replace all the "+" with ":" because ":" can't be used
# in make targets. The "+" replacement is safe since it isn't a valid character
# in image names.
#
# When an image isn't available, i.e., IMAGE_imagename is empty, we still
# return a string of the form "$(bin_dir)/containers/missing-imagename.tar".
define local-image-tar
$(bin_dir)/containers/$(if $(LOCALIMAGE_$(1)),$(subst :,+,$(LOCALIMAGE_$(1))),missing-$(1)).tar
endef

# Let's separate the pulling of the Kind image so that more tasks can be
# run in parallel when running "make -j e2e-setup". In CI, the Docker
# engine being stripped on every job, we save the kind image to
# "$(bin_dir)/downloads". Side note: we don't use "$(CI)" directly since we would
# get the message "warning: undefined variable 'CI'".
.PHONY: preload-kind-image
ifeq ($(shell printenv CI),)
preload-kind-image:
	@$(CTR) inspect $(IMAGE_kind_$(CRI_ARCH)) 2>/dev/null >&2 || (set -x; $(CTR) pull $(IMAGE_kind_$(CRI_ARCH)))
else
preload-kind-image: $(call image-tar,kind)
	$(CTR) inspect $(IMAGE_kind_$(CRI_ARCH)) 2>/dev/null >&2 || $(CTR) load -i $<
endif

LOAD_TARGETS=load-$(call image-tar,ingressnginx) load-$(call image-tar,kyverno) load-$(call image-tar,kyvernopre) load-$(call image-tar,bind) load-$(call image-tar,projectcontour) load-$(call image-tar,sampleexternalissuer) load-$(call local-image-tar,vaultretagged) load-$(call local-image-tar,pebble) load-$(call local-image-tar,samplewebhook) load-$(bin_dir)/containers/cert-manager-controller-linux-$(CRI_ARCH).tar load-$(bin_dir)/containers/cert-manager-acmesolver-linux-$(CRI_ARCH).tar load-$(bin_dir)/containers/cert-manager-cainjector-linux-$(CRI_ARCH).tar load-$(bin_dir)/containers/cert-manager-webhook-linux-$(CRI_ARCH).tar load-$(bin_dir)/containers/cert-manager-startupapicheck-linux-$(CRI_ARCH).tar
.PHONY: $(LOAD_TARGETS)
$(LOAD_TARGETS): load-%: % $(bin_dir)/scratch/kind-exists | $(NEEDS_KIND)
	$(KIND) load image-archive --name=$(shell cat $(bin_dir)/scratch/kind-exists) $*

# Download a single-arch image
#
# The input variable IMAGE_example_ARCH must contain the digest of the single-arch image manifest,
# NOT the multi-arch manifest.
#
# We use crane instead of docker when pulling images, which saves some time
# since we don't care about having the image available to docker.
#
# We don't pull using both the digest and tag because crane replaces the
# tag with "i-was-a-digest". We still check that the downloaded image
# matches the digest.
#
# We check that the remote image tag and digest still match what is pinned in
# the `IMAGE_example_arch` variables (above).
# This is useful because:
# 1. It tells us if the image maintainers have deliberately or maliciously
#    pushed a different image and re-used an existing tag.
# 2. It makes it easy to learn the new digest when updating the pinned image
#    tag. The rule will fail and the new digest will be printed out.
# 3. It prevents us accidentally using the wrong digest when we pin the images
#    in the variables above.
$(call image-tar,vault) $(call image-tar,kyverno) $(call image-tar,kyvernopre) $(call image-tar,bind) $(call image-tar,projectcontour) $(call image-tar,sampleexternalissuer) $(call image-tar,ingressnginx): $(bin_dir)/downloaded/containers/$(CRI_ARCH)/%.tar: | $(NEEDS_CRANE)
	@$(eval IMAGE=$(subst +,:,$*))
	@$(eval IMAGE_WITHOUT_DIGEST=$(shell cut -d@ -f1 <<<"$(IMAGE)"))
	@$(eval DIGEST=$(subst $(IMAGE_WITHOUT_DIGEST)@,,$(IMAGE)))
	@mkdir -p $(dir $@)
	diff <(echo "$(DIGEST)  -" | cut -d: -f2) <($(CRANE) manifest --platform=linux/$(CRI_ARCH) $(IMAGE_WITHOUT_DIGEST) | sha256sum)
	$(CRANE) pull $(IMAGE_WITHOUT_DIGEST) $@ --platform=linux/$(CRI_ARCH)

# Download the Kind node image
#
# This is handled differently from the other image downloads, because:
# 1. The pinned Kind image references are automatically generated using
#    `hack/latest-kind-image.sh`.
# 2. It uses digests that point to the multi-arch manifest, rather than the
#    actual image.
# 3. The Kind image tags DO change; each new Kind release has a set of Kind node
#    images tagged using the Kubernetes version. Subsequent Kind releases may
#    have an incompatible Kind node image format, but re-use the same Kubernetes
#    version tags.
$(call image-tar,kind): $(NEEDS_CRANE)
	@mkdir -p $(dir $@)
	$(CRANE) pull $(IMAGE_kind_$(CRI_ARCH)) $@ --platform linux/$(CRI_ARCH)

# Since we dynamically install Vault via Helm during the end-to-end tests,
# we need its image to be retagged to a well-known tag "local/vault:local".
$(call local-image-tar,vaultretagged): $(call image-tar,vault)
	@mkdir -p /tmp/vault $(dir $@)
	tar xf $< -C /tmp/vault
	cat /tmp/vault/manifest.json | jq '.[0].RepoTags |= ["local/vault:local"]' -r > /tmp/vault/temp
	mv /tmp/vault/temp /tmp/vault/manifest.json
	tar cf $@ -C /tmp/vault .
	@rm -rf /tmp/vault

FEATURE_GATES ?= AdditionalCertificateOutputFormats=true,ExperimentalCertificateSigningRequestControllers=true,ExperimentalGatewayAPISupport=true,ServerSideApply=true,LiteralCertificateSubject=true,UseCertificateRequestBasicConstraints=true,NameConstraints=true,OtherNames=true

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
E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_URL ?= https://raw.githubusercontent.com/cert-manager/website/ea5db62772e6b9d1430b9d63f581e74d5c18b627/public/docs/installation/best-practice/values.best-practice.yaml
E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_URL_SUM := $(shell sha256sum <<<$(E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_URL) | cut -d ' ' -f 1)

## A local Helm values file containing best-practice configuration values.
## It will be downloaded from E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_URL if
## it does not exist.
##
## @category Development
E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_FILE ?= $(bin_dir)/scratch/values-bestpractice-$(E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_URL_SUM).yaml
$(E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_FILE): | $(bin_dir)/scratch
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
feature_gates_controller := $(subst $(space),\$(comma),$(filter AllAlpha=% AllBeta=% AdditionalCertificateOutputFormats=% ValidateCAA=% ExperimentalCertificateSigningRequestControllers=% ExperimentalGatewayAPISupport=% ServerSideApply=% LiteralCertificateSubject=% UseCertificateRequestBasicConstraints=% NameConstraints=% SecretsFilteredCaching=% OtherNames=%, $(subst $(comma),$(space),$(FEATURE_GATES))))
feature_gates_webhook := $(subst $(space),\$(comma),$(filter AllAlpha=% AllBeta=% AdditionalCertificateOutputFormats=% LiteralCertificateSubject=% NameConstraints=% OtherNames=%, $(subst $(comma),$(space),$(FEATURE_GATES))))
feature_gates_cainjector := $(subst $(space),\$(comma),$(filter AllAlpha=% AllBeta=% ServerSideApply=%, $(subst $(comma),$(space),$(FEATURE_GATES))))

# When testing an published chart the repo can be configured using
# E2E_CERT_MANAGER_REPO 
E2E_CERT_MANAGER_REPO ?= https://charts.jetstack.io
# When testing an published chart the chart name can be configured using
# E2E_CERT_MANAGER_CHART. This can also be set to a local path to test a 
# downloaded chart
E2E_CERT_MANAGER_CHART ?= cert-manager
# When testing an published chart, default to the latest release
E2E_CERT_MANAGER_VERSION ?= 

# Example running E2E tests against a downloaded chart:
# 	E2E_EXISTING_CHART=true E2E_CERT_MANAGER_CHART=./cert-manager-v1.14.2.tgz make e2e-setup
# 	make e2e
#
# Example running E2E test against published version of a chart:
# 	E2E_EXISTING_CHART=true E2E_CERT_MANAGER_VERSION=1.14.2 make e2e-setup
# 	make e2e

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
ifdef E2E_EXISTING_CHART
.PHONY: e2e-setup-certmanager
e2e-setup-certmanager: e2e-setup-gatewayapi $(E2E_SETUP_OPTION_DEPENDENCIES) $(bin_dir)/scratch/kind-exists | $(NEEDS_KUBECTL) $(NEEDS_KIND) $(NEEDS_HELM)
	$(HELM) upgrade \
		--install \
		--create-namespace \
		--wait \
		--namespace cert-manager \
		--repo $(E2E_CERT_MANAGER_REPO) \
		$(addprefix --version,$(E2E_CERT_MANAGER_VERSION)) \
		--set crds.enabled=true \
		--set featureGates="$(feature_gates_controller)" \
		--set "extraArgs={--kube-api-qps=9000,--kube-api-burst=9000,--concurrent-workers=200,--enable-gateway-api}" \
		--set webhook.featureGates="$(feature_gates_webhook)" \
		--set "cainjector.extraArgs={--feature-gates=$(feature_gates_cainjector)}" \
		--set "dns01RecursiveNameservers=$(SERVICE_IP_PREFIX).16:53" \
		--set "dns01RecursiveNameserversOnly=true" \
		$(if $(E2E_SETUP_OPTION_BESTPRACTICE),--values=$(E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_FILE)) \
		cert-manager $(E2E_CERT_MANAGER_CHART) >/dev/null
else
.PHONY: e2e-setup-certmanager
e2e-setup-certmanager: $(bin_dir)/cert-manager.tgz $(foreach binaryname,controller acmesolver cainjector webhook startupapicheck,$(bin_dir)/containers/cert-manager-$(binaryname)-linux-$(CRI_ARCH).tar) $(foreach binaryname,controller acmesolver cainjector webhook startupapicheck,load-$(bin_dir)/containers/cert-manager-$(binaryname)-linux-$(CRI_ARCH).tar) e2e-setup-gatewayapi $(E2E_SETUP_OPTION_DEPENDENCIES) $(bin_dir)/scratch/kind-exists | $(NEEDS_KUBECTL) $(NEEDS_KIND) $(NEEDS_HELM)
	@$(eval TAG = $(shell tar xfO $(bin_dir)/containers/cert-manager-controller-linux-$(CRI_ARCH).tar manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f2))
	$(HELM) upgrade \
		--install \
		--create-namespace \
		--wait \
		--namespace cert-manager \
		--set image.repository="$(shell tar xfO $(bin_dir)/containers/cert-manager-controller-linux-$(CRI_ARCH).tar manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f1)" \
		--set cainjector.image.repository="$(shell tar xfO $(bin_dir)/containers/cert-manager-cainjector-linux-$(CRI_ARCH).tar manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f1)" \
		--set webhook.image.repository="$(shell tar xfO $(bin_dir)/containers/cert-manager-webhook-linux-$(CRI_ARCH).tar manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f1)" \
		--set acmesolver.image.repository="$(shell tar xfO $(bin_dir)/containers/cert-manager-acmesolver-linux-$(CRI_ARCH).tar manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f1)" \
		--set startupapicheck.image.repository="$(shell tar xfO $(bin_dir)/containers/cert-manager-startupapicheck-linux-$(CRI_ARCH).tar manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f1)" \
		--set image.tag="$(TAG)" \
		--set cainjector.image.tag="$(TAG)" \
		--set webhook.image.tag="$(TAG)" \
		--set acmesolver.image.tag="$(TAG)" \
		--set startupapicheck.image.tag="$(TAG)" \
		--set crds.enabled=true \
		--set featureGates="$(feature_gates_controller)" \
		--set "extraArgs={--kube-api-qps=9000,--kube-api-burst=9000,--concurrent-workers=200,--enable-gateway-api}" \
		--set webhook.featureGates="$(feature_gates_webhook)" \
		--set "cainjector.extraArgs={--feature-gates=$(feature_gates_cainjector)}" \
		--set "dns01RecursiveNameservers=$(SERVICE_IP_PREFIX).16:53" \
		--set "dns01RecursiveNameserversOnly=true" \
		$(if $(E2E_SETUP_OPTION_BESTPRACTICE),--values=$(E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_FILE)) \
		cert-manager $< >/dev/null
endif

.PHONY: e2e-setup-bind
e2e-setup-bind: $(call image-tar,bind) load-$(call image-tar,bind) $(wildcard make/config/bind/*.yaml) $(bin_dir)/scratch/kind-exists | $(NEEDS_KUBECTL)
	@$(eval IMAGE = $(shell tar xfO $< manifest.json | jq '.[0].RepoTags[0]' -r))
	$(KUBECTL) get ns bind 2>/dev/null >&2 || $(KUBECTL) create ns bind
	sed -e "s|{SERVICE_IP_PREFIX}|$(SERVICE_IP_PREFIX)|g" -e "s|{IMAGE}|$(IMAGE)|g" make/config/bind/*.yaml | $(KUBECTL) apply -n bind -f - >/dev/null

.PHONY: e2e-setup-gatewayapi
e2e-setup-gatewayapi: $(bin_dir)/scratch/gateway-api-$(GATEWAY_API_VERSION).yaml $(bin_dir)/scratch/kind-exists $(NEEDS_KUBECTL)
	$(KUBECTL) apply --server-side -f $(bin_dir)/scratch/gateway-api-$(GATEWAY_API_VERSION).yaml > /dev/null


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
		--version 4.7.3 \
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
e2e-setup-kyverno: $(call image-tar,kyverno) $(call image-tar,kyvernopre) load-$(call image-tar,kyverno) load-$(call image-tar,kyvernopre) make/config/kyverno/policy.yaml $(bin_dir)/scratch/kind-exists | $(NEEDS_KUBECTL) $(NEEDS_HELM)
	@$(eval TAG=$(shell tar xfO $< manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f2))
	$(HELM) repo add kyverno --force-update https://kyverno.github.io/kyverno/ >/dev/null
	$(HELM) upgrade \
		--install \
		--wait \
		--namespace kyverno \
		--create-namespace \
		--version 3.0.4 \
		--set image.tag=v1.8.1 \
		--set initImage.tag=v1.8.1 \
		--set image.pullPolicy=Never \
		--set initImage.pullPolicy=Never \
		kyverno kyverno/kyverno >/dev/null
	@$(KUBECTL) create ns cert-manager >/dev/null 2>&1 || true
	$(KUBECTL) apply --server-side -f make/config/kyverno/policy.yaml >/dev/null

$(bin_dir)/downloaded/pebble-$(PEBBLE_COMMIT).tar.gz: | $(bin_dir)/downloaded
	$(CURL) https://github.com/letsencrypt/pebble/archive/$(PEBBLE_COMMIT).tar.gz -o $@

# We can't use GOBIN with "go install" because cross-compilation is not
# possible with go install. That's a problem when cross-compiling for
# linux/arm64 when running on darwin/arm64.
$(call local-image-tar,pebble).dir/pebble: $(bin_dir)/downloaded/pebble-$(PEBBLE_COMMIT).tar.gz | $(NEEDS_GO)
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
e2e-setup-pebble: load-$(call local-image-tar,pebble) $(bin_dir)/scratch/kind-exists | $(NEEDS_HELM)
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
e2e-setup-samplewebhook: load-$(call local-image-tar,samplewebhook) e2e-setup-certmanager $(bin_dir)/scratch/kind-exists | $(NEEDS_HELM)
	$(HELM) upgrade \
		--install \
		--wait \
		--namespace samplewebhook \
		--create-namespace \
		samplewebhook make/config/samplewebhook/chart >/dev/null

.PHONY: e2e-setup-projectcontour
e2e-setup-projectcontour: $(call image-tar,projectcontour) load-$(call image-tar,projectcontour) make/config/projectcontour/gateway.yaml make/config/projectcontour/contour.yaml $(bin_dir)/scratch/kind-exists | $(NEEDS_HELM) $(NEEDS_KUBECTL)
	@$(eval TAG=$(shell tar xfO $< manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f2))
	$(HELM) repo add bitnami --force-update https://charts.bitnami.com/bitnami >/dev/null
	# Warning: When upgrading the version of this helm chart, bear in mind that the IMAGE_projectcontour_* images above might need to be updated, too.
	# Each helm chart version in the bitnami repo corresponds to an underlying application version. Check application versions and chart versions with:
	# $$ helm search repo bitnami -l | grep -E "contour[^-]"
	$(HELM) upgrade \
		--install \
		--wait \
		--version 12.2.4 \
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
e2e-setup-sampleexternalissuer: load-$(call image-tar,sampleexternalissuer) $(bin_dir)/scratch/kind-exists | $(NEEDS_KUBECTL)
	$(KUBECTL) apply -n sample-external-issuer-system -f https://github.com/cert-manager/sample-external-issuer/releases/download/v0.4.0/install.yaml >/dev/null
	$(KUBECTL) patch -n sample-external-issuer-system deployments.apps sample-external-issuer-controller-manager --type=json -p='[{"op": "add", "path": "/spec/template/spec/containers/1/imagePullPolicy", "value": "Never"}]' >/dev/null

# Note that the end-to-end tests are dealing with the Helm installation. We
# do not need to Helm install here.
.PHONY: e2e-setup-vault
e2e-setup-vault: load-$(call local-image-tar,vaultretagged) $(bin_dir)/scratch/kind-exists | $(NEEDS_HELM)

# Exported because it needs to flow down to make/e2e.sh.
export ARTIFACTS ?= $(shell pwd)/$(bin_dir)/artifacts

.PHONY: kind-logs
kind-logs: $(bin_dir)/scratch/kind-exists | $(NEEDS_KIND)
	rm -rf $(ARTIFACTS)/cert-manager-e2e-logs
	mkdir -p $(ARTIFACTS)/cert-manager-e2e-logs
	$(KIND) export logs $(ARTIFACTS)/cert-manager-e2e-logs --name=$(shell cat $(bin_dir)/scratch/kind-exists)
