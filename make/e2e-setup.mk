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

# We are using @inteon's fork of Pebble, which adds support for signing CSRs with
# Ed25519 keys:
# - https://github.com/letsencrypt/pebble/pull/468
# - https://github.com/inteon/pebble/tree/add_Ed25519_support
PEBBLE_COMMIT = 8318667fcd32f96579c45ee64c747d52519f0cdc

# TODO: considering moving the installation commands in this file to separate scripts for readability
# Once that is done, we can consume this variable from ./make/config/lib.sh
SERVICE_IP_PREFIX = 10.0.0

# This variable is exported so that the Vault add-on in the E2E tests can set
# the image reference of the locally loaded Docker image when it installs the
# Vault Helm chart.
# The Vault Docker image is loaded into kind by `make e2e-setup`.
export E2E_VAULT_IMAGE := dev.local/vault:dev

FEATURE_GATES ?= ExperimentalCertificateSigningRequestControllers=true,ExperimentalGatewayAPISupport=true,ServerSideApply=true,LiteralCertificateSubject=true,UseCertificateRequestBasicConstraints=true,NameConstraints=true,OtherNames=true

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
feature_gates_controller := $(subst $(space),\$(comma),$(filter AllAlpha=% AllBeta=% ExperimentalCertificateSigningRequestControllers=% ExperimentalGatewayAPISupport=% ServerSideApply=% LiteralCertificateSubject=% UseCertificateRequestBasicConstraints=% NameConstraints=% SecretsFilteredCaching=% OtherNames=%, $(subst $(comma),$(space),$(FEATURE_GATES))))
feature_gates_webhook := $(subst $(space),\$(comma),$(filter AllAlpha=% AllBeta=% LiteralCertificateSubject=% NameConstraints=% OtherNames=%, $(subst $(comma),$(space),$(FEATURE_GATES))))
feature_gates_cainjector := $(subst $(space),\$(comma),$(filter AllAlpha=% AllBeta=% ServerSideApply=% CAInjectorMerging=%, $(subst $(comma),$(space),$(FEATURE_GATES))))


# The "install" target can be run on its own with any currently active cluster,
# we can't use any other cluster then a target containing "test-e2e" is run.
# When a "test-e2e" target is run, the currently active cluster must be the kind
# cluster created by the "kind-cluster" target.
ifeq ($(findstring e2e-setup,$(MAKECMDGOALS)),e2e-setup)
install: kind-cluster oci-load-controller oci-load-acmesolver oci-load-webhook oci-load-cainjector oci-load-startupapicheck
install: e2e-setup-gatewayapi
install: e2e-setup-bind
endif

INSTALL_OPTIONS :=
INSTALL_OPTIONS += \
		--set crds.enabled=true \
		--set featureGates="$(feature_gates_controller)" \
		--set webhook.featureGates="$(feature_gates_webhook)" \
		--set cainjector.featureGates="$(feature_gates_cainjector)" \
		\
		--set image.repository=$(oci_controller_image_name_development) \
		--set cainjector.image.repository=$(oci_cainjector_image_name_development) \
		--set webhook.image.repository=$(oci_webhook_image_name_development) \
		--set acmesolver.image.repository=$(oci_acmesolver_image_name_development) \
		--set startupapicheck.image.repository=$(oci_startupapicheck_image_name_development)

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
e2e-setup: INSTALL_OPTIONS += --set "extraArgs={--kube-api-qps=9000,--kube-api-burst=9000,--concurrent-workers=200,--enable-gateway-api}"
e2e-setup: INSTALL_OPTIONS += --set "dns01RecursiveNameservers=$(SERVICE_IP_PREFIX).16:53"
e2e-setup: INSTALL_OPTIONS += --set "dns01RecursiveNameserversOnly=true"
e2e-setup: INSTALL_OPTIONS += $(if $(E2E_SETUP_OPTION_BESTPRACTICE),--values=$(E2E_SETUP_OPTION_BESTPRACTICE_HELM_VALUES_FILE))
e2e-setup: install
e2e-setup: e2e-setup-vault
e2e-setup: e2e-setup-sampleexternalissuer
e2e-setup: e2e-setup-samplewebhook
e2e-setup: e2e-setup-pebble
e2e-setup: e2e-setup-ingressnginx
e2e-setup: e2e-setup-projectcontour

.PHONY: e2e-setup-coredns
e2e-setup-coredns: kind-cluster | $(NEEDS_KUBECTL) $(bin_dir)/scratch
	$(KUBECTL) get -ogo-template='{{.data.Corefile}}' -n=kube-system configmap/coredns > $(bin_dir)/scratch/coredns.yaml
	if ! grep -q "example.com:53 {" $(bin_dir)/scratch/coredns.yaml; then \
		echo -e "example.com:53 {\n    forward . $(SERVICE_IP_PREFIX).16\n}\n" >> $(bin_dir)/scratch/coredns.yaml; \
	fi
	$(KUBECTL) create configmap -oyaml coredns --dry-run=client --from-file=Corefile=$(bin_dir)/scratch/coredns.yaml \
		| $(KUBECTL) apply --server-side --force-conflicts -n kube-system -f - >/dev/null

.PHONY: e2e-setup-bind
e2e-setup-bind: e2e-setup-coredns $(wildcard make/config/bind/*.yaml) kind-cluster | $(NEEDS_KUBECTL)
	$(KUBECTL) get ns bind 2>/dev/null >&2 || $(KUBECTL) create ns bind
	sed \
		-e "s|{SERVICE_IP_PREFIX}|$(SERVICE_IP_PREFIX)|g" \
		-e "s|{IMAGE}|$(docker.io/ubuntu/bind9.FULL)|g" \
		make/config/bind/*.yaml \
		| $(KUBECTL) apply -n bind -f - >/dev/null

.PHONY: e2e-setup-gatewayapi
e2e-setup-gatewayapi: $(bin_dir)/scratch/gateway-api-$(GATEWAY_API_VERSION).yaml kind-cluster | $(NEEDS_KUBECTL)
	$(KUBECTL) apply --server-side -f $(bin_dir)/scratch/gateway-api-$(GATEWAY_API_VERSION).yaml > /dev/null

# v1 NGINX-Ingress by default only watches Ingresses with Ingress class
# defined. When configuring solver block for ACME HTTP01 challenge on an
# ACME issuer, cert-manager users can currently specify either an Ingress
# name or a class. We also e2e test these two ways of creating Ingresses
# with ingress-shim. For the ingress controller to watch our Ingresses that
# don't have a class, we pass a --watch-ingress-without-class flag:
# https://github.com/kubernetes/ingress-nginx/blob/main/charts/ingress-nginx/values.yaml#L64-L67
#
# Versions of ingress-nginx >=1.8.0 support a strict-validate-path-type
# configuration option which, when enabled, disallows . (dot) in the path value.
# This is a bug which makes it impossible to use various legitimate URL paths,
# including the http://<YOUR_DOMAIN>/.well-known/acme-challenge/<TOKEN> URLs
# used for ACME HTTP01. To make matters worse, the buggy validation is enabled
# by default in ingress-nginx >= 1.12.0.
# We disable it by passing a `--set-string controller.config.strict-validate-path-type=false` flag.
# https://github.com/kubernetes/ingress-nginx/issues/11176
.PHONY: e2e-setup-ingressnginx
e2e-setup-ingressnginx: kind-cluster | $(NEEDS_HELM)
	$(HELM) repo add ingress-nginx --force-update https://kubernetes.github.io/ingress-nginx >/dev/null
	$(HELM) upgrade \
		--install \
		--wait \
		--version 4.12.3 \
		--namespace ingress-nginx \
		--create-namespace \
		--set controller.image.repository=$(registry.k8s.io/ingress-nginx/controller.REPO) \
		--set controller.image.tag=$(registry.k8s.io/ingress-nginx/controller.TAG) \
		--set controller.image.digest= \
		--set controller.image.pullPolicy=Never \
		--set controller.service.clusterIP=${SERVICE_IP_PREFIX}.15 \
		--set controller.service.type=ClusterIP \
		--set controller.config.no-tls-redirect-locations= \
		--set-string controller.config.strict-validate-path-type=false \
		--set admissionWebhooks.enabled=true \
		--set controller.admissionWebhooks.enabled=true \
		--set controller.watchIngressWithoutClass=true \
		ingress-nginx ingress-nginx/ingress-nginx >/dev/null

.PHONY: e2e-setup-kyverno
e2e-setup-kyverno: make/config/kyverno/policy.yaml kind-cluster | $(NEEDS_KUBECTL) $(NEEDS_HELM)
	$(HELM) repo add kyverno --force-update https://kyverno.github.io/kyverno/ >/dev/null
	$(HELM) upgrade \
		--install \
		--wait \
		--namespace kyverno \
		--create-namespace \
		--version 3.2.4 \
		--set webhooksCleanup.enabled=false \
		--set reportsController.enabled=false \
		--set cleanupController.enabled=false \
		--set backgroundController.enabled=false \
		--set admissionController.container.image.registry="ghcr.io" \
		--set admissionController.container.image.repository="kyverno/kyverno" \
		--set admissionController.container.image.tag=$(ghcr.io/kyverno/kyverno.TAG) \
		--set admissionController.container.image.pullPolicy=Never \
		--set admissionController.initContainer.image.registry="ghcr.io" \
		--set admissionController.initContainer.image.repository="kyverno/kyvernopre" \
		--set admissionController.initContainer.image.tag=$(ghcr.io/kyverno/kyvernopre.TAG) \
		--set admissionController.initContainer.image.pullPolicy=Never \
		kyverno kyverno/kyverno >/dev/null
	@$(KUBECTL) create ns cert-manager >/dev/null 2>&1 || true
	$(KUBECTL) apply --server-side -f make/config/kyverno/policy.yaml >/dev/null

.PHONY: e2e-setup-projectcontour
e2e-setup-projectcontour: make/config/projectcontour/gateway.yaml make/config/projectcontour/contour.yaml kind-cluster | $(NEEDS_HELM) $(NEEDS_KUBECTL)
	$(HELM) repo add bitnami --force-update https://charts.bitnami.com/bitnami >/dev/null
	# Warning: When upgrading the version of this helm chart, bear in mind that the IMAGE_projectcontour_* images above might need to be updated, too.
	# Each helm chart version in the bitnami repo corresponds to an underlying application version. Check application versions and chart versions with:
	# $$ helm search repo bitnami -l | grep -E "contour[^-]"
	$(HELM) upgrade \
		--install \
		--wait \
		--version 18.2.4 \
		--namespace projectcontour \
		--create-namespace \
		--set contour.ingressClass.create=false \
		--set contour.ingressClass.default=false \
		--set contour.image.registry="ghcr.io" \
		--set contour.image.repository="projectcontour/contour" \
		--set contour.image.tag=$(ghcr.io/projectcontour/contour.TAG) \
		--set contour.image.pullPolicy=Never \
		--set contour.service.type=ClusterIP \
		--set contour.service.externalTrafficPolicy="" \
		--set envoy.service.type=ClusterIP \
		--set envoy.service.externalTrafficPolicy="" \
		--set envoy.service.clusterIP=${SERVICE_IP_PREFIX}.14 \
		--set-file configInline=make/config/projectcontour/contour.yaml \
		projectcontour bitnami/contour >/dev/null
	$(KUBECTL) apply --server-side -f make/config/projectcontour/gateway.yaml

# TODO1: upgrade sample-external-issuer
# TODO2: overwrite the images in the YAML
.PHONY: e2e-setup-sampleexternalissuer
e2e-setup-sampleexternalissuer: kind-cluster | $(NEEDS_KUBECTL)
	$(KUBECTL) apply -n sample-external-issuer-system -f https://github.com/cert-manager/sample-external-issuer/releases/download/v0.4.0/install.yaml >/dev/null
	$(KUBECTL) patch -n sample-external-issuer-system deployments.apps sample-external-issuer-controller-manager --type=json -p='[{"op": "add", "path": "/spec/template/spec/containers/1/imagePullPolicy", "value": "Never"}]' >/dev/null

$(bin_dir)/containers/vault.tar: $(docker.io/hashicorp/vault.TAR) | $(NEEDS_IMAGE-TOOL)
	cp $(docker.io/hashicorp/vault.TAR) $@
	$(IMAGE-TOOL) tag-docker-tar $@ "$(E2E_VAULT_IMAGE)"

# Note that the end-to-end tests are dealing with the Helm installation. We
# do not need to Helm install here.
.PHONY: e2e-setup-vault
e2e-setup-vault: $(bin_dir)/containers/vault.tar kind-cluster | $(NEEDS_KIND)
	$(KIND) load image-archive --name $(kind_cluster_name) $(bin_dir)/containers/vault.tar

$(bin_dir)/downloaded/pebble-$(PEBBLE_COMMIT).tar.gz: | $(bin_dir)/downloaded
	$(CURL) https://github.com/inteon/pebble/archive/$(PEBBLE_COMMIT).tar.gz -o $@

# We can't use GOBIN with "go install" because cross-compilation is not
# possible with go install. That's a problem when cross-compiling for
# linux/arm64 when running on darwin/arm64.
$(bin_dir)/containers/pebble.tar.dir/pebble: $(bin_dir)/downloaded/pebble-$(PEBBLE_COMMIT).tar.gz | $(NEEDS_GO)
	@mkdir -p $(dir $@) $(bin_dir)/containers/pebble.tar.dir/tmp
	tar xzf $< -C $(bin_dir)/containers/pebble.tar.dir/tmp
	cd $(bin_dir)/containers/pebble.tar.dir/tmp/pebble-$(PEBBLE_COMMIT) && \
		GOOS=linux GOARCH=$(HOST_ARCH) CGO_ENABLED=0 $(GO) build -o $(CURDIR)/$@ ./cmd/pebble

$(bin_dir)/containers/pebble.tar: $(bin_dir)/containers/pebble.tar.dir/pebble make/config/pebble/Containerfile.pebble | $(NEEDS_CTR)
	$(CTR) build --quiet \
		-f make/config/pebble/Containerfile.pebble \
		--build-arg BASE_IMAGE=$(base_image_static) \
		-t local/pebble:local \
		$(dir $<) >/dev/null
	$(CTR) save local/pebble:local -o $@ >/dev/null

.PHONY: e2e-setup-pebble
e2e-setup-pebble: $(bin_dir)/containers/pebble.tar kind-cluster | $(NEEDS_HELM) $(NEEDS_KIND)
	$(KIND) load image-archive --name $(kind_cluster_name) $(bin_dir)/containers/pebble.tar

	$(HELM) upgrade \
		--install \
		--wait \
		--namespace pebble \
		--create-namespace \
		pebble make/config/pebble/chart >/dev/null

$(bin_dir)/containers/samplewebhook.tar.dir/samplewebhook: make/config/samplewebhook/sample/main.go | $(NEEDS_GO)
	@mkdir -p $(dir $@)
	GOOS=linux GOARCH=$(HOST_ARCH) CGO_ENABLED=0 $(GO) build -o $@ make/config/samplewebhook/sample/main.go

$(bin_dir)/containers/samplewebhook.tar: $(bin_dir)/containers/samplewebhook.tar.dir/samplewebhook make/config/samplewebhook/Containerfile.samplewebhook | $(NEEDS_CTR)
	$(CTR) build --quiet \
		-f make/config/samplewebhook/Containerfile.samplewebhook \
		--build-arg BASE_IMAGE=$(base_image_static) \
		-t local/samplewebhook:local \
		$(dir $<) >/dev/null
	$(CTR) save local/samplewebhook:local -o $@ >/dev/null

.PHONY: e2e-setup-samplewebhook
e2e-setup-samplewebhook: $(bin_dir)/containers/samplewebhook.tar install kind-cluster | $(NEEDS_HELM) $(NEEDS_KIND)
	$(KIND) load image-archive --name $(kind_cluster_name) $(bin_dir)/containers/samplewebhook.tar

	$(HELM) upgrade \
		--install \
		--wait \
		--namespace samplewebhook \
		--create-namespace \
		samplewebhook make/config/samplewebhook/chart >/dev/null
