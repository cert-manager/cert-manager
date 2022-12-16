## Experimental tools for building and deploying cert-manager using ko to build and push Docker images.
##
## Examples:
##
##  # Build and Push all images to an OCI registry
##  make ko-images-push KO_REGISTRY=<my-oci-registry>
##
##  # Build and Push images to an OCI registry and deploy cert-manager to the current cluster in KUBECONFIG
##  make ko-deploy-certmanager KO_REGISTRY=<my-oci-registry>
##
## @category Experimental/ko

## (required) The OCI registry prefix to which images will be pushed by ko.
## @category Experimental/ko
KO_REGISTRY ?= $(error "KO_REGISTRY is a required environment variable")

## (optional) The SBOM media type to use (none will disable SBOM synthesis and
## upload, also supports: spdx, cyclonedx, go.version-m).
## @category Experimental/ko
KO_SBOM ?= none

## (optional) Which platforms to include in the multi-arch image.
## Format: all | <os>[/<arch>[/<variant>]][,platform]*
## @category Experimental/ko
KO_PLATFORM ?= linux/amd64

## (optional) Which cert-manager images to build.
## @category Experimental/ko
KO_BINS ?= controller acmesolver cainjector webhook ctl

export KOCACHE = $(BINDIR)/scratch/ko/cache

KO_IMAGE_REFS = $(foreach bin,$(KO_BINS),_bin/scratch/ko/$(bin).yaml)
$(KO_IMAGE_REFS): _bin/scratch/ko/%.yaml: FORCE | $(NEEDS_KO) $(NEEDS_YQ)
	@mkdir -p $(dir $@)
	@$(eval export KO_DOCKER_REPO=$(KO_REGISTRY)/cert-manager-$*)
	$(KO) build ./cmd/$* \
		--bare \
		--sbom=$(KO_SBOM) \
		--platform=$(KO_PLATFORM) \
		--tags=$(RELEASE_VERSION) \
		| $(YQ) 'capture("(?P<ref>(?P<repository>[^:]+):(?P<tag>[^@]+)@(?P<digest>.*))")' > $@

.PHONY: ko-images-push
## Build and push docker images to an OCI registry using ko.
## @category Experimental/ko
ko-images-push: $(KO_IMAGE_REFS)

.PHONY: ko-deploy-cert-manager
## Deploy cert-manager after pushing docker images to an OCI registry using ko.
## @category Experimental/ko
ko-deploy-certmanager: $(BINDIR)/cert-manager.tgz $(KO_IMAGE_REFS)
	@$(eval ACME_HTTP01_SOLVER_IMAGE = $(shell $(YQ) '.repository + "@" + .digest' $(BINDIR)/scratch/ko/acmesolver.yaml))
	$(HELM) upgrade cert-manager $< \
		--install \
		--create-namespace \
		--wait \
		--namespace cert-manager \
		--set image.repository="$(shell $(YQ) .repository $(BINDIR)/scratch/ko/controller.yaml)" \
		--set image.digest="$(shell $(YQ) .digest $(BINDIR)/scratch/ko/controller.yaml)" \
		--set cainjector.image.repository="$(shell $(YQ) .repository $(BINDIR)/scratch/ko/cainjector.yaml)" \
		--set cainjector.image.digest="$(shell $(YQ) .digest $(BINDIR)/scratch/ko/cainjector.yaml)" \
		--set webhook.image.repository="$(shell $(YQ) .repository $(BINDIR)/scratch/ko/webhook.yaml)" \
		--set webhook.image.digest="$(shell $(YQ) .digest $(BINDIR)/scratch/ko/webhook.yaml)" \
		--set startupapicheck.image.repository="$(shell $(YQ) .repository $(BINDIR)/scratch/ko/ctl.yaml)" \
		--set startupapicheck.image.digest="$(shell $(YQ) .digest $(BINDIR)/scratch/ko/ctl.yaml)" \
		--set installCRDs=true \
		--set "extraArgs={--acme-http01-solver-image=$(ACME_HTTP01_SOLVER_IMAGE)}" \
