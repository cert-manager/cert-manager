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

## Experimental tools for building and deploying cert-manager using ko to build and push Docker images.
## You need to have go workspaces set up to use the ko make targets.
## https://go.dev/blog/get-familiar-with-workspaces.
## Run make go-workspaces to set up a Go workspace for this repo.
##
## Examples:
##
##  # Build and Push all images to an OCI registry
##  make ko-images-push KO_REGISTRY=<my-oci-registry>
##
##  # Build and Push images to an OCI registry and deploy cert-manager to the current cluster in KUBECONFIG
##  make ko-deploy-certmanager KO_REGISTRY=<my-oci-registry> [KO_HELM_VALUES_FILES=path/to/values.yaml]
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
KO_BINS ?= controller acmesolver cainjector webhook startupapicheck

## (optional) Paths of Helm values files which will be supplied to `helm install
## --values` flag by make ko-deploy-certmanager.
## @category Experimental/ko
KO_HELM_VALUES_FILES ?=

export KOCACHE = $(bin_dir)/scratch/ko/cache

KO_IMAGE_REFS = $(foreach bin,$(KO_BINS),_bin/scratch/ko/$(bin).yaml)
$(KO_IMAGE_REFS): _bin/scratch/ko/%.yaml: FORCE | $(NEEDS_KO) $(NEEDS_YQ)
	@mkdir -p $(dir $@)
	@$(eval export KO_DOCKER_REPO=$(KO_REGISTRY)/cert-manager-$*)
	$(KO) build ./cmd/$* \
		--bare \
		--sbom=$(KO_SBOM) \
		--platform=$(KO_PLATFORM) \
		--tags=$(VERSION) \
		| $(YQ) 'capture("(?P<ref>(?P<repository>[^:]+):(?P<tag>[^@]+)@(?P<digest>.*))")' > $@

.PHONY: ko-images-push
## Build and push docker images to an OCI registry using ko.
## @category Experimental/ko
ko-images-push: $(KO_IMAGE_REFS)

.PHONY: ko-deploy-certmanager
## Deploy cert-manager after pushing docker images to an OCI registry using ko.
## @category Experimental/ko
ko-deploy-certmanager: $(bin_dir)/cert-manager.tgz $(KO_IMAGE_REFS)
	@$(eval ACME_HTTP01_SOLVER_IMAGE = $(shell $(YQ) '.repository + "@" + .digest' $(bin_dir)/scratch/ko/acmesolver.yaml))
	$(HELM) upgrade cert-manager $< \
		--install \
		--create-namespace \
		--wait \
		--namespace cert-manager \
		$(and $(KO_HELM_VALUES_FILES),--values $(KO_HELM_VALUES_FILES)) \
		--set image.repository="$(shell $(YQ) .repository $(bin_dir)/scratch/ko/controller.yaml)" \
		--set image.digest="$(shell $(YQ) .digest $(bin_dir)/scratch/ko/controller.yaml)" \
		--set cainjector.image.repository="$(shell $(YQ) .repository $(bin_dir)/scratch/ko/cainjector.yaml)" \
		--set cainjector.image.digest="$(shell $(YQ) .digest $(bin_dir)/scratch/ko/cainjector.yaml)" \
		--set webhook.image.repository="$(shell $(YQ) .repository $(bin_dir)/scratch/ko/webhook.yaml)" \
		--set webhook.image.digest="$(shell $(YQ) .digest $(bin_dir)/scratch/ko/webhook.yaml)" \
		--set startupapicheck.image.repository="$(shell $(YQ) .repository $(bin_dir)/scratch/ko/startupapicheck.yaml)" \
		--set startupapicheck.image.digest="$(shell $(YQ) .digest $(bin_dir)/scratch/ko/startupapicheck.yaml)" \
		--set crds.enabled=true \
		--set "extraArgs={--acme-http01-solver-image=$(ACME_HTTP01_SOLVER_IMAGE)}"
