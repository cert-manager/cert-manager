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

$(kind_cluster_config): make/config/kind/cluster.yaml | $(bin_dir)/scratch
	cat $< | \
	sed -e 's|{{KIND_IMAGES}}|$(CURDIR)/$(images_tar_dir)|g' \
	> $@

# Version of Gateway API install bundle https://gateway-api.sigs.k8s.io/v1alpha2/guides/#installing-gateway-api
GATEWAY_API_VERSION=v1.0.0

$(bin_dir)/scratch/gateway-api-$(GATEWAY_API_VERSION).yaml: | $(bin_dir)/scratch
	$(CURL) https://github.com/kubernetes-sigs/gateway-api/releases/download/$(GATEWAY_API_VERSION)/experimental-install.yaml -o $@

include make/util.mk
include make/ci.mk
include make/test.mk
include make/manifests.mk
include make/e2e-setup.mk
include make/third_party.mk
include make/scan.mk

generate-licenses: generate-go-licenses

.PHONY: tidy
tidy: generate-go-mod-tidy

.PHONY: update-licenses
update-licenses: generate-go-licenses

.PHONY: verify-licenses
verify-licenses: verify-generate-go-licenses

.PHONY: release
## Publish all release artifacts (image + helm chart)
## @category [shared] Release
release:
	$(MAKE) oci-push-controller oci-push-acmesolver oci-push-webhook oci-push-cainjector oci-push-startupapicheck
	$(MAKE) helm-chart-oci-push

	@echo "RELEASE_OCI_CONTROLLER_IMAGE=$(oci_controller_image_name)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_OCI_CONTROLLER_TAG=$(oci_controller_image_tag)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_OCI_ACMESOLVER_IMAGE=$(oci_acmesolver_image_name)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_OCI_ACMESOLVER_TAG=$(oci_acmesolver_image_tag)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_OCI_WEBHOOK_IMAGE=$(oci_webhook_image_name)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_OCI_WEBHOOK_TAG=$(oci_webhook_image_tag)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_OCI_CAINJECTOR_IMAGE=$(oci_cainjector_image_name)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_OCI_CAINJECTOR_TAG=$(oci_cainjector_image_tag)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_OCI_STARTUPAPICHECK_IMAGE=$(oci_startupapicheck_image_name)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_OCI_STARTUPAPICHECK_TAG=$(oci_startupapicheck_image_tag)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_HELM_CHART_IMAGE=$(helm_chart_image_name)" >> "$(GITHUB_OUTPUT)"
	@echo "RELEASE_HELM_CHART_VERSION=$(helm_chart_version)" >> "$(GITHUB_OUTPUT)"

	@echo "Release complete!"
