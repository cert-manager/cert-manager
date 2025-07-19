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

$(bin_dir)/scratch/image:
	@mkdir -p $@

define ko_config_target
.PHONY: $(ko_config_path_$1:$(CURDIR)/%=%)
$(ko_config_path_$1:$(CURDIR)/%=%): | $(NEEDS_YQ) $(bin_dir)/scratch/image
	echo '{}' | \
		$(YQ) '.defaultBaseImage = "$(oci_$1_base_image)"' | \
		$(YQ) '.builds[0].id = "$1"' | \
		$(YQ) '.builds[0].dir = "$(go_$1_mod_dir)"' | \
		$(YQ) '.builds[0].main = "$(go_$1_main_dir)"' | \
		$(YQ) '.builds[0].env[0] = "CGO_ENABLED=$(go_$1_cgo_enabled)"' | \
		$(YQ) '.builds[0].env[1] = "GOEXPERIMENT=$(go_$1_goexperiment)"' | \
		$(YQ) '.builds[0].ldflags[0] = "-s"' | \
		$(YQ) '.builds[0].ldflags[1] = "-w"' | \
		$(YQ) '.builds[0].ldflags[2] = "{{.Env.LDFLAGS}}"' | \
		$(YQ) '.builds[0].flags[0] = "$(go_$1_flags)"' | \
		$(YQ) '.builds[0].linux_capabilities = "$(oci_$1_linux_capabilities)"' \
		> $(CURDIR)/$(oci_layout_path_$1).ko_config.yaml

ko-config-$1: $(ko_config_path_$1:$(CURDIR)/%=%)
endef

.PHONY: $(ko_config_targets)
$(foreach build_name,$(build_names),$(eval $(call ko_config_target,$(build_name))))

.PHONY: $(oci_build_targets)
## Build the OCI image.
## @category [shared] Build
$(oci_build_targets): oci-build-%: ko-config-% | $(NEEDS_KO) $(NEEDS_GO) $(NEEDS_YQ) $(NEEDS_IMAGE-TOOL) $(bin_dir)/scratch/image
	rm -rf $(CURDIR)/$(oci_layout_path_$*)
	GOWORK=off \
	KO_DOCKER_REPO=$(oci_$*_image_name_development) \
	KOCACHE=$(CURDIR)/$(bin_dir)/scratch/image/ko_cache \
	KO_CONFIG_PATH=$(ko_config_path_$*) \
	SOURCE_DATE_EPOCH=$(GITEPOCH) \
	KO_GO_PATH=$(GO) \
	LDFLAGS="$(go_$*_ldflags)" \
	$(KO) build $(go_$*_mod_dir)/$(go_$*_main_dir) \
		--platform=$(oci_platforms) \
		$(oci_$*_build_args) \
		--oci-layout-path=$(oci_layout_path_$*) \
		--sbom-dir=$(CURDIR)/$(oci_layout_path_$*).sbom \
		--sbom=spdx \
		--push=false \
		--bare

	$(IMAGE-TOOL) append-layers \
		$(CURDIR)/$(oci_layout_path_$*) \
		$(oci_$*_additional_layers)

	$(IMAGE-TOOL) list-digests \
		$(CURDIR)/$(oci_layout_path_$*) \
		> $(oci_digest_path_$*)

# Only include the oci-load target if kind is provided by the kind makefile-module
ifdef kind_cluster_name
.PHONY: $(oci_load_targets)
## Build OCI image for the local architecture and load
## it into the $(kind_cluster_name) kind cluster.
## @category [shared] Build
$(oci_load_targets): oci-load-%: docker-tarball-% | kind-cluster $(NEEDS_KIND)
	$(KIND) load image-archive --name $(kind_cluster_name) $(docker_tarball_path_$*)
endif

## Build Docker tarball image for the local architecture
## @category [shared] Build
.PHONY: $(docker_tarball_targets)
$(docker_tarball_targets): oci_platforms := "linux/$(HOST_ARCH)"
$(docker_tarball_targets): docker-tarball-%: oci-build-% | $(NEEDS_GO) $(NEEDS_IMAGE-TOOL)
	$(IMAGE-TOOL) convert-to-docker-tar $(CURDIR)/$(oci_layout_path_$*) $(docker_tarball_path_$*) $(oci_$*_image_name_development):$(oci_$*_image_tag)
