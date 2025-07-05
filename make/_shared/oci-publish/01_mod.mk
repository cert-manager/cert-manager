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

# Utility functions
fatal_if_undefined = $(if $(findstring undefined,$(origin $1)),$(error $1 is not set))
oci_digest = $(shell head -1 $(oci_digest_path_$1) 2> /dev/null)
sanitize_target = $(subst :,-,$1)
registry_for = $(firstword $(subst /, ,$1))

# Utility variables
current_makefile_directory := $(dir $(lastword $(MAKEFILE_LIST)))
image_exists_script := $(current_makefile_directory)/image-exists.sh

# Validate globals that are required
$(call fatal_if_undefined,bin_dir)
$(call fatal_if_undefined,push_names)

# Set default config values
RELEASE_DRYRUN ?= false
CRANE_FLAGS ?= # empty by default
COSIGN_FLAGS ?= # empty by default
OCI_SIGN_ON_PUSH ?= true

# Default variables per push_names entry
#
# $1 - build_name
define default_per_build_variables
release_dryrun_$1 ?= $(RELEASE_DRYRUN)
crane_flags_$1 ?= $(CRANE_FLAGS)
cosign_flags_$1 ?= $(COSIGN_FLAGS)
oci_sign_on_push_$1 ?= $(OCI_SIGN_ON_PUSH)
endef

$(foreach build_name,$(push_names),$(eval $(call default_per_build_variables,$(build_name))))

# Validate variables per push_names entry
#
# $1 - build_name
define check_per_build_variables
$(call fatal_if_undefined,oci_digest_path_$1)
$(call fatal_if_undefined,oci_layout_path_$1)
$(call fatal_if_undefined,oci_$1_image_name)
$(call fatal_if_undefined,oci_$1_image_tag)
endef

$(foreach build_name,$(push_names),$(eval $(call check_per_build_variables,$(build_name))))

# Create variables holding targets
#
# We create the following targets for each $(push_names)
# - oci-build-$(build_name) = build the oci directory
# - oci-load-$(build_name) = load the image into docker using the oci_$(build_name)_image_name_development variable
# - docker-tarball-$(build_name) = build a "docker load" compatible tarball of the image
# - ko-config-$(build_name) = generate "ko" config for a given build
oci_push_targets := $(push_names:%=oci-push-%)
oci_sign_targets := $(push_names:%=oci-sign-%)
oci_maybe_push_targets := $(push_names:%=oci-maybe-push-%)

# Define push target 
# $1 - build_name
# $2 - image_name
define oci_push_target
.PHONY: $(call sanitize_target,oci-push-$2)
$(call sanitize_target,oci-push-$2): oci-build-$1 | $(NEEDS_CRANE)
	$$(CRANE) $(crane_flags_$1) push "$(oci_layout_path_$1)" "$2:$(call oci_image_tag_for,$1)"
	$(if $(filter true,$(oci_sign_on_push_$1)),$(MAKE) $(call sanitize_target,oci-sign-$2))

.PHONY: $(call sanitize_target,oci-maybe-push-$2)
$(call sanitize_target,oci-maybe-push-$2): oci-build-$1 | $(NEEDS_CRANE)
	CRANE="$$(CRANE) $(crane_flags_$1)" \
	source $(image_exists_script) $2:$(call oci_image_tag_for,$1); \
		$$(CRANE) $(crane_flags_$1) push "$(oci_layout_path_$1)" "$2:$(call oci_image_tag_for,$1)"; \
		$(if $(filter true,$(oci_sign_on_push_$1)),$(MAKE) $(call sanitize_target,oci-sign-$2))

oci-push-$1: $(call sanitize_target,oci-push-$2)
oci-maybe-push-$1: $(call sanitize_target,oci-maybe-push-$2)
endef

oci_push_target_per_image = $(foreach image_name,$2,$(eval $(call oci_push_target,$1,$(image_name))))
$(foreach build_name,$(push_names),$(eval $(call oci_push_target_per_image,$(build_name),$(call oci_image_names_for,$(build_name)))))

.PHONY: $(oci_push_targets)
## Build and push OCI image.
## If the tag already exists, this target will overwrite it.
## If an identical image was already built before, we will add a new tag to it, but we will not sign it again.
## Expected pushed images:
## - :v1.2.3, @sha256:0000001
## - :v1.2.3.sig, :sha256-0000001.sig
## @category [shared] Publish
$(oci_push_targets):

.PHONY: $(oci_maybe_push_targets)
## Push image if tag does not already exist in registry.
## @category [shared] Publish
$(oci_maybe_push_targets):

# Define sign target 
# $1 - build_name
# $2 - image_name
define oci_sign_target
.PHONY: $(call sanitize_target,oci-sign-$2)
$(call sanitize_target,oci-sign-$2): $(oci_digest_path_$1) | $(NEEDS_CRANE) $(NEEDS_COSIGN)
	$$(CRANE) $(crane_flags_$1) manifest $2:$$(subst :,-,$$(call oci_digest,$1)).sig > /dev/null 2>&1 || \
		$$(COSIGN) sign --yes=true $(cosign_flags_$1) "$2@$$(call oci_digest,$1)"

oci-sign-$1: $(call sanitize_target,oci-sign-$2)
endef

oci_sign_target_per_image = $(foreach image_name,$2,$(eval $(call oci_sign_target,$1,$(image_name))))
$(foreach build_name,$(push_names),$(eval $(call oci_sign_target_per_image,$(build_name),$(call oci_image_names_for,$(build_name)))))

.PHONY: $(oci_sign_targets)
## Sign an OCI image.
## If a signature already exists, this will not overwrite it.
## @category [shared] Publish
$(oci_sign_targets):