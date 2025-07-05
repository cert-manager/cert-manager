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

# Push names is equivalent to build_names, additional names can be added for 
# pushing images that are not build with the oci-build module
push_names ?=
push_names += $(build_names)

# Sometimes we need to push to one registry, but pull from another. This allows
# that.
#
# The lines should be in the format a=b
#
# The value on the left is the domain you include in your oci_<name>_image_name
# variable, the one on the right is the domain that is actually pushed to.
#
# For example, if we set up a vanity domain for the current quay:
# 
#   oci_controller_image_name = registry.cert-manager.io/cert-manager-controller` 
#   image_registry_rewrite += registry.cert-manager.io=quay.io/jetstack
#
# This would push to quay.io/jetstack/cert-manager-controller.
#
# The general idea is oci_<name>_image_name contains the final image name, after replication, after vanity domains etc.

image_registry_rewrite ?= 

# Utilities for extracting the key and value from a foo=bar style line
kv_key = $(word 1,$(subst =, ,$1))
kv_value = $(word 2,$(subst =, ,$1))

# Apply the image_registry_rewrite rules, if no rules match an image then the 
# image name is not changed. Any rules that match will be applied.
#
# For example, if there was a rule vanity-domain.com=real-registry.com/foo
# then any references to vanity-domain.com/image would be rewritten to 
# real-registry.com/foo/image
image_registry_rewrite_rules_for_image = $(strip $(sort $(foreach rule,$(image_registry_rewrite),$(if $(findstring $(call kv_key,$(rule)),$1),$(rule)))))
apply_image_registry_rewrite_rules_to_image = $(if $(call image_registry_rewrite_rules_for_image,$1),\
	$(foreach rule,$(call image_registry_rewrite_rules_for_image,$1),$(subst $(call kv_key,$(rule)),$(call kv_value,$(rule)),$1)),\
	$1)
apply_image_registry_rewrite_rules = $(foreach image_name,$1,$(call apply_image_registry_rewrite_rules_to_image,$(image_name)))

# This is a helper function to return the image names for a given build_name.
# It will apply all rewrite rules to the image names
oci_image_names_for = $(call apply_image_registry_rewrite_rules,$(oci_$1_image_name))
oci_image_tag_for = $(oci_$1_image_tag)