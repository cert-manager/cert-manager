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

oci_platforms ?= linux/amd64,linux/arm/v7,linux/arm64,linux/ppc64le

# Use distroless as minimal base image to package the manager binary
# To get latest SHA run "crane digest quay.io/jetstack/base-static:latest"
base_image_static := quay.io/jetstack/base-static@sha256:01d887b98d90226dbaeb32b9cab0dbede410a652fa16829c6fd2f94df55d7757

# Use custom apko-built image as minimal base image to package the manager binary
# To get latest SHA run "crane digest quay.io/jetstack/base-static-csi:latest"
base_image_csi-static := quay.io/jetstack/base-static-csi@sha256:35531ca8c25f441a15b9ae211aaa2a9978334c45dd2a9c130525aa73c8bdf5af

# Utility functions
fatal_if_undefined = $(if $(findstring undefined,$(origin $1)),$(error $1 is not set))
fatal_if_deprecated_defined = $(if $(findstring undefined,$(origin $1)),,$(error $1 is deprecated, use $2 instead))

# Validate globals that are required
$(call fatal_if_undefined,bin_dir)
$(call fatal_if_undefined,build_names)

# Set default config values
CGO_ENABLED ?= 0
GOEXPERIMENT ?=  # empty by default

# Default variables per build_names entry
#
# $1 - build_name
define default_per_build_variables
go_$1_cgo_enabled ?= $(CGO_ENABLED)
go_$1_goexperiment ?= $(GOEXPERIMENT)
go_$1_flags ?= -tags=
oci_$1_additional_layers ?= 
oci_$1_linux_capabilities ?= 
oci_$1_build_args ?= 
endef

$(foreach build_name,$(build_names),$(eval $(call default_per_build_variables,$(build_name))))

# Validate variables per build_names entry
#
# $1 - build_name
define check_per_build_variables
# Validate deprecated variables
$(call fatal_if_deprecated_defined,cgo_enabled_$1,go_$1_cgo_enabled)
$(call fatal_if_deprecated_defined,goexperiment_$1,go_$1_goexperiment)
$(call fatal_if_deprecated_defined,oci_additional_layers_$1,oci_$1_additional_layers)

# Validate required config exists
$(call fatal_if_undefined,go_$1_ldflags)
$(call fatal_if_undefined,go_$1_main_dir)
$(call fatal_if_undefined,go_$1_mod_dir)
$(call fatal_if_undefined,oci_$1_base_image_flavor)
$(call fatal_if_undefined,oci_$1_image_name_development)

# Validate we have valid base image config
ifeq ($(oci_$1_base_image_flavor),static)
    oci_$1_base_image := $(base_image_static)
else ifeq ($(oci_$1_base_image_flavor),csi-static)
    oci_$1_base_image := $(base_image_csi-static)
else ifeq ($(oci_$1_base_image_flavor),custom)
    $$(call fatal_if_undefined,oci_$1_base_image)
else
    $$(error oci_$1_base_image_flavor has unknown value "$(oci_$1_base_image_flavor)")
endif

# Validate the config required to build the golang based images
ifneq ($(go_$1_main_dir:.%=.),.)
$$(error go_$1_main_dir "$(go_$1_main_dir)" should be a directory path that DOES start with ".")
endif
ifeq ($(go_$1_main_dir:%/=/),/)
$$(error go_$1_main_dir "$(go_$1_main_dir)" should be a directory path that DOES NOT end with "/")
endif
ifeq ($(go_$1_main_dir:%.go=.go),.go)
$$(error go_$1_main_dir "$(go_$1_main_dir)" should be a directory path that DOES NOT end with ".go")
endif
ifneq ($(go_$1_mod_dir:.%=.),.)
$$(error go_$1_mod_dir "$(go_$1_mod_dir)" should be a directory path that DOES start with ".")
endif
ifeq ($(go_$1_mod_dir:%/=/),/)
$$(error go_$1_mod_dir "$(go_$1_mod_dir)" should be a directory path that DOES NOT end with "/")
endif
ifeq ($(go_$1_mod_dir:%.go=.go),.go)
$$(error go_$1_mod_dir "$(go_$1_mod_dir)" should be a directory path that DOES NOT end with ".go")
endif
ifeq ($(wildcard $(go_$1_mod_dir)/go.mod),)
$$(error go_$1_mod_dir "$(go_$1_mod_dir)" does not contain a go.mod file)
endif
ifeq ($(wildcard $(go_$1_mod_dir)/$(go_$1_main_dir)/main.go),)
$$(error go_$1_main_dir "$(go_$1_mod_dir)" does not contain a main.go file)
endif

# Validate the config required to build OCI images
ifneq ($(words $(oci_$1_image_name_development)),1)
$$(error oci_$1_image_name_development "$(oci_$1_image_name_development)" should be a single image name)
endif

endef

$(foreach build_name,$(build_names),$(eval $(call check_per_build_variables,$(build_name))))

# Create variables holding targets
#
# We create the following targets for each $(build_names)
# - oci-build-$(build_name) = build the oci directory
# - oci-load-$(build_name) = load the image into docker using the oci_$(build_name)_image_name_development variable
# - docker-tarball-$(build_name) = build a "docker load" compatible tarball of the image
# - ko-config-$(build_name) = generate "ko" config for a given build
oci_build_targets := $(build_names:%=oci-build-%)
oci_load_targets := $(build_names:%=oci-load-%)
docker_tarball_targets := $(build_names:%=docker-tarball-%)
ko_config_targets := $(build_names:%=ko-config-%)

# Derive config based on user config
# 
# - oci_layout_path_$(build_name) = path that the OCI image will be saved in OCI layout directory format
# - oci_digest_path_$(build_name) = path to the file that will contain the digests
# - ko_config_path_$(build_name) = path to the ko config file
# - docker_tarball_path_$(build_name) = path that the docker tarball that the docker-tarball-$(build_name) will produce
$(foreach build_name,$(build_names),$(eval oci_layout_path_$(build_name) := $(bin_dir)/scratch/image/oci-layout-$(build_name)))
$(foreach build_name,$(build_names),$(eval oci_digest_path_$(build_name) := $(CURDIR)/$(oci_layout_path_$(build_name)).digests))
$(foreach build_name,$(build_names),$(eval ko_config_path_$(build_name) := $(CURDIR)/$(oci_layout_path_$(build_name)).ko_config.yaml))
$(foreach build_name,$(build_names),$(eval docker_tarball_path_$(build_name) := $(CURDIR)/$(oci_layout_path_$(build_name)).docker.tar))
