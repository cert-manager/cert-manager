# Copyright 2024 The cert-manager Authors.
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

###################### Generate LICENSES files ######################

# Create a go.work file so that go-licenses can discover the LICENSE file of the
# other modules in the repo.
#
# Without this, go-licenses *guesses* the wrong LICENSE for local dependencies and
# links to the wrong versions of LICENSES for transitive dependencies.
licenses_go_work := $(bin_dir)/scratch/LICENSES.go.work
$(licenses_go_work): $(bin_dir)/scratch
	GOWORK=$(abspath $@) \
		$(MAKE) go-workspace

## Generate licenses for the golang dependencies
## @category [shared] Generate/Verify
generate-go-licenses: #
shared_generate_targets += generate-go-licenses

define licenses_target
$1/LICENSES: $1/go.mod $(licenses_go_work) | $(NEEDS_GO-LICENSES)
	cd $$(dir $$@) && \
		GOWORK=$(abspath $(licenses_go_work)) \
		GOOS=linux GOARCH=amd64 \
		$(GO-LICENSES) report --ignore "$$(license_ignore)" ./... > LICENSES

generate-go-licenses: $1/LICENSES
# The /LICENSE targets make sure these files exist.
# Otherwise, make will error.
generate-go-licenses: $1/LICENSE
endef

# Calculate all the go.mod directories, build targets may share go.mod dirs so
# we use $(sort) to de-duplicate.
go_mod_dirs := $(foreach build_name,$(build_names),$(go_$(build_name)_mod_dir))
ifneq ("$(wildcard go.mod)","")
    go_mod_dirs += .
endif
go_mod_dirs := $(sort $(go_mod_dirs))
$(foreach go_mod_dir,$(go_mod_dirs),$(eval $(call licenses_target,$(go_mod_dir))))

###################### Include LICENSES in OCI image ######################

define license_layer
license_layer_path_$1 := $$(abspath $(bin_dir)/scratch/licenses-$1)

# Target to generate image layer containing license information
.PHONY: oci-license-layer-$1
oci-license-layer-$1: | $(bin_dir)/scratch $(NEEDS_GO-LICENSES)
	rm -rf $$(license_layer_path_$1)
	mkdir -p $$(license_layer_path_$1)/licenses
	cp $$(go_$1_mod_dir)/LICENSE $$(license_layer_path_$1)/licenses/LICENSE
	cp $$(go_$1_mod_dir)/LICENSES $$(license_layer_path_$1)/licenses/LICENSES

oci-build-$1: oci-license-layer-$1
oci_$1_additional_layers += $$(license_layer_path_$1)
endef

$(foreach build_name,$(build_names),$(eval $(call license_layer,$(build_name))))
