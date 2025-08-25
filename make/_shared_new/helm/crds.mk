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

################
# Check Inputs #
################

ifndef helm_chart_source_dir
$(error helm_chart_source_dir is not set)
endif

ifndef helm_labels_template_name
$(error helm_labels_template_name is not set)
endif

################
# Add targets #
################

crd_template_header := $(dir $(lastword $(MAKEFILE_LIST)))/crd.template.header.yaml
crd_template_footer := $(dir $(lastword $(MAKEFILE_LIST)))/crd.template.footer.yaml

# see https://stackoverflow.com/a/53408233
sed_inplace := sed -i''
ifeq ($(HOST_OS),darwin)
	sed_inplace := sed -i ''
endif

crds_dir ?= deploy/crds
crds_dir_readme := $(dir $(lastword $(MAKEFILE_LIST)))/crds_dir.README.md
crds_expression ?= .Values.crds.enabled
crds_template_include_pattern := *.yaml
# Space-separated list of basenames to exclude (e.g. foo.yaml *_test.yaml)
crds_template_exclude_pattern ?=

define filter-out-basenames
  $(if $(strip $(2)), \
    $(foreach f,$(1),$(if $(filter $(2),$(notdir $(f))),,$(f))), \
    $(1))
endef

.PHONY: generate-crds
## Generate CRD manifests.
## @category [shared] Generate/ Verify
generate-crds: | $(NEEDS_CONTROLLER-GEN) $(NEEDS_YQ)
	$(eval crds_gen_temp := $(bin_dir)/scratch/crds)
	$(eval directories := $(shell ls -d */ | grep -v -e 'make' $(shell git check-ignore -- * | sed 's/^/-e /')))

	rm -rf $(crds_gen_temp)
	mkdir -p $(crds_gen_temp)

	$(CONTROLLER-GEN) crd \
		$(directories:%=paths=./%...) \
		output:crd:artifacts:config=$(crds_gen_temp)

	@echo "Updating CRDs with helm templating, writing to $(helm_chart_source_dir)/templates"

	$(eval crds_gen_temp_all_files := $(wildcard $(crds_gen_temp)/$(crds_template_include_pattern)))
	$(eval crds_gen_temp_files := $(if $(crds_template_exclude_pattern), \
		$(call filter-out-basenames,$(crds_gen_temp_all_files),$(crds_template_exclude_pattern)), \
		$(crds_gen_temp_all_files)))

	@for f in $(crds_gen_temp_files); do \
		crd_name=$$($(YQ) eval '.metadata.name' $$f); \
		crd_template_file="$(helm_chart_source_dir)/templates/crd-$$(basename $$f)"; \
		cat $(crd_template_header) > $$crd_template_file; \
		$(sed_inplace) "s/REPLACE_CRD_EXPRESSION/$(crds_expression)/g" $$crd_template_file; \
		$(sed_inplace) "s/REPLACE_CRD_NAME/$$crd_name/g" $$crd_template_file; \
		$(sed_inplace) "s/REPLACE_LABELS_TEMPLATE/$(helm_labels_template_name)/g" $$crd_template_file; \
		$(YQ) -I2 '{"spec": .spec}' $$f >> $$crd_template_file; \
		cat $(crd_template_footer) >> $$crd_template_file; \
	done

	@if [ -n "$$(ls $(crds_gen_temp) 2>/dev/null)" ]; then \
		cp $(crds_gen_temp)/* $(crds_dir)/ ; \
		cp $(crds_dir_readme) $(crds_dir)/README.md ; \
	fi

shared_generate_targets += generate-crds
