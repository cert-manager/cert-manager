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

####################
# Friendly Targets #
####################

# These targets provide friendly names for the various manifests / charts we build

.PHONY: static-manifests
static-manifests: $(bin_dir)/yaml/cert-manager.crds.yaml $(bin_dir)/yaml/cert-manager.yaml

###################
# Release Targets #
###################

.PHONY: release-manifests
## Build YAML manifests and helm charts (but not the helm chart signature)
##
## @category Release
release-manifests: $(bin_dir)/scratch/cert-manager-manifests-unsigned.tar.gz

$(bin_dir)/scratch/cert-manager-manifests-unsigned.tar.gz: $(helm_chart_archive) $(bin_dir)/yaml/cert-manager.crds.yaml $(bin_dir)/yaml/cert-manager.yaml | $(bin_dir)/scratch/manifests-unsigned
	mkdir -p $(bin_dir)/scratch/manifests-unsigned/deploy/chart/
	mkdir -p $(bin_dir)/scratch/manifests-unsigned/deploy/manifests/
	cp $(helm_chart_archive) $(bin_dir)/scratch/manifests-unsigned/deploy/chart/
	cp $(bin_dir)/yaml/cert-manager.crds.yaml $(bin_dir)/yaml/cert-manager.yaml $(bin_dir)/scratch/manifests-unsigned/deploy/manifests/
	# removes leading ./ from archived paths
	find $(bin_dir)/scratch/manifests-unsigned -maxdepth 1 -mindepth 1 | sed 's|.*/||' | tar czf $@ -C $(bin_dir)/scratch/manifests-unsigned -T -
	rm -rf $(bin_dir)/scratch/manifests-unsigned

############################################################
# Targets for cert-manager.yaml and cert-manager.crds.yaml #
############################################################

# These targets depend on the cert-manager helm chart and the creation of the standalone CRDs.
# They use `helm template` to create a single static YAML manifest containing all resources
# with templating completed, and then concatenate with the cert-manager namespace and the CRDs.

# Renders all resources except the namespace and the CRDs
$(bin_dir)/scratch/yaml/cert-manager.noncrd.unlicensed.yaml: $(helm_chart_archive) | $(NEEDS_HELM) $(bin_dir)/scratch/yaml
	@# The sed command removes the first line but only if it matches "---", which helm adds
	$(HELM) template --api-versions="" --namespace=cert-manager --set="creator=static" --set="startupapicheck.enabled=false" cert-manager $< | \
		sed -e "1{/^---$$/d;}" > $@

$(bin_dir)/scratch/yaml/cert-manager.all.unlicensed.yaml: $(helm_chart_archive) | $(NEEDS_HELM) $(bin_dir)/scratch/yaml
	@# The sed command removes the first line but only if it matches "---", which helm adds
	$(HELM) template --api-versions="" --namespace=cert-manager --set="crds.enabled=true" --set="creator=static" --set="startupapicheck.enabled=false" cert-manager $< | \
		sed -e "1{/^---$$/d;}" > $@

$(bin_dir)/scratch/yaml/cert-manager.crds.unlicensed.yaml: $(bin_dir)/scratch/yaml/cert-manager.all.unlicensed.yaml | $(NEEDS_GO) $(bin_dir)/scratch/yaml
	$(GO) run hack/extractcrd/main.go $< > $@

# Creates the boilerplate header for YAML files from the template in hack/
$(bin_dir)/scratch/license.yaml: hack/boilerplate-yaml.txt | $(bin_dir)/scratch
	sed -e "s/YEAR/$(LICENSE_YEAR)/g" < $< > $@

$(bin_dir)/yaml/cert-manager.yaml: $(bin_dir)/scratch/license.yaml deploy/manifests/namespace.yaml $(bin_dir)/scratch/yaml/cert-manager.crds.unlicensed.yaml $(bin_dir)/scratch/yaml/cert-manager.noncrd.unlicensed.yaml | $(bin_dir)/yaml
	@# NB: filter-out removes the license (the first dependency, $<) from the YAML concatenation
	./hack/concat-yaml.sh $(filter-out $<, $^) | cat $< - > $@

$(bin_dir)/yaml/cert-manager.crds.yaml: $(bin_dir)/scratch/license.yaml $(bin_dir)/scratch/yaml/cert-manager.crds.unlicensed.yaml | $(bin_dir)/yaml
	cat $^ > $@

###############
# Dir targets #
###############

# These targets are trivial, to ensure that dirs exist

$(bin_dir)/yaml:
	@mkdir -p $@

$(bin_dir)/helm/cert-manager:
	@mkdir -p $@

$(bin_dir)/helm/cert-manager/templates:
	@mkdir -p $@

$(bin_dir)/scratch/yaml:
	@mkdir -p $@

$(bin_dir)/scratch/manifests-unsigned:
	@mkdir -p $@

$(bin_dir)/scratch/manifests-signed:
	@mkdir -p $@
