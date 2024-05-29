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

CRDS_SOURCES=$(wildcard deploy/crds/*.yaml)
CRDS_TEMPLATED=$(CRDS_SOURCES:deploy/crds/%.yaml=$(bin_dir)/yaml/templated-crds/%.templated.yaml)

HELM_TEMPLATE_SOURCES=$(wildcard deploy/charts/cert-manager/templates/*.yaml)
HELM_TEMPLATE_TARGETS=$(patsubst deploy/charts/cert-manager/templates/%,$(bin_dir)/helm/cert-manager/templates/%,$(HELM_TEMPLATE_SOURCES))

####################
# Friendly Targets #
####################

# These targets provide friendly names for the various manifests / charts we build

.PHONY: helm-chart
helm-chart: $(bin_dir)/cert-manager-$(VERSION).tgz

$(bin_dir)/cert-manager.tgz: $(bin_dir)/cert-manager-$(VERSION).tgz
	@ln -s -f $(notdir $<) $@

.PHONY: helm-chart-signature
helm-chart-signature: $(bin_dir)/cert-manager-$(VERSION).tgz.prov

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

.PHONY: release-manifests-signed
## Build YAML manifests and helm charts including the helm chart signature
##
## Since this command signs artifacts, this requires CMREL_KEY to be configured.
## Prefer `make release-manifests` locally.
##
## @category Release
release-manifests-signed: $(bin_dir)/release/cert-manager-manifests.tar.gz $(bin_dir)/metadata/cert-manager-manifests.tar.gz.metadata.json

$(bin_dir)/release/cert-manager-manifests.tar.gz: $(bin_dir)/cert-manager-$(VERSION).tgz $(bin_dir)/yaml/cert-manager.crds.yaml $(bin_dir)/yaml/cert-manager.yaml $(bin_dir)/cert-manager-$(VERSION).tgz.prov | $(bin_dir)/scratch/manifests-signed $(bin_dir)/release
	mkdir -p $(bin_dir)/scratch/manifests-signed/deploy/chart/
	mkdir -p $(bin_dir)/scratch/manifests-signed/deploy/manifests/
	cp $(bin_dir)/cert-manager-$(VERSION).tgz $(bin_dir)/cert-manager-$(VERSION).tgz.prov $(bin_dir)/scratch/manifests-signed/deploy/chart/
	cp $(bin_dir)/yaml/cert-manager.crds.yaml $(bin_dir)/yaml/cert-manager.yaml $(bin_dir)/scratch/manifests-signed/deploy/manifests/
	# removes leading ./ from archived paths
	find $(bin_dir)/scratch/manifests-signed -maxdepth 1 -mindepth 1 | sed 's|.*/||' | tar czf $@ -C $(bin_dir)/scratch/manifests-signed -T -
	rm -rf $(bin_dir)/scratch/manifests-signed

$(bin_dir)/scratch/cert-manager-manifests-unsigned.tar.gz: $(bin_dir)/cert-manager-$(VERSION).tgz $(bin_dir)/yaml/cert-manager.crds.yaml $(bin_dir)/yaml/cert-manager.yaml | $(bin_dir)/scratch/manifests-unsigned
	mkdir -p $(bin_dir)/scratch/manifests-unsigned/deploy/chart/
	mkdir -p $(bin_dir)/scratch/manifests-unsigned/deploy/manifests/
	cp $(bin_dir)/cert-manager-$(VERSION).tgz $(bin_dir)/scratch/manifests-unsigned/deploy/chart/
	cp $(bin_dir)/yaml/cert-manager.crds.yaml $(bin_dir)/yaml/cert-manager.yaml $(bin_dir)/scratch/manifests-unsigned/deploy/manifests/
	# removes leading ./ from archived paths
	find $(bin_dir)/scratch/manifests-unsigned -maxdepth 1 -mindepth 1 | sed 's|.*/||' | tar czf $@ -C $(bin_dir)/scratch/manifests-unsigned -T -
	rm -rf $(bin_dir)/scratch/manifests-unsigned

# This metadata blob is constructed slightly differently and doesn't use hack/artifact-metadata.template.json directly;
# this is because the bazel staged releases didn't include an "os" or "architecture" field for this artifact
$(bin_dir)/metadata/cert-manager-manifests.tar.gz.metadata.json: $(bin_dir)/release/cert-manager-manifests.tar.gz hack/artifact-metadata.template.json | $(bin_dir)/metadata
	jq -n --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		'.name = $$name | .sha256 = $$sha256' > $@

################
# Helm Targets #
################

# These targets provide for building and signing the cert-manager helm chart.

$(bin_dir)/cert-manager-$(VERSION).tgz: $(bin_dir)/helm/cert-manager/README.md $(bin_dir)/helm/cert-manager/Chart.yaml $(bin_dir)/helm/cert-manager/values.yaml $(HELM_TEMPLATE_TARGETS) $(bin_dir)/helm/cert-manager/templates/NOTES.txt $(bin_dir)/helm/cert-manager/templates/_helpers.tpl $(bin_dir)/helm/cert-manager/templates/crds.yaml | $(NEEDS_HELM) $(bin_dir)/helm/cert-manager
	$(HELM) package --app-version=$(VERSION) --version=$(VERSION) --destination "$(dir $@)" ./$(bin_dir)/helm/cert-manager

$(bin_dir)/cert-manager-$(VERSION).tgz.prov: $(bin_dir)/cert-manager-$(VERSION).tgz | $(NEEDS_CMREL) $(bin_dir)/helm/cert-manager
ifeq ($(strip $(CMREL_KEY)),)
	$(error Trying to sign helm chart but CMREL_KEY is empty)
endif
	cd $(dir $<) && $(CMREL) sign helm --chart-path "$(notdir $<)" --key "$(CMREL_KEY)"

$(bin_dir)/helm/cert-manager/templates/%.yaml: deploy/charts/cert-manager/templates/%.yaml | $(bin_dir)/helm/cert-manager/templates
	cp -f $^ $@

$(bin_dir)/helm/cert-manager/templates/_helpers.tpl: deploy/charts/cert-manager/templates/_helpers.tpl | $(bin_dir)/helm/cert-manager/templates
	cp $< $@

$(bin_dir)/helm/cert-manager/templates/NOTES.txt: deploy/charts/cert-manager/templates/NOTES.txt | $(bin_dir)/helm/cert-manager/templates
	cp $< $@

$(bin_dir)/helm/cert-manager/templates/crds.yaml: $(CRDS_SOURCES) | $(bin_dir)/helm/cert-manager/templates
	./hack/concat-yaml.sh $^ > $@

$(bin_dir)/helm/cert-manager/values.yaml: deploy/charts/cert-manager/values.yaml | $(bin_dir)/helm/cert-manager
	cp $< $@

$(bin_dir)/helm/cert-manager/README.md: deploy/charts/cert-manager/README.template.md | $(bin_dir)/helm/cert-manager
	sed -e "s:{{RELEASE_VERSION}}:$(VERSION):g" < $< > $@

$(bin_dir)/helm/cert-manager/Chart.yaml: deploy/charts/cert-manager/Chart.template.yaml deploy/charts/cert-manager/signkey_annotation.txt | $(NEEDS_YQ) $(bin_dir)/helm/cert-manager
	@# this horrible mess is taken from the YQ manual's example of multiline string blocks from a file:
	@# https://mikefarah.gitbook.io/yq/operators/string-operators#string-blocks-bash-and-newlines
	@# we set a bash variable called SIGNKEY_ANNOTATION using read, and then use that bash variable in yq
	IFS= read -rd '' SIGNKEY_ANNOTATION < <(cat deploy/charts/cert-manager/signkey_annotation.txt) ; \
		SIGNKEY_ANNOTATION=$$SIGNKEY_ANNOTATION $(YQ) eval \
		'.annotations."artifacthub.io/signKey" = strenv(SIGNKEY_ANNOTATION) | .annotations."artifacthub.io/prerelease" = "$(IS_PRERELEASE)" | .version = "$(VERSION)" | .appVersion = "$(VERSION)"' \
		$< > $@

############################################################
# Targets for cert-manager.yaml and cert-manager.crds.yaml #
############################################################

# These targets depend on the cert-manager helm chart and the creation of the standalone CRDs.
# They use `helm template` to create a single static YAML manifest containing all resources
# with templating completed, and then concatenate with the cert-manager namespace and the CRDs.

# Renders all resources except the namespace and the CRDs
$(bin_dir)/scratch/yaml/cert-manager.noncrd.unlicensed.yaml: $(bin_dir)/cert-manager-$(VERSION).tgz | $(NEEDS_HELM) $(bin_dir)/scratch/yaml
	@# The sed command removes the first line but only if it matches "---", which helm adds
	$(HELM) template --api-versions="" --namespace=cert-manager --set="creator=static" --set="startupapicheck.enabled=false" cert-manager $< | \
		sed -e "1{/^---$$/d;}" > $@

$(bin_dir)/scratch/yaml/cert-manager.all.unlicensed.yaml: $(bin_dir)/cert-manager-$(VERSION).tgz | $(NEEDS_HELM) $(bin_dir)/scratch/yaml
	@# The sed command removes the first line but only if it matches "---", which helm adds
	$(HELM) template --api-versions="" --namespace=cert-manager --set="crds.enabled=true" --set="creator=static" --set="startupapicheck.enabled=false" cert-manager $< | \
		sed -e "1{/^---$$/d;}" > $@

$(bin_dir)/scratch/yaml/cert-manager.crds.unlicensed.yaml: $(bin_dir)/scratch/yaml/cert-manager.all.unlicensed.yaml | $(NEEDS_GO) $(bin_dir)/scratch/yaml
	$(GO) run hack/extractcrd/main.go $< > $@

$(bin_dir)/yaml/cert-manager.yaml: $(bin_dir)/scratch/license.yaml deploy/manifests/namespace.yaml $(bin_dir)/scratch/yaml/cert-manager.crds.unlicensed.yaml $(bin_dir)/scratch/yaml/cert-manager.noncrd.unlicensed.yaml | $(bin_dir)/yaml
	@# NB: filter-out removes the license (the first dependency, $<) from the YAML concatenation
	./hack/concat-yaml.sh $(filter-out $<, $^) | cat $< - > $@

$(bin_dir)/yaml/cert-manager.crds.yaml: $(bin_dir)/scratch/license.yaml $(bin_dir)/scratch/yaml/cert-manager.crds.unlicensed.yaml | $(bin_dir)/yaml
	cat $^ > $@

$(CRDS_TEMPLATED): $(bin_dir)/yaml/templated-crds/crd-%.templated.yaml: $(bin_dir)/scratch/license.yaml $(bin_dir)/scratch/yaml/cert-manager.crds.unlicensed.yaml | $(NEEDS_GO) $(bin_dir)/yaml/templated-crds
	cat $< > $@
	$(GO) run hack/extractcrd/main.go $(word 2,$^) $* >> $@

.PHONY: templated-crds
templated-crds: $(CRDS_TEMPLATED)

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

$(bin_dir)/yaml/templated-crds:
	@mkdir -p $@
