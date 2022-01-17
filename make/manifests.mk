HELM_CMD=./bin/tools/helm

ALLCRDS=deploy/crds/crd-certificaterequests.yaml deploy/crds/crd-certificates.yaml deploy/crds/crd-challenges.yaml deploy/crds/crd-clusterissuers.yaml deploy/crds/crd-issuers.yaml deploy/crds/crd-orders.yaml

HELM_TEMPLATE_SOURCES=$(wildcard deploy/charts/cert-manager/templates/*.yaml)
HELM_TEMPLATE_TARGETS=$(patsubst deploy/charts/cert-manager/templates/%,bin/helm/cert-manager/templates/%,$(HELM_TEMPLATE_SOURCES))

####################
# Friendly Targets #
####################

# These targets provide friendly names for the various manifests / charts we build

.PHONY: helm-chart
helm-chart: bin/cert-manager-$(RELEASE_VERSION).tgz

.PHONY: helm-chart-signature
helm-chart-signature: bin/cert-manager-$(RELEASE_VERSION).tgz.prov

.PHONY: static-manifests
static-manifests: bin/yaml/cert-manager.crds.yaml bin/yaml/cert-manager.yaml

###################
# Release Targets #
###################

.PHONY: release-manifests
release-manifests: bin/release/cert-manager-manifests.tar.gz bin/metadata/cert-manager-manifests.tar.gz.metadata.json

bin/release/cert-manager-manifests.tar.gz: bin/cert-manager-$(RELEASE_VERSION).tgz bin/yaml/cert-manager.crds.yaml bin/yaml/cert-manager.yaml bin/cert-manager-$(RELEASE_VERSION).tgz.prov | bin/scratch/manifests bin/release
	mkdir -p bin/scratch/manifests/deploy/chart/
	mkdir -p bin/scratch/manifests/deploy/manifests/
	cp bin/cert-manager-$(RELEASE_VERSION).tgz bin/cert-manager-$(RELEASE_VERSION).tgz.prov bin/scratch/manifests/deploy/chart/
	cp bin/yaml/cert-manager.crds.yaml bin/yaml/cert-manager.yaml bin/scratch/manifests/deploy/manifests/
	tar czf $@ -C bin/scratch/manifests .
	rm -rf bin/scratch/manifests

# This metadata blob is constructed slightly differently and doesn't use hack/artifact-metadata.template.json directly;
# this is because the bazel staged releases didn't include an "os" or "architecture" field for this artifact
bin/metadata/cert-manager-manifests.tar.gz.metadata.json: bin/release/cert-manager-manifests.tar.gz hack/artifact-metadata.template.json | bin/metadata
	jq -n --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		'.name = $$name | .sha256 = $$sha256' > $@

################
# Helm Targets #
################

# These targets provide for building and signing the cert-manager helm chart.

bin/cert-manager-$(RELEASE_VERSION).tgz: bin/helm/cert-manager/README.md bin/helm/cert-manager/Chart.yaml bin/helm/cert-manager/values.yaml $(HELM_TEMPLATE_TARGETS) bin/helm/cert-manager/templates/NOTES.txt bin/helm/cert-manager/templates/_helpers.tpl bin/helm/cert-manager/templates/crds.yaml | bin/helm/cert-manager bin/tools/helm
	$(HELM_CMD) package --app-version=$(RELEASE_VERSION) --version=$(RELEASE_VERSION) --destination "$(dir $@)" ./bin/helm/cert-manager

bin/cert-manager-$(RELEASE_VERSION).tgz.prov: bin/cert-manager-$(RELEASE_VERSION).tgz | bin/helm/cert-manager bin/tools/cmrel
ifeq ($(strip $(CMREL_KEY)),)
	$(error Trying to sign helm chart but CMREL_KEY is empty)
endif
	cd $(dir $<) && $(CMREL) sign helm --chart-path "$(notdir $<)" --key "$(CMREL_KEY)"

$(HELM_TEMPLATE_TARGETS): $(HELM_TEMPLATE_SOURCES) | bin/helm/cert-manager/templates
	cp -f $^ $(dir $@)

bin/helm/cert-manager/templates/_helpers.tpl: deploy/charts/cert-manager/templates/_helpers.tpl | bin/helm/cert-manager/templates
	cp $< $@

bin/helm/cert-manager/templates/NOTES.txt: deploy/charts/cert-manager/templates/NOTES.txt | bin/helm/cert-manager/templates
	cp $< $@

bin/helm/cert-manager/templates/crds.yaml: bin/scratch/yaml/cert-manager-crd-templates.yaml
	echo '{{- if .Values.installCRDs }}' > $@
	cat $< >> $@
	echo '{{- end }}' >> $@

bin/helm/cert-manager/values.yaml: deploy/charts/cert-manager/values.yaml | bin/helm/cert-manager
	cp $< $@

bin/helm/cert-manager/README.md: deploy/charts/cert-manager/README.template.md | bin/helm/cert-manager
	sed -e "s:{{RELEASE_VERSION}}:$(RELEASE_VERSION):g" < $< > $@

bin/helm/cert-manager/Chart.yaml: deploy/charts/cert-manager/Chart.template.yaml deploy/charts/cert-manager/signkey_annotation.txt | bin/helm/cert-manager bin/tools/yq
	@# this horrible mess is taken from the YQ manual's example of multiline string blocks from a file:
	@# https://mikefarah.gitbook.io/yq/operators/string-operators#string-blocks-bash-and-newlines
	@# we set a bash variable called SIGNKEY_ANNOTATION using read, and then use that bash variable in yq
	IFS= read -rd '' SIGNKEY_ANNOTATION < <(cat deploy/charts/cert-manager/signkey_annotation.txt) ; \
		SIGNKEY_ANNOTATION=$$SIGNKEY_ANNOTATION $(YQ) eval \
		'.annotations."artifacthub.io/signKey" = strenv(SIGNKEY_ANNOTATION) | .annotations."artifacthub.io/prerelease" = "$(IS_PRERELEASE)" | .version = "$(RELEASE_VERSION)" | .appVersion = "$(RELEASE_VERSION)"' \
		$< > $@

#################################
# Targets for cert-manager.yaml #
#################################

# These targets depend on the cert-manager helm chart and the creation of the standalone CRDs.
# They use `helm template` to create a single static YAML manifest containing all resources
# with templating completed, and then concatenate with the cert-manager namespace and the CRDs.

bin/yaml/cert-manager.yaml: bin/scratch/license.yaml deploy/manifests/namespace.yaml bin/scratch/yaml/cert-manager.crds.unlicensed.yaml bin/scratch/yaml/cert-manager-static-resources.yaml | bin/yaml
	@# NB: filter-out removes the license (the first dependency, $<) from the YAML concatenation
	./hack/concat-yaml.sh $(filter-out $<, $^) | cat $< - > $@

# Renders all resources except the namespace and the CRDs
bin/scratch/yaml/cert-manager-static-resources.yaml: bin/cert-manager-$(RELEASE_VERSION).tgz | bin/scratch/yaml bin/tools/helm
	# The sed command removes the first line but only if it matches "---", which helm adds
	$(HELM_CMD) template --api-versions="" --namespace=cert-manager --set="creator=static" --set="startupapicheck.enabled=false" cert-manager $< | \
		sed -e "1{/^---$$/d;}" > $@

######################################
# Targets for cert-manager.crds.yaml #
######################################

# These targets generate a dummy helm chart containing _only_ our CRDs, and then uses `helm template`
# to create a single YAML file containing all CRDS with the templating completed

# CRDs with a license
bin/yaml/cert-manager.crds.yaml: bin/scratch/license.yaml bin/scratch/yaml/cert-manager.crds.unlicensed.yaml | bin/yaml
	cat $^ > $@

bin/scratch/yaml/cert-manager.crds.unlicensed.yaml: bin/scratch/cert-manager-crds/cert-manager-$(RELEASE_VERSION).tgz | bin/scratch/yaml bin/tools/helm
	# The sed command removes the first line but only if it matches "---", which helm adds
	$(HELM_CMD) template --api-versions="" --namespace=cert-manager --set="creator=static" --set="startupapicheck.enabled=false" cert-manager $< | \
		sed -e "1{/^---$$/d;}" > $@

bin/scratch/cert-manager-crds/cert-manager-$(RELEASE_VERSION).tgz: bin/helm/cert-manager-crds/templates/_helpers.tpl bin/helm/cert-manager-crds/templates/crd-templates.yaml bin/helm/cert-manager-crds/README.md bin/helm/cert-manager-crds/Chart.yaml bin/helm/cert-manager-crds/values.yaml  | bin/scratch bin/tools/helm
	$(HELM_CMD) package --app-version=$(RELEASE_VERSION) --version=$(RELEASE_VERSION) --destination "$(dir $@)" ./bin/helm/cert-manager-crds

# create a temporary chart containing the cert-manager CRDs in order to use helm's
# templating engine to create usable CRDs for static installation
bin/helm/cert-manager-crds/Chart.yaml: deploy/charts/cert-manager/Chart.template.yaml | bin/helm/cert-manager-crds
	sed -e "s:{{IS_PRERELEASE}}:$(IS_PRERELEASE):g" \
		-e "s:{{RELEASE_VERSION}}:$(RELEASE_VERSION):g" < $< > $@

bin/helm/cert-manager-crds/README.md: | bin/helm/cert-manager-crds
	@echo "This chart is a cert-manager build artifact, do not use" > $@

bin/helm/cert-manager-crds/values.yaml: deploy/charts/cert-manager/values.yaml | bin/helm/cert-manager
	cp $< $@

bin/helm/cert-manager-crds/templates/_helpers.tpl: deploy/charts/cert-manager/templates/_helpers.tpl | bin/helm/cert-manager-crds/templates
	cp $< $@

bin/helm/cert-manager-crds/templates/crd-templates.yaml: bin/scratch/yaml/cert-manager-crd-templates.yaml | bin/helm/cert-manager-crds/templates
	cp $< $@

# Create a single file containing all CRDs before they've been templated.
bin/scratch/yaml/cert-manager-crd-templates.yaml: $(ALLCRDS) | bin/scratch/yaml
	./hack/concat-yaml.sh $^ > $@

.PHONY: templated-crds
templated-crds: bin/yaml/templated-crds/crd-challenges.templated.yaml bin/yaml/templated-crds/crd-orders.templated.yaml bin/yaml/templated-crds/crd-certificaterequests.templated.yaml bin/yaml/templated-crds/crd-clusterissuers.templated.yaml bin/yaml/templated-crds/crd-issuers.templated.yaml bin/yaml/templated-crds/crd-certificates.templated.yaml

bin/yaml/templated-crds/crd-challenges.templated.yaml bin/yaml/templated-crds/crd-orders.templated.yaml bin/yaml/templated-crds/crd-certificaterequests.templated.yaml bin/yaml/templated-crds/crd-clusterissuers.templated.yaml bin/yaml/templated-crds/crd-issuers.templated.yaml bin/yaml/templated-crds/crd-certificates.templated.yaml: bin/yaml/templated-crds/crd-%.templated.yaml: bin/yaml/cert-manager.yaml | bin/yaml/templated-crds
	$(GO) run hack/extractcrd/main.go $< $* > $@

###############
# Dir targets #
###############

# These targets are trivial, to ensure that dirs exist

bin/yaml:
	@mkdir -p $@

bin/helm/cert-manager:
	@mkdir -p $@

bin/helm/cert-manager/templates:
	@mkdir -p $@

bin/helm/cert-manager-crds:
	@mkdir -p $@

bin/helm/cert-manager-crds/templates:
	@mkdir -p $@

bin/scratch/yaml:
	@mkdir -p $@

bin/scratch/manifests:
	@mkdir -p $@

bin/yaml/templated-crds:
	@mkdir -p $@
