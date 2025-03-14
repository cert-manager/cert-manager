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

.PHONY: ci-presubmit
## Run all checks (but not Go tests) which should pass before any given pull
## request or change is merged.
##
## @category CI
ci-presubmit: verify-imports verify-errexit verify-boilerplate verify-codegen verify-crds verify-modules

.PHONY: verify-modules
verify-modules: | $(NEEDS_CMREL)
	$(CMREL) validate-gomod --path $(shell pwd) --direct-import-modules github.com/cert-manager/cert-manager/cmd/ctl --no-dummy-modules github.com/cert-manager/cert-manager/integration-tests

.PHONY: verify-imports
verify-imports: | $(NEEDS_GOIMPORTS)
	./hack/verify-goimports.sh $(GOIMPORTS)

.PHONY: verify-chart
verify-chart: $(BINDIR)/cert-manager-$(RELEASE_VERSION).tgz
	DOCKER=$(CTR) ./hack/verify-chart-version.sh $<

.PHONY: verify-errexit
verify-errexit:
	./hack/verify-errexit.sh

.PHONY: verify-boilerplate
verify-boilerplate: | $(NEEDS_BOILERSUITE)
	$(BOILERSUITE) .

.PHONY: verify-licenses
## Check that the LICENSES file is up to date; must pass before a change to go.mod can be merged
##
## @category CI
verify-licenses: $(BINDIR)/scratch/LATEST-LICENSES $(BINDIR)/scratch/LATEST-LICENSES-acmesolver $(BINDIR)/scratch/LATEST-LICENSES-cainjector $(BINDIR)/scratch/LATEST-LICENSES-controller $(BINDIR)/scratch/LATEST-LICENSES-ctl $(BINDIR)/scratch/LATEST-LICENSES-webhook $(BINDIR)/scratch/LATEST-LICENSES-integration-tests $(BINDIR)/scratch/LATEST-LICENSES-e2e-tests
	@diff $(BINDIR)/scratch/LATEST-LICENSES LICENSES >/dev/null || (echo -e "\033[0;33mLICENSES seems to be out of date; update with 'make update-licenses'\033[0m" && exit 1)
	@diff $(BINDIR)/scratch/LATEST-LICENSES-acmesolver cmd/acmesolver/LICENSES >/dev/null || (echo -e "\033[0;33mcmd/acmesolver/LICENSES seems to be out of date; update with 'make update-licenses'\033[0m" && exit 1)
	@diff $(BINDIR)/scratch/LATEST-LICENSES-cainjector cmd/cainjector/LICENSES >/dev/null || (echo -e "\033[0;33mcmd/cainjector/LICENSES seems to be out of date; update with 'make update-licenses'\033[0m" && exit 1)
	@diff $(BINDIR)/scratch/LATEST-LICENSES-ctl        cmd/ctl/LICENSES        >/dev/null || (echo -e "\033[0;33mcmd/ctl/LICENSES seems to be out of date; update with 'make update-licenses'\033[0m" && exit 1)
	@diff $(BINDIR)/scratch/LATEST-LICENSES-controller cmd/controller/LICENSES >/dev/null || (echo -e "\033[0;33mcmd/controller/LICENSES seems to be out of date; update with 'make update-licenses'\033[0m" && exit 1)
	@diff $(BINDIR)/scratch/LATEST-LICENSES-webhook    cmd/webhook/LICENSES    >/dev/null || (echo -e "\033[0;33mcmd/webhook/LICENSES seems to be out of date; update with 'make update-licenses'\033[0m" && exit 1)
	@diff $(BINDIR)/scratch/LATEST-LICENSES-integration-tests test/integration/LICENSES >/dev/null || (echo -e "\033[0;33mtest/integration/LICENSES seems to be out of date; update with 'make update-licenses'\033[0m" && exit 1)
	@diff $(BINDIR)/scratch/LATEST-LICENSES-e2e-tests         test/e2e/LICENSES         >/dev/null || (echo -e "\033[0;33mtest/e2e/LICENSES seems to be out of date; update with 'make update-licenses'\033[0m" && exit 1)

.PHONY: verify-crds
verify-crds: | $(NEEDS_GO) $(NEEDS_CONTROLLER-GEN) $(NEEDS_YQ)
	./hack/check-crds.sh $(GO) $(CONTROLLER-GEN) $(YQ)

# generate-licenses here is provided as an alias so that maintainers who're accustomed to running `make generate-licenses`
# on newer cert-manager versions don't need to remember a different command for 1.12 LTS
.PHONY: generate-licenses
generate-licenses: update-licenses

.PHONY: update-licenses
update-licenses:
	rm -rf LICENSES cmd/acmesolver/LICENSES cmd/cainjector/LICENSES cmd/ctl/LICENSES cmd/controller/LICENSES cmd/webhook/LICENSES test/integration/LICENSES test/e2e/LICENSES
	$(MAKE) LICENSES cmd/acmesolver/LICENSES cmd/cainjector/LICENSES cmd/ctl/LICENSES cmd/controller/LICENSES cmd/webhook/LICENSES test/integration/LICENSES test/e2e/LICENSES

.PHONY: update-crds
update-crds: generate-test-crds patch-crds

.PHONY: generate-test-crds
generate-test-crds: | $(NEEDS_CONTROLLER-GEN)
	$(CONTROLLER-GEN) \
		crd \
		paths=./pkg/webhook/handlers/testdata/apis/testgroup/v{1,2}/... \
		output:crd:dir=./pkg/webhook/handlers/testdata/apis/testgroup/crds

PATCH_CRD_OUTPUT_DIR=./deploy/crds
.PHONY: patch-crds
patch-crds: | $(NEEDS_CONTROLLER-GEN)
	$(CONTROLLER-GEN) \
		schemapatch:manifests=./deploy/crds \
		output:dir=$(PATCH_CRD_OUTPUT_DIR) \
		paths=./pkg/apis/...

.PHONY: verify-codegen
verify-codegen: | k8s-codegen-tools $(NEEDS_GO)
	VERIFY_ONLY="true" ./hack/k8s-codegen.sh \
		$(GO) \
		./$(BINDIR)/tools/client-gen \
		./$(BINDIR)/tools/deepcopy-gen \
		./$(BINDIR)/tools/informer-gen \
		./$(BINDIR)/tools/lister-gen \
		./$(BINDIR)/tools/defaulter-gen \
		./$(BINDIR)/tools/conversion-gen \
		./$(BINDIR)/tools/openapi-gen

.PHONY: update-codegen
update-codegen: | k8s-codegen-tools $(NEEDS_GO)
	./hack/k8s-codegen.sh \
		$(GO) \
		./$(BINDIR)/tools/client-gen \
		./$(BINDIR)/tools/deepcopy-gen \
		./$(BINDIR)/tools/informer-gen \
		./$(BINDIR)/tools/lister-gen \
		./$(BINDIR)/tools/defaulter-gen \
		./$(BINDIR)/tools/conversion-gen \
		./$(BINDIR)/tools/openapi-gen

.PHONY: update-all
## Update CRDs, code generation and licenses to the latest versions.
## This is provided as a convenience to run locally before creating a PR, to ensure
## that everything is up-to-date.
##
## @category Development
update-all: update-crds update-codegen update-licenses
