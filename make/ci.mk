.PHONY: ci-presubmit
## Run all checks (but not Go tests) which should pass before any given pull
## request or change is merged.
##
## @category CI
ci-presubmit: verify-imports verify-errexit verify-boilerplate verify-codegen verify-crds verify-licenses

.PHONY: verify-imports
verify-imports: $(BINDIR)/tools/goimports
	./hack/verify-goimports.sh $<

.PHONY: verify-chart
verify-chart: $(BINDIR)/cert-manager-$(RELEASE_VERSION).tgz
	DOCKER=$(CTR) ./hack/verify-chart-version.sh $<

.PHONY: verify-errexit
verify-errexit:
	./hack/verify-errexit.sh

__PYTHON := python3

.PHONY: verify-boilerplate
verify-boilerplate:
	@command -v $(__PYTHON) >/dev/null || (echo "couldn't find python3 at '$(__PYTHON)', required for $@. Install python3 or set '__PYTHON'" && exit 1)
	$(__PYTHON) hack/verify_boilerplate.py

.PHONY: verify-licenses
verify-licenses: $(BINDIR)/scratch/LATEST-LICENSES
	@diff $(BINDIR)/scratch/LATEST-LICENSES LICENSES >/dev/null || (echo -e "\033[0;33mLICENSES seem to be out of date; update with 'make update-licenses'\033[0m" && exit 1)

.PHONY: verify-crds
verify-crds: | $(DEPENDS_ON_GO) $(BINDIR)/tools/controller-gen $(BINDIR)/tools/yq
	./hack/check-crds.sh $(GO) ./$(BINDIR)/tools/controller-gen ./$(BINDIR)/tools/yq

.PHONY: update-licenses
update-licenses: LICENSES

.PHONY: update-crds
## Update all CRDs to the latest version based on the current checkout
##
## @category Development
update-crds: generate-test-crds patch-crds | $(BINDIR)/tools/controller-gen

.PHONY: generate-test-crds
generate-test-crds: | $(BINDIR)/tools/controller-gen
	./$(BINDIR)/tools/controller-gen \
		crd \
		paths=./pkg/webhook/handlers/testdata/apis/testgroup/v{1,2}/... \
		output:crd:dir=./pkg/webhook/handlers/testdata/apis/testgroup/crds

PATCH_CRD_OUTPUT_DIR=./deploy/crds
.PHONY: patch-crds
patch-crds: | $(BINDIR)/tools/controller-gen
	./$(BINDIR)/tools/controller-gen \
		schemapatch:manifests=./deploy/crds \
		output:dir=$(PATCH_CRD_OUTPUT_DIR) \
		paths=./pkg/apis/...

.PHONY: verify-codegen
verify-codegen: | k8s-codegen-tools $(DEPENDS_ON_GO)
	VERIFY_ONLY="true" ./hack/k8s-codegen.sh \
		$(GO) \
		./$(BINDIR)/tools/client-gen \
		./$(BINDIR)/tools/deepcopy-gen \
		./$(BINDIR)/tools/informer-gen \
		./$(BINDIR)/tools/lister-gen \
		./$(BINDIR)/tools/defaulter-gen \
		./$(BINDIR)/tools/conversion-gen

.PHONY: update-codegen
update-codegen: | k8s-codegen-tools $(DEPENDS_ON_GO)
	./hack/k8s-codegen.sh \
		$(GO) \
		./$(BINDIR)/tools/client-gen \
		./$(BINDIR)/tools/deepcopy-gen \
		./$(BINDIR)/tools/informer-gen \
		./$(BINDIR)/tools/lister-gen \
		./$(BINDIR)/tools/defaulter-gen \
		./$(BINDIR)/tools/conversion-gen

# The targets (verify_deps, verify_chart, verify_upgrade, and cluster) are
# temorary and exist to keep the compatibility with the following Prow jobs:
#
#   pull-cert-manager-chart
#   pull-cert-manager-deps
#   pull-cert-manager-upgrade
#
# These targets should be removed as soon as the four above jobs and scripts are
# updated to use the "make" flow.
.PHONY: verify
verify:
	$(warning "The 'verify' target is deprecated and will be removed soon. Please use instead 'ci-presubmit'")
	bazel test //...

.PHONY: verify_deps
verify_deps:
	@# this target can be removed once we've removed the pull-cert-manager-deps test from presubmits
	@# for now, just make it a no-op so the tests don't fail
	$(warning "The 'verify_deps' target is deprecated, does nothing, and will be removed soon. This target is not useful anymore with the new make flow.")
	@true

# requires docker
.PHONY: verify_chart
verify_chart:
	$(warning "The 'verify_chart' target is deprecated and will be removed soon. Please use instead 'verify-chart'.")
	bazel build //deploy/charts/cert-manager
	./hack/verify-chart-version.sh bazel-bin/deploy/charts/cert-manager/cert-manager.tgz

.PHONY: verify_upgrade
verify_upgrade:
	$(warning "The 'verify_upgrade' target is deprecated and will be removed soon. Please use instead 'make e2e-setup-kind && ./hack/verify-upgrade.sh'.")
	./hack/verify-upgrade.sh

.PHONY: cluster
cluster:
	$(warning "The 'cluster' target is deprecated and will be removed soon. Please use instead 'make e2e-setup-kind'.")
	./devel/ci-cluster.sh
