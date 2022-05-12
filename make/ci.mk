__PYTHON := python3

.PHONY: ci-presubmit
## Run all checks (but not Go tests) which should pass before any given pull
## request or change is merged.
##
## @category CI
ci-presubmit: verify-imports verify-errexit verify-boilerplate verify-deps-licenses verify-codegen verify-crds

.PHONY: verify-imports
verify-imports: bin/tools/goimports
	./hack/verify-goimports.sh $<

.PHONY: verify-chart
verify-chart: bin/cert-manager-$(RELEASE_VERSION).tgz
	DOCKER=$(CTR) ./hack/verify-chart-version.sh $<

.PHONY: verify-errexit
verify-errexit:
	./hack/verify-errexit.sh

.PHONY: verify-boilerplate
verify-boilerplate:
	$(__PYTHON) hack/verify_boilerplate.py

.PHONY: verify-crds
verify-crds: | $(DEPENDS_ON_GO) bin/tools/controller-gen bin/tools/yq
	./hack/check-crds.sh $(GO) ./bin/tools/controller-gen ./bin/tools/yq

.PHONY: update-crds
## Update all CRDs to the latest version based on the current checkout
##
## @category Development
update-crds: generate-test-crds patch-crds | bin/tools/controller-gen

.PHONY: generate-test-crds
generate-test-crds: | bin/tools/controller-gen
	./bin/tools/controller-gen \
		crd \
		paths=./pkg/webhook/handlers/testdata/apis/testgroup/v{1,2}/... \
		output:crd:dir=./pkg/webhook/handlers/testdata/apis/testgroup/crds

PATCH_CRD_OUTPUT_DIR=./deploy/crds
.PHONY: patch-crds
patch-crds: | bin/tools/controller-gen
	./bin/tools/controller-gen \
		schemapatch:manifests=./deploy/crds \
		output:dir=$(PATCH_CRD_OUTPUT_DIR) \
		paths=./pkg/apis/...

.PHONY: verify-codegen
verify-codegen: | k8s-codegen-tools $(DEPENDS_ON_GO)
	VERIFY_ONLY="true" ./hack/k8s-codegen.sh \
		$(GO) \
		./bin/tools/client-gen \
		./bin/tools/deepcopy-gen \
		./bin/tools/informer-gen \
		./bin/tools/lister-gen \
		./bin/tools/defaulter-gen \
		./bin/tools/conversion-gen

.PHONY: update-codegen
update-codegen: | k8s-codegen-tools $(DEPENDS_ON_GO)
	./hack/k8s-codegen.sh \
		$(GO) \
		./bin/tools/client-gen \
		./bin/tools/deepcopy-gen \
		./bin/tools/informer-gen \
		./bin/tools/lister-gen \
		./bin/tools/defaulter-gen \
		./bin/tools/conversion-gen

.PHONY: update-deps-licenses
update-deps-licenses: | $(DEPENDS_ON_GO) bin
	./hack/generate-deps-licenses.sh $(GO) LICENSES >/dev/null 2>&1

.PHONY: verify-deps-licenses
verify-deps-licenses: | $(DEPENDS_ON_GO) bin
	./hack/verify-deps-licenses.sh $(GO) LICENSES

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
# verify_deps on't be recreated in make because it's tightly tied to bazel.
verify_deps:
	$(warning "The 'verify_deps' target is deprecated and will be removed soon. This target is not useful anymore with the new make flow.")
	./hack/verify-deps.sh

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
