__PYTHON := python3

.PHONY: ci-presubmit
ci-presubmit: verify-imports verify-chart verify-errexit verify-boilerplate

.PHONY: verify-imports
verify-imports: bin/tools/goimports
	./hack/verify-goimports.sh $<

.PHONY: verify-chart
verify-chart: bin/cert-manager-$(RELEASE_VERSION).tgz
	./hack/verify-chart-version.sh $<

.PHONY: verify-errexit
verify-errexit:
	./hack/verify-errexit.sh

.PHONY: verify-boilerplate
verify-boilerplate:
	$(__PYTHON) hack/verify_boilerplate.py

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
