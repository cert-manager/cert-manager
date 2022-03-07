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
