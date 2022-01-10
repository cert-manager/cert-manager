.PHONY: ci-presubmit
ci-presubmit: verify-imports verify-chart

.PHONY: verify-imports
verify-imports: bin/tools/goimports
	./hack/verify-goimports.sh $<

.PHONY: verify-chart
verify-chart: bin/cert-manager-$(RELEASE_VERSION).tgz
	./hack/verify-chart-version.sh $<
