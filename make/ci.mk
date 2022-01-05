.PHONY: ci-presubmit
ci-presubmit: verify-imports

.PHONY: verify-imports
verify-imports: bin/tools/goimports
	./hack/verify-goimports.sh $<
