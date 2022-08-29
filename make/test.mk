export KUBEBUILDER_ASSETS=$(PWD)/$(BINDIR)/tools

# WHAT can be used to control which unit tests are run by "make test"; defaults to running all
# tests except e2e tests (which require more significant setup)
# For example: make WHAT=./pkg/util/pki test-pretty to only run the PKI utils tests
WHAT ?= ./pkg/... ./cmd/... ./internal/... ./test/... ./hack/prune-junit-xml/...

.PHONY: test
## Test is the workhorse test command which by default runs all unit and
## integration tests. Configured through WHAT, e.g.:
##
##   make test WHAT=./pkg/...
##
## @category Development
test: setup-integration-tests | $(NEEDS_GOTESTSUM) $(NEEDS_ETCD) $(NEEDS_KUBECTL) $(NEEDS_KUBE-APISERVER) $(NEEDS_GO)
	$(GOTESTSUM) -- $(WHAT)

.PHONY: test-ci
## test-ci runs all unit and integration tests and writes a JUnit report of
## the results. WHAT can be used to limit which tests are run; see help for
## `make test` for more details.
##
## Fuzz tests are hidden from JUnit output, because they're noisy and can cause
## issues with dashboards and UIs.
##
## @category CI
test-ci: setup-integration-tests | $(NEEDS_GOTESTSUM) $(NEEDS_ETCD) $(NEEDS_KUBECTL) $(NEEDS_KUBE-APISERVER) $(NEEDS_GO)
	@mkdir -p $(ARTIFACTS)
	$(GOTESTSUM) \
		--junitfile $(ARTIFACTS)/junit_make-test-ci.xml \
		--junitfile-testsuite-name short \
		--junitfile-testcase-classname relative \
		--post-run-command $$'bash -c "$(GO) run hack/prune-junit-xml/prunexml.go $$GOTESTSUM_JUNITFILE"' \
		-- \
		$(WHAT)

.PHONY: unit-test
## Same as `test` but only runs the unit tests. By "unit tests", we mean tests
## that are quick to run and don't require dependencies like Kubernetes, etcd,
## or an apiserver.
##
## @category Development
unit-test: | $(NEEDS_GOTESTSUM)
	$(GOTESTSUM) ./cmd/... ./pkg/... ./internal/...

.PHONY: setup-integration-tests
setup-integration-tests: test/integration/versionchecker/testdata/test_manifests.tar templated-crds
	@$(eval GIT_TAGS_FILE := $(BINDIR)/scratch/git/upstream-tags.txt)
	@echo -e "\033[0;33mLatest known tag for integration tests is $(shell tail -1 $(GIT_TAGS_FILE)); if that seems out-of-date,\npull latest tags, run 'rm $(GIT_TAGS_FILE)' and retest\033[0m"

.PHONY: integration-test
## Same as `test` but only run the integration tests. By "integration tests",
## we mean the tests that require a live apiserver and etcd to run, but don't
## require a full Kubernetes cluster.
##
## @category Development
integration-test: setup-integration-tests | $(NEEDS_GOTESTSUM) $(NEEDS_ETCD) $(NEEDS_KUBECTL) $(NEEDS_KUBE-APISERVER) $(NEEDS_GO)
	$(GOTESTSUM) ./test/...

.PHONY: e2e
## Run the end-to-end tests. Before running this, you need to run:
##
##     make -j e2e-setup
##
## To run a specific test instead of the whole suite, run:
##
##     make e2e GINKGO_FOCUS='.*call the dummy webhook'
##
## For more information about GINKGO_FOCUS, see "make/e2e.sh --help".
##
## @category Development
e2e: $(BINDIR)/scratch/kind-exists | $(NEEDS_KUBECTL) $(NEEDS_GINKGO)
	make/e2e.sh

.PHONY: e2e-ci
e2e-ci: e2e-setup-kind e2e-setup
	make/e2e-ci.sh

.PHONY: test-upgrade
test-upgrade: | $(NEEDS_HELM) $(NEEDS_KIND) $(NEEDS_YTT) $(NEEDS_KUBECTL) $(BINDIR)/cmctl/cmctl-$(HOST_OS)-$(HOST_ARCH)
	./hack/verify-upgrade.sh $(HELM) $(KIND) $(YTT) $(KUBECTL) $(BINDIR)/cmctl/cmctl-$(HOST_OS)-$(HOST_ARCH)

test/integration/versionchecker/testdata/test_manifests.tar: $(BINDIR)/scratch/oldcrds.tar $(BINDIR)/yaml/cert-manager.yaml
	@# Remove the temp files if they exist
	rm -f $(BINDIR)/scratch/versionchecker-test-manifests.tar $(BINDIR)/scratch/$(RELEASE_VERSION).yaml
	@# Copy the old CRDs tar and append the currentl release version to it
	cp $(BINDIR)/scratch/oldcrds.tar $(BINDIR)/scratch/versionchecker-test-manifests.tar
	cp $(BINDIR)/yaml/cert-manager.yaml $(BINDIR)/scratch/$(RELEASE_VERSION).yaml
	tar --append -f $(BINDIR)/scratch/versionchecker-test-manifests.tar -C $(BINDIR)/scratch ./$(RELEASE_VERSION).yaml
	cp $(BINDIR)/scratch/versionchecker-test-manifests.tar $@

$(BINDIR)/scratch/oldcrds.tar: $(BINDIR)/scratch/git/upstream-tags.txt | $(BINDIR)/scratch/oldcrds
	@# First, download the CRDs for all releases listed in upstream-tags.txt
	<$(BINDIR)/scratch/git/upstream-tags.txt xargs -I% -P5 \
		./hack/fetch-old-crd.sh \
		"https://github.com/cert-manager/cert-manager/releases/download/%/cert-manager.yaml" \
		$(BINDIR)/scratch/oldcrds/%.yaml
	@# Next, tar up the old CRDs together
	tar cf $@ -C $(BINDIR)/scratch/oldcrds .

$(BINDIR)/scratch/oldcrds:
	@mkdir -p $@

$(BINDIR)/test:
	@mkdir -p $@

$(BINDIR)/testlogs:
	@mkdir -p $@
