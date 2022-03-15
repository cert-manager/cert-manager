export KUBEBUILDER_ASSETS=$(PWD)/bin/tools

# WHAT can be used to control which unit tests are run by "make test"; defaults to running all
# tests except e2e tests (which require more significant setup)
# For example: make WHAT=./pkg/util/pki test-pretty to only run the PKI utils tests
WHAT ?= ./pkg/... ./cmd/... ./internal/... ./test/...

.PHONY: test
## Test is the workhorse test command which by default runs all unit and
## integration tests. Configured through WHAT, e.g.:
##
##   make test WHAT=./pkg/...
##
## @category Development
test: setup-integration-tests bin/tools/gotestsum bin/tools/etcd bin/tools/kubectl bin/tools/kube-apiserver
	$(GOTESTSUM) -- $(WHAT)

.PHONY: test-ci
# test-ci runs all unit and integration tests and writes a JUnit report of the
# results. WHAT also works here.
test-ci: setup-integration-tests bin/tools/gotestsum bin/tools/etcd bin/tools/kubectl bin/tools/kube-apiserver
	@mkdir -p $(ARTIFACTS)
	$(GOTESTSUM) --junitfile $(ARTIFACTS)/test-ci.xml -- $(WHAT)

.PHONY: unit-test
## Same as `test` but only runs the unit tests. By "unit tests", we mean tests
## that are quick to run and don't require dependencies like a Kubernetes, etcd,
## or an apiserver.
##
## @category Development
unit-test: bin/tools/gotestsum
	$(GOTESTSUM) ./cmd/... ./pkg/... ./internal/...

.PHONY: setup-integration-tests
setup-integration-tests: test/integration/versionchecker/testdata/test_manifests.tar templated-crds
	@$(eval GIT_TAGS_FILE := bin/scratch/git/upstream-tags.txt)
	@echo -e "\033[0;33mLatest known tag for integration tests is $(shell tail -1 $(GIT_TAGS_FILE)); if that seems out-of-date,\npull latest tags, run 'rm $(GIT_TAGS_FILE)' and retest\033[0m"

.PHONY: integration-test
## Same as `test` but only run the integration tests. By "integration tests",
## we mean the tests that require a live apiserver and etcd to run, but don't
## require a full Kubernetes cluster.
##
## @category Development
integration-test: setup-integration-tests bin/tools/gotestsum bin/tools/etcd bin/tools/kubectl bin/tools/kube-apiserver
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
e2e: bin/scratch/kind-exists bin/tools/kubectl bin/tools/ginkgo
	make/e2e.sh

.PHONY: e2e-ci
e2e-ci: e2e-setup-kind e2e-setup
	$(MAKE) --no-print-directory e2e FLAKE_ATTEMPTS=2 K8S_VERSION="$(K8S_VERSION)" || (make kind-logs && exit 1)

test/integration/versionchecker/testdata/test_manifests.tar: bin/scratch/oldcrds.tar bin/yaml/cert-manager.yaml
	@# Remove the temp files if they exist
	rm -f bin/scratch/versionchecker-test-manifests.tar bin/scratch/$(RELEASE_VERSION).yaml
	@# Copy the old CRDs tar and append the currentl release version to it
	cp bin/scratch/oldcrds.tar bin/scratch/versionchecker-test-manifests.tar
	cp bin/yaml/cert-manager.yaml bin/scratch/$(RELEASE_VERSION).yaml
	tar --append -f bin/scratch/versionchecker-test-manifests.tar -C bin/scratch ./$(RELEASE_VERSION).yaml
	cp bin/scratch/versionchecker-test-manifests.tar $@

bin/scratch/oldcrds.tar: bin/scratch/git/upstream-tags.txt | bin/scratch/oldcrds
	@# First, download the CRDs for all releases listed in upstream-tags.txt
	<bin/scratch/git/upstream-tags.txt xargs -I% -P5 \
		curl --compressed -sfL \
		-o bin/scratch/oldcrds/%.yaml \
		"https://github.com/cert-manager/cert-manager/releases/download/%/cert-manager.yaml"
	@# Next, tar up the old CRDs together
	tar cf $@ -C bin/scratch/oldcrds .

bin/scratch/oldcrds:
	@mkdir -p $@

bin/test:
	@mkdir -p $@

bin/testlogs:
	@mkdir -p $@
