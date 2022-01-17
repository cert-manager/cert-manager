# WHAT can be used to control which unit tests are run by "make test"; defaults to running all
# tests except e2e tests (which require more significant setup)
# For example: make WHAT=./pkg/util/pki test-pretty to only run the PKI utils tests
WHAT ?= ./pkg/... ./cmd/... ./internal/... ./test/...

.PHONY: test
test: setup-integration-tests  ## test is the workhorse test command which by default runs all unit and integration tests. Configured through WHAT, e.g. make WHAT=./pkg/... test
	$(GOTEST) $(WHAT)

.PHONY: test-pretty
test-pretty: setup-integration-tests | bin/tools/gotestsum  ## test-pretty is similar to test, but uses gotestsum for prettier output
	$(GOTESTSUM) -- $(WHAT)

.PHONY: test-ci
test-ci: setup-integration-tests | bin/testlogs bin/tools/gotestsum  ## test-ci runs all unit and integration tests and writes a JUnit report of the results
	$(GOTESTSUM) --junitfile bin/testlogs/test-ci.xml -- ./...

.PHONY: unit-test
unit-test:
	$(GOTEST) ./cmd/... ./pkg/... ./internal/...

.PHONY: setup-integration-tests
setup-integration-tests: integration-test-tools test/integration/versionchecker/testdata/test_manifests.tar templated-crds

.PHONY: integration-test
integration-test: setup-integration-tests
	$(GOTEST) ./test/...

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
	<bin/scratch/git/upstream-tags.txt xargs -I% --max-procs=5 \
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
