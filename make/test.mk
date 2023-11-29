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

export KUBEBUILDER_ASSETS=$(PWD)/$(BINDIR)/tools

# GOTESTSUM_CI_FLAGS contains flags which are common to invocations of gotestsum in CI environments
GOTESTSUM_CI_FLAGS := --junitfile-testsuite-name short --junitfile-testcase-classname relative

# WHAT can be used to control which unit tests are run by "make test"; defaults to running all
# tests except e2e tests (which require more significant setup)
# For example: make WHAT=./pkg/util/pki test-pretty to only run the PKI utils tests
WHAT ?= ./pkg/... ./internal/... ./test/... ./hack/prune-junit-xml/...

.PHONY: test
## Test is the workhorse test command which by default runs all unit and
## integration tests. Configured through WHAT, e.g.:
##
##   make test WHAT=./pkg/...
##
## Note that some tests and binaries are separated into different modules, and
## as such won't be testable from the root directory or using this command.
## There are separate make targets - such as "make unit-test" which should be
## used to test everything at once.
##
## @category Development
test: setup-integration-tests | $(NEEDS_GOTESTSUM) $(NEEDS_ETCD) $(NEEDS_KUBECTL) $(NEEDS_KUBE-APISERVER) $(NEEDS_GO)
	$(GOTESTSUM) -- $(WHAT)

.PHONY: test-ci
## test-ci runs all unit and integration tests and writes JUnit reports of
## the results.
##
## Fuzz tests are hidden from JUnit output, because they're noisy and can cause
## issues with dashboards and UIs.
##
## @category CI
test-ci: setup-integration-tests | $(NEEDS_GOTESTSUM) $(NEEDS_ETCD) $(NEEDS_KUBECTL) $(NEEDS_KUBE-APISERVER) $(NEEDS_GO)
	@mkdir -p $(ARTIFACTS)
	$(GOTESTSUM) \
		--junitfile $(ARTIFACTS)/junit_make-test-ci-core.xml \
		$(GOTESTSUM_CI_FLAGS) \
		--post-run-command $$'bash -c "$(GO) run hack/prune-junit-xml/prunexml.go $$GOTESTSUM_JUNITFILE"' \
		-- \
		$(WHAT)
	cd cmd/acmesolver && $(GOTESTSUM) --junitfile $(ARTIFACTS)/junit_make-test-ci-acmesolver.xml $(GOTESTSUM_CI_FLAGS) --post-run-command $$'bash -c "$(GO) run ../../hack/prune-junit-xml/prunexml.go $$GOTESTSUM_JUNITFILE"' -- ./...
	cd cmd/cainjector && $(GOTESTSUM) --junitfile $(ARTIFACTS)/junit_make-test-ci-cainjector.xml $(GOTESTSUM_CI_FLAGS) --post-run-command $$'bash -c "$(GO) run ../../hack/prune-junit-xml/prunexml.go $$GOTESTSUM_JUNITFILE"' -- ./...
	cd cmd/controller && $(GOTESTSUM) --junitfile $(ARTIFACTS)/junit_make-test-ci-controller.xml $(GOTESTSUM_CI_FLAGS) --post-run-command $$'bash -c "$(GO) run ../../hack/prune-junit-xml/prunexml.go $$GOTESTSUM_JUNITFILE"' -- ./...
	cd cmd/ctl        && $(GOTESTSUM) --junitfile $(ARTIFACTS)/junit_make-test-ci-ctl.xml        $(GOTESTSUM_CI_FLAGS) --post-run-command $$'bash -c "$(GO) run ../../hack/prune-junit-xml/prunexml.go $$GOTESTSUM_JUNITFILE"' -- ./...
	cd cmd/webhook    && $(GOTESTSUM) --junitfile $(ARTIFACTS)/junit_make-test-ci-webhook.xml    $(GOTESTSUM_CI_FLAGS) --post-run-command $$'bash -c "$(GO) run ../../hack/prune-junit-xml/prunexml.go $$GOTESTSUM_JUNITFILE"' -- ./...
	cd test/integration && $(GOTESTSUM) --junitfile $(ARTIFACTS)/junit_make-test-ci-integration.xml $(GOTESTSUM_CI_FLAGS) --post-run-command $$'bash -c "$(GO) run ../../hack/prune-junit-xml/prunexml.go $$GOTESTSUM_JUNITFILE"' -- ./...

.PHONY: unit-test
## Same as `test` but only runs the unit tests. By "unit tests", we mean tests
## that are quick to run and don't require dependencies like Kubernetes, etcd,
## or an apiserver.
##
## @category Development
unit-test: unit-test-core-module unit-test-acmesolver unit-test-cainjector unit-test-cmctl unit-test-controller unit-test-webhook | $(NEEDS_GOTESTSUM)

.PHONY: unit-test-core-module
unit-test-core-module: | $(NEEDS_GOTESTSUM)
	$(GOTESTSUM) ./pkg/... ./internal/...

.PHONY: unit-test-acmesolver
unit-test-acmesolver: | $(NEEDS_GOTESTSUM)
	cd cmd/acmesolver && $(GOTESTSUM) ./...

.PHONY: unit-test-cainjector
unit-test-cainjector: | $(NEEDS_GOTESTSUM)
	cd cmd/cainjector && $(GOTESTSUM) ./...

.PHONY: unit-test-cmctl
unit-test-cmctl: | $(NEEDS_GOTESTSUM)
	cd cmd/ctl && $(GOTESTSUM) ./...

.PHONY: unit-test-controller
unit-test-controller: | $(NEEDS_GOTESTSUM)
	cd cmd/controller && $(GOTESTSUM) ./...

.PHONY: unit-test-webhook
unit-test-webhook: | $(NEEDS_GOTESTSUM)
	cd cmd/webhook && $(GOTESTSUM) ./...

.PHONY: setup-integration-tests
setup-integration-tests: test/integration/versionchecker/testdata/test_manifests.tar templated-crds
	@$(eval GIT_TAGS_FILE := $(BINDIR)/scratch/git/upstream-tags.1.txt)
	@echo -e "\033[0;33mLatest known tag for integration tests is $(shell tail -1 $(GIT_TAGS_FILE)); if that seems out-of-date,\npull latest tags, run 'rm $(GIT_TAGS_FILE)' and retest\033[0m"

.PHONY: integration-test
## Same as `test` but only run the integration tests. By "integration tests",
## we mean the tests that require a live apiserver and etcd to run, but don't
## require a full Kubernetes cluster.
##
## @category Development
integration-test: setup-integration-tests | $(NEEDS_GOTESTSUM) $(NEEDS_ETCD) $(NEEDS_KUBECTL) $(NEEDS_KUBE-APISERVER) $(NEEDS_GO)
	cd test/integration && $(GOTESTSUM) ./...

## (optional) Set this to true to run the E2E tests against an OpenShift cluster.
## When set to true, the Hashicorp Vault Helm chart will be installed with
## settings appropriate for OpenShift.
##
## @category Development
E2E_OPENSHIFT ?= false

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
e2e-ci: | $(NEEDS_GO)
	$(shell export HELM_BURST_LIMIT=-1)
	$(MAKE) e2e-setup-kind e2e-setup
	make/e2e-ci.sh

$(BINDIR)/test/e2e.test: FORCE | $(NEEDS_GINKGO) $(BINDIR)/test
	CGO_ENABLED=0 $(GINKGO) build --ldflags="-w -s" --trimpath --tags e2e_test test/e2e
	mv test/e2e/e2e.test $(BINDIR)/test/e2e.test

.PHONY: e2e-build
## Build an end-to-end test binary
##
## The resulting binary can be used to execute the end-to-end tests on a
## computer without the test source files and without Go or Ginkgo installed.
##
## For example, the binary can be copied to an OpenShift CRC virtual machine and
## used to run end-to-end tests against cert-manager that has been installed
## using OperatorHub.
##
## Most of the tests require some other dependencies such as an ingress controller or an ACME server,
## so you will need to use --ginkgo.skip and / or  --ginkgo.focus to select a subset of the tests.
##
## The tests will use the current context in your KUBECONFIG file
## and create namespaces and resources in that cluster.
##
## Here's an example of how you might run a subset of the end-to-end tests
## which only require cert-manager to be installed:
##
##  ./_bin/test/e2e.test --repo-root=/dev/null --ginkgo.focus="CA\ Issuer" --ginkgo.skip="Gateway"
##
## @category Development
e2e-build: $(BINDIR)/test/e2e.test

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

$(BINDIR)/scratch/oldcrds.tar: $(BINDIR)/scratch/git/upstream-tags.1.txt | $(BINDIR)/scratch/oldcrds
	@# First, download the CRDs for all releases listed in upstream-tags
	<$(BINDIR)/scratch/git/upstream-tags.1.txt xargs -I% -P5 \
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
