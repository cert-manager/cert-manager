ACCOUNT=jetstackexperimental
APP_NAME=cert-manager
REGISTRY=docker.io

PACKAGE_NAME=github.com/${ACCOUNT}/${APP_NAME}
GO_VERSION=1.8

GOOS := linux
GOARCH := amd64

DOCKER_IMAGE=${REGISTRY}/${ACCOUNT}/${APP_NAME}

BUILD_DIR=_build
TEST_DIR=_test

CONTAINER_DIR=/go/src/${PACKAGE_NAME}

BUILD_TAG := build
IMAGE_TAGS := canary

PACKAGES=$(shell find . -name "*_test.go" | xargs -n1 dirname | grep -v 'vendor/' | sort -u | xargs -n1 printf "%s.test_pkg ")

BINDIR        ?= bin
HACK_DIR     ?= hack
TYPES_FILES = $(shell find pkg/apis -name types.go)

.PHONY: version

all: verify test build

.get_deps:
	@echo "Grabbing dependencies..."
	@go get -d -u k8s.io/kubernetes/ || true
	@go get -d github.com/kubernetes/repo-infra || true
	# Once k8s.io/kube-gen is live, we should be able to remove this dependency
	# on k8s.io/kubernetes. https://github.com/kubernetes/kubernetes/pull/49114
	cd ${GOPATH}/src/k8s.io/kubernetes
	@touch $@

.hack_verify: .generate_exes
	@echo Running repo-infra verify scripts
	@echo Running href checker:
	@${HACK_DIR}/verify-links.sh
	@echo Running errexit checker:
	@${HACK_DIR}/verify-errexit.sh
	@echo Running generated client checker:
	@${HACK_DIR}/verify-client-gen.sh

depend:
	rm -rf $(TEST_DIR)/
	rm -rf ${BUILD_DIR}/
	mkdir $(TEST_DIR)/
	mkdir $(BUILD_DIR)/

verify: .hack_verify
test: go_test

version:
	$(eval GIT_STATE := $(shell if test -z "`git status --porcelain 2> /dev/null`"; then echo "clean"; else echo "dirty"; fi))
	$(eval GIT_COMMIT := $(shell git rev-parse HEAD))

build_%: depend version
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		-a -tags netgo \
		-o ${BUILD_DIR}/${APP_NAME}-$*-$(GOOS)-$(GOARCH) \
		-ldflags "-X main.AppGitState=${GIT_STATE} -X main.AppGitCommit=${GIT_COMMIT} -X main.AppVersion=${APP_VERSION}" \
		./cmd/$*

go_test:
	go test $$(go list ./... | grep -v '/vendor/')

build: build_controller build_acmesolver

docker: docker_all

docker_%:
	# create a container
	$(eval CONTAINER_ID := $(shell docker create \
		-i \
		-w $(CONTAINER_DIR) \
		golang:${GO_VERSION} \
		/bin/bash -c "tar xf - && make $*" \
	))
	
	# run build inside container
	tar cf - . | docker start -a -i $(CONTAINER_ID)

	# copy artifacts over
	rm -rf $(BUILD_DIR)/ $(TEST_DIR)/
	docker cp $(CONTAINER_ID):$(CONTAINER_DIR)/$(BUILD_DIR)/ .
	docker cp $(CONTAINER_ID):$(CONTAINER_DIR)/$(TEST_DIR)/ .

	# remove container
	docker rm $(CONTAINER_ID)

image_%: version
	docker build -f "./Dockerfile.$*" --build-arg VCS_REF=$(GIT_COMMIT) -t "$(DOCKER_IMAGE)-$*:$(BUILD_TAG)" .

image: image_controller image_acmesolver

push_%: image_%
	set -e; \
	for tag in $(IMAGE_TAGS); do \
		docker tag  "$(DOCKER_IMAGE)-$*:$(BUILD_TAG)" "$(DOCKER_IMAGE)-$*:$${tag}" ; \
		docker push "$(DOCKER_IMAGE)-$*:$${tag}"; \
	done

push: push_controller push_acmesolver

release:
ifndef VERSION
	$(error VERSION is not set)
endif
	@echo "Preparing release of version $(VERSION)"
	echo $(VERSION) > VERSION
	find examples -name '*.yaml' -type f -exec sed -i 's/kube-lego:[0-9\.]*$$/kube-lego:$(VERSION)/g' {} \;

# This section contains the code generation stuff
#################################################
.generate_exes: .get_deps \
				$(BINDIR)/defaulter-gen \
                $(BINDIR)/deepcopy-gen \
                $(BINDIR)/conversion-gen \
                $(BINDIR)/client-gen \
                $(BINDIR)/lister-gen \
                $(BINDIR)/informer-gen
	touch $@

$(BINDIR)/%:
	go build -o $@ k8s.io/kubernetes/staging/src/k8s.io/code-generator/cmd/$*

# Regenerate all files if the gen exes changed or any "types.go" files changed
.generate_files: .generate_exes $(TYPES_FILES)
	# Generate defaults
	$(BINDIR)/defaulter-gen \
		--v 1 --logtostderr \
		--go-header-file "$${GOPATH}/src/github.com/kubernetes/repo-infra/verify/boilerplate/boilerplate.go.txt" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/certmanager/v1alpha1" \
		--extra-peer-dirs "$(PACKAGE_NAME)/pkg/apis/certmanager/v1alpha1" \
		--output-file-base "zz_generated.defaults"
	# Generate deep copies
	$(BINDIR)/deepcopy-gen \
		--v 1 --logtostderr \
		--go-header-file "$${GOPATH}/src/github.com/kubernetes/repo-infra/verify/boilerplate/boilerplate.go.txt" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/certmanager/v1alpha1" \
		--bounding-dirs "github.com/openshift/open-service-broker-sdk" \
		--output-file-base zz_generated.deepcopy
	# generate all pkg/client contents
	$(HACK_DIR)/update-client-gen.sh
