ACCOUNT=munnerz
APP_NAME=cert-manager

PACKAGE_NAME=github.com/${ACCOUNT}/${APP_NAME}
GO_VERSION=1.8

GOOS := linux
GOARCH := amd64

DOCKER_IMAGE=${ACCOUNT}/${APP_NAME}

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

all: test build

.get_deps:
	@echo "Grabbing dependencies..."
	@go get -d k8s.io/kubernetes/cmd/libs/go2idl/... || true
	@go get -d github.com/kubernetes/repo-infra || true
	@touch $@

.hack_verify: .generate_exes
	@echo Running repo-infra verify scripts
	@echo Running href checker:
	@${HACK_DIR}/verify-links.sh
	@echo Running errexit checker:
	@${HACK_DIR}/verify-errexit.sh
	@echo Running generated client checker:
	@${HACK_DIR}/verify-client-gen.sh

codegen:
	which mockgen
	mockgen -imports .=github.com/munnerz/cert-manager/pkg/kubelego_const -package=mocks -source=pkg/kubelego_const/interfaces.go > pkg/mocks/mocks.go

depend:
	rm -rf $(TEST_DIR)/
	rm -rf ${BUILD_DIR}/
	mkdir $(TEST_DIR)/
	mkdir $(BUILD_DIR)/

version:
	$(eval GIT_STATE := $(shell if test -z "`git status --porcelain 2> /dev/null`"; then echo "clean"; else echo "dirty"; fi))
	$(eval GIT_COMMIT := $(shell git rev-parse HEAD))
	$(eval APP_VERSION ?= $(shell cat VERSION))
	echo $(APP_VERSION)


test_prepare: depend
	which gocover-cobertura || go get github.com/t-yuki/gocover-cobertura
	which go2xunit || go get github.com/tebeka/go2xunit
	which ngrok || curl -sL "https://bin.equinox.io/a/mU8jSiqMekT/ngrok-2.1.14-linux-amd64.tar.gz" | tar xvzf - -C "${GOPATH}/bin"
	go build -i

test: .hack_verify test_prepare $(PACKAGES)
	echo $(PACKAGES)

%.test_pkg: test_prepare
	$(eval PKG := ./$*)
	$(eval PKG_CLEAN := $(shell echo "$*" | sed "s#^p#.p#" | sed "s#/#-#g"))
	@echo "test $(PKG_CLEAN) ($(PKG))"
	bash -o pipefail -c "go test -v -coverprofile=$(TEST_DIR)/coverage$(PKG_CLEAN).txt -covermode count $(PKG) | tee $(TEST_DIR)/test$(PKG_CLEAN).out"
	cat $(TEST_DIR)/test$(PKG_CLEAN).out | go2xunit > $(TEST_DIR)/test$(PKG_CLEAN).xml
	gocover-cobertura < $(TEST_DIR)/coverage$(PKG_CLEAN).txt > $(TEST_DIR)/coverage$(PKG_CLEAN).xml

build: depend version
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		-a -tags netgo \
		-o ${BUILD_DIR}/${APP_NAME}-$(GOOS)-$(GOARCH) \
		-ldflags "-X main.AppGitState=${GIT_STATE} -X main.AppGitCommit=${GIT_COMMIT} -X main.AppVersion=${APP_VERSION}"

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

image: docker_all version
	docker build --build-arg VCS_REF=$(GIT_COMMIT) -t $(DOCKER_IMAGE):$(BUILD_TAG) .
	
push: image
	set -e; \
	for tag in $(IMAGE_TAGS); do \
		docker tag  $(DOCKER_IMAGE):$(BUILD_TAG) $(DOCKER_IMAGE):$${tag} ; \
		docker push $(DOCKER_IMAGE):$${tag}; \
	done

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

$(BINDIR)/defaulter-gen:
	go build -o $@ k8s.io/kubernetes/cmd/libs/go2idl/defaulter-gen

$(BINDIR)/deepcopy-gen:
	go build -o $@ k8s.io/kubernetes/cmd/libs/go2idl/deepcopy-gen

$(BINDIR)/conversion-gen:
	go build -o $@ k8s.io/kubernetes/cmd/libs/go2idl/conversion-gen

$(BINDIR)/client-gen:
	go build -o $@ k8s.io/kubernetes/cmd/libs/go2idl/client-gen

$(BINDIR)/lister-gen:
	go build -o $@ k8s.io/kubernetes/cmd/libs/go2idl/lister-gen

$(BINDIR)/informer-gen:
	go build -o $@ k8s.io/kubernetes/cmd/libs/go2idl/informer-gen

# Regenerate all files if the gen exes changed or any "types.go" files changed
.generate_files: .generate_exes $(TYPES_FILES)
	# Generate defaults
	$(BINDIR)/defaulter-gen \
		--v 1 --logtostderr \
		--go-header-file "$${GOPATH}/src/github.com/kubernetes/repo-infra/verify/boilerplate/boilerplate.go.txt" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/certmanager" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/certmanager/v1alpha1" \
		--extra-peer-dirs "$(PACKAGE_NAME)/pkg/apis/certmanager" \
		--extra-peer-dirs "$(PACKAGE_NAME)/pkg/apis/certmanager/v1alpha1" \
		--output-file-base "zz_generated.defaults"
	# Generate deep copies
	$(BINDIR)/deepcopy-gen \
		--v 1 --logtostderr \
		--go-header-file "$${GOPATH}/src/github.com/kubernetes/repo-infra/verify/boilerplate/boilerplate.go.txt" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/certmanager" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/certmanager/v1alpha1" \
		--bounding-dirs "github.com/openshift/open-service-broker-sdk" \
		--output-file-base zz_generated.deepcopy
	# Generate conversions
	$(BINDIR)/conversion-gen \
		--v 1 --logtostderr \
		--go-header-file "$${GOPATH}/src/github.com/kubernetes/repo-infra/verify/boilerplate/boilerplate.go.txt" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/certmanager" \
		--input-dirs "$(PACKAGE_NAME)/pkg/apis/certmanager/v1alpha1" \
		--output-file-base zz_generated.conversion
	# generate all pkg/client contents
	$(HACK_DIR)/update-client-gen.sh