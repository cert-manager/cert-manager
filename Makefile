ACCOUNT=jetstackexperimental
APP_NAME=cert-manager
REGISTRY=docker.io

PACKAGE_NAME=github.com/jetstack-experimental/cert-manager
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

E2E_NGINX_CERTIFICATE_DOMAIN=

.PHONY: version

ifeq ($(APP_VERSION),)
APP_VERSION := canary
endif

all: verify test build

.hack_verify:
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

verify: go_fmt .hack_verify
test: go_test

version:
	$(eval GIT_STATE := $(shell if test -z "`git status --porcelain 2> /dev/null`"; then echo "clean"; else echo "dirty"; fi))
	$(eval GIT_COMMIT := $(shell git rev-parse HEAD))

build_%: depend version
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		-a -tags netgo \
		-o ${BUILD_DIR}/${APP_NAME}-$*-$(GOOS)-$(GOARCH) \
		-ldflags "-X github.com/jetstack-experimental/cert-manager/pkg/util.AppGitState=${GIT_STATE} -X github.com/jetstack-experimental/cert-manager/pkg/util.AppGitCommit=${GIT_COMMIT} -X github.com/jetstack-experimental/cert-manager/pkg/util.AppVersion=${APP_VERSION}" \
		./cmd/$*

go_fmt:
	$(eval FMT_OUTPUT := $(shell go fmt ./pkg/... ./cmd/... ./test/... | wc -l))
	@if [ "$(FMT_OUTPUT)" != "0" ]; then echo "Please run go fmt"; exit 1; fi

go_test:
	go test -v $$(go list ./... | grep -v '/vendor/' | grep -v '/test/e2e' )

e2e_test:
	go test -o e2e-tests -c ./test/e2e
	KUBECONFIG=$$HOME/.kube/config CERTMANAGERCONFIG=$$HOME/.kube/config \
		./e2e-tests \
			-cert-manager-image-pull-policy=Never \
			-cert-manager-image=$(DOCKER_IMAGE)-controller:$(BUILD_TAG) \
			-acme-nginx-certificate-domain=$(E2E_NGINX_CERTIFICATE_DOMAIN)

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

# Regenerate all files if the gen exes changed or any "types.go" files changed
.generate_files:
	# generate all pkg/client contents
	$(HACK_DIR)/update-client-gen.sh
