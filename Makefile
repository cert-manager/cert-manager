PACKAGE_NAME := github.com/jetstack/cert-manager
REGISTRY := quay.io/jetstack
APP_NAME := cert-manager
IMAGE_TAGS := canary
GOPATH ?= $HOME/go
HACK_DIR ?= hack
BUILD_TAG := build

# Domain name to use in e2e tests. This is important for ACME HTTP01 e2e tests,
# which require a domain that resolves to the ingress controller to be used for
# e2e tests.
E2E_NGINX_CERTIFICATE_DOMAIN=

PEBBLE_IMAGE_REPO=quay.io/munnerz/pebble

# AppVersion is set as the AppVersion to be compiled into the controller binary.
# It's used as the default version of the 'acmesolver' image to use for ACME
# challenge requests, and any other future provider that requires additional
# image dependencies will use this same tag.
ifeq ($(APP_VERSION),)
APP_VERSION := canary
endif

# Get a list of all binaries to be built
CMDS := $(shell find ./cmd/ -maxdepth 1 -type d -exec basename {} \; | grep -v cmd)
# Path to dockerfiles directory
DOCKERFILES := $(HACK_DIR)/build/dockerfiles
# A list of all types.go files in pkg/apis
TYPES_FILES := $(shell find pkg/apis -name types.go)
# docker_build_controller, docker_build_apiserver etc
DOCKER_BUILD_TARGETS := $(addprefix docker_build_, $(CMDS))
# docker_push_controller, docker_push_apiserver etc
DOCKER_PUSH_TARGETS := $(addprefix docker_push_, $(CMDS))

# Go build flags
GOOS := linux
GOARCH := amd64
GIT_COMMIT := $(shell git rev-parse HEAD)
GOLDFLAGS := -ldflags "-X $(PACKAGE_NAME)/pkg/util.AppGitState=${GIT_STATE} -X $(PACKAGE_NAME)/pkg/util.AppGitCommit=${GIT_COMMIT} -X $(PACKAGE_NAME)/pkg/util.AppVersion=${APP_VERSION}"

.PHONY: verify build docker_build push generate generate_verify deploy_verify \
	$(CMDS) go_test go_fmt e2e_test go_verify hack_verify hack_verify_pr \
	$(DOCKER_BUILD_TARGETS) $(DOCKER_PUSH_TARGETS)

# Docker build flags
DOCKER_BUILD_FLAGS := --build-arg VCS_REF=$(GIT_COMMIT) $(DOCKER_BUILD_FLAGS)

# Alias targets
###############

build: $(CMDS) docker_build
verify: generate_verify deploy_verify hack_verify dep_verify go_verify
verify_pr: hack_verify_pr
docker_build: $(DOCKER_BUILD_TARGETS)
docker_push: $(DOCKER_PUSH_TARGETS)
push: build docker_push

# Code generation
#################
# This target runs all required generators against our API types.
generate: $(TYPES_FILES)
	$(HACK_DIR)/update-codegen.sh

generate_verify:
	$(HACK_DIR)/verify-codegen.sh

# Hack targets
##############
hack_verify:
	@echo Running href checker
	$(HACK_DIR)/verify-links.sh
	@echo Running errexit checker
	$(HACK_DIR)/verify-errexit.sh

hack_verify_pr:
	@echo Running helm chart version checker
	$(HACK_DIR)/verify-chart-version.sh
	@echo Running reference docs checker
	IMAGE=eu.gcr.io/jetstack-build-infra/gen-apidocs-img $(HACK_DIR)/verify-reference-docs.sh

deploy_verify:
	@echo Running deploy-gen
	$(HACK_DIR)/verify-deploy-gen.sh

# Go targets
#################
dep_verify:
	@echo Running dep
	$(HACK_DIR)/verify-deps.sh

go_verify: go_fmt go_test

$(CMDS):
	CGO_ENABLED=0 GOOS=$(GOOS) GOARCH=$(GOARCH) go build \
		-a -tags netgo \
		-o $(DOCKERFILES)/${APP_NAME}-$@_$(GOOS)_$(GOARCH) \
		$(GOLDFLAGS) \
		./cmd/$@

go_test:
	go test -v \
	    -race \
		$$(go list ./... | \
			grep -v '/vendor/' | \
			grep -v '/test/e2e' | \
			grep -v '/pkg/client' | \
			grep -v '/third_party' | \
			grep -v '/docs/generated' \
		)

go_fmt:
	@set -e; \
	GO_FMT=$$(git ls-files *.go | grep -v 'vendor/' | xargs gofmt -d); \
	if [ -n "$${GO_FMT}" ] ; then \
		echo "Please run go fmt"; \
		echo "$$GO_FMT"; \
		exit 1; \
	fi

e2e_test:
	# Build the e2e tests
	go test -o e2e-tests -c ./test/e2e
	mkdir -p "$$(pwd)/_artifacts"
	# TODO: make these paths configurable
	# Run e2e tests
	KUBECONFIG=$$HOME/.kube/config CERTMANAGERCONFIG=$$HOME/.kube/config \
		./e2e-tests \
			-acme-nginx-certificate-domain=$(E2E_NGINX_CERTIFICATE_DOMAIN) \
			-cloudflare-email=$${CLOUDFLARE_E2E_EMAIL} \
			-cloudflare-api-key=$${CLOUDFLARE_E2E_API_TOKEN} \
			-acme-cloudflare-domain=$${CLOUDFLARE_E2E_DOMAIN} \
			-pebble-image-repo=$(PEBBLE_IMAGE_REPO) \
			-report-dir=./_artifacts

# Docker targets
################
$(DOCKER_BUILD_TARGETS):
	$(eval DOCKER_BUILD_CMD := $(subst docker_build_,,$@))
	docker build \
		$(DOCKER_BUILD_FLAGS) \
		-t $(REGISTRY)/$(APP_NAME)-$(DOCKER_BUILD_CMD):$(BUILD_TAG) \
		-f $(DOCKERFILES)/$(DOCKER_BUILD_CMD)/Dockerfile \
		$(DOCKERFILES)

$(DOCKER_PUSH_TARGETS):
	$(eval DOCKER_PUSH_CMD := $(subst docker_push_,,$@))
	set -e; \
		for tag in $(IMAGE_TAGS); do \
		docker tag $(REGISTRY)/$(APP_NAME)-$(DOCKER_PUSH_CMD):$(BUILD_TAG) $(REGISTRY)/$(APP_NAME)-$(DOCKER_PUSH_CMD):$${tag} ; \
		docker push $(REGISTRY)/$(APP_NAME)-$(DOCKER_PUSH_CMD):$${tag}; \
	done
