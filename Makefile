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
E2E_NGINX_CERTIFICATE_DOMAIN ?= certmanager.kubernetes.network

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
GOLDFLAGS := -ldflags "-X $(PACKAGE_NAME)/pkg/util.AppGitState=${GIT_STATE} -X $(PACKAGE_NAME)/pkg/util.AppGitCommit=${GIT_COMMIT} -X $(PACKAGE_NAME)/pkg/util.AppVersion=${APP_VERSION}"

.PHONY: verify build docker_build push generate generate_verify $(CMDS) go_test go_fmt $(DOCKER_BUILD_TARGETS) $(DOCKER_PUSH_TARGETS)

# Alias targets
###############

verify: generate_verify hack_verify go_verify
build: $(CMDS) docker_build
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

# Go targets
#################
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
			grep -v '/third_party' \
		)

go_fmt:
	@set -e; \
	GO_FMT=$$(git ls-files *.go | grep -v 'vendor/' | xargs gofmt -d); \
	if [ -n "$${GO_FMT}" ] ; then \
		echo "Please run go fmt"; \
		echo "$$GO_FMT"; \
		exit 1; \
	fi

.e2e_configure_ingress:
	while true; do if kubectl get rc nginx-ingress-controller -n kube-system; then break; fi; echo "Waiting 5s for nginx-ingress-controller rc to be installed..."; sleep 5; done
	kubectl expose -n kube-system --port 80 --target-port 80 --type ClusterIP rc nginx-ingress-controller --cluster-ip 10.0.0.15

e2e_test: .e2e_configure_ingress
	# Build the e2e tests
	go test -o e2e-tests -c ./test/e2e
	# TODO: make these paths configurable
	# Run e2e tests
	KUBECONFIG=$$HOME/.kube/config CERTMANAGERCONFIG=$$HOME/.kube/config \
		./e2e-tests \
			-cert-manager-image-pull-policy=Never \
			-cert-manager-image=$(REGISTRY)/$(APP_NAME)-controller:$(BUILD_TAG) \
			-ingress-shim-image-pull-policy=Never \
			-ingress-shim-image=$(REGISTRY)/$(APP_NAME)-ingress-shim:$(BUILD_TAG) \
			-acme-nginx-certificate-domain=$(E2E_NGINX_CERTIFICATE_DOMAIN)

# Docker targets
################
$(DOCKER_BUILD_TARGETS):
	$(eval DOCKER_BUILD_CMD := $(subst docker_build_,,$@))
	docker build \
		--build-arg VCS_REF=$(GIT_COMMIT) \
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
