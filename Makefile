ACCOUNT=jetstack
APP_NAME=kube-lego

PACKAGE_NAME=github.com/${ACCOUNT}/${APP_NAME}
GO_VERSION=1.8

GOOS := linux
GOARCH := amd64

DOCKER_IMAGE=${ACCOUNT}/${APP_NAME}

BUILD_DIR=_build
TEST_DIR=_test

CONTAINER_DIR=/go/src/${PACKAGE_NAME}

PACKAGES=$(shell find . -name "*_test.go" | xargs -n1 dirname | grep -v 'vendor/' | sort -u | xargs -n1 printf "%s.test_pkg ")

.PHONY: version

all: test build

codegen:
	which mockgen
	mockgen -imports .=github.com/jetstack/kube-lego/pkg/kubelego_const -package=mocks -source=pkg/kubelego_const/interfaces.go > pkg/mocks/mocks.go

depend:
	rm -rf $(TEST_DIR)/
	rm -rf ${BUILD_DIR}/
	mkdir $(TEST_DIR)/
	mkdir $(BUILD_DIR)/

version: 
	$(eval GIT_STATE := $(shell if test -z "`git status --porcelain 2> /dev/null`"; then echo "clean"; else echo "dirty"; fi))
	$(eval GIT_COMMIT := $(shell git rev-parse HEAD))
	$(eval APP_VERSION := $(shell cat VERSION))


test_prepare: depend
	which gocover-cobertura || go get github.com/t-yuki/gocover-cobertura
	which go2xunit || go get github.com/tebeka/go2xunit
	which ngrok || curl -sL "https://bin.equinox.io/a/mU8jSiqMekT/ngrok-2.1.14-linux-amd64.tar.gz" | tar xvzf - -C "${GOPATH}/bin"
	go build -i

test: test_prepare $(PACKAGES)
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
	docker build --build-arg VCS_REF=$(GIT_COMMIT) -t $(DOCKER_IMAGE):latest .
	
push: image
	docker push $(DOCKER_IMAGE):latest

release:
ifndef VERSION
	$(error VERSION is not set)
endif
	@echo "Preparing release of version $(VERSION)"
	echo $(VERSION) > VERSION
	find examples -name '*.yaml' -type f -exec sed -i 's/kube-lego:[0-9\.]*$$/kube-lego:$(VERSION)/g' {} \;
