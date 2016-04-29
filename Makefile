ACCOUNT=simonswine
APP_NAME=kube-lego

PACKAGE_NAME=github.com/${ACCOUNT}/${APP_NAME}
GO_VERSION=1.6

DOCKER_IMAGE=${ACCOUNT}/${APP_NAME}

BUILD_DIR=_build
TEST_DIR=_test

CONTAINER_DIR=/go/src/${PACKAGE_NAME}

depend:
	which godep || go get github.com/tools/godep

version:
	$(eval GIT_STATE := $(shell if test -z "`git status --porcelain 2> /dev/null`"; then echo -n "clean"; else echo -n "dirty"; fi))
	$(eval GIT_COMMIT := $(shell git rev-parse HEAD))
	$(eval APP_VERSION := $(shell cat VERSION))

test: test_root test_pkg_acme test_pkg_ingress test_pkg_kubelego test_pkg_kubelego_const test_pkg_secret test_pkg_utils

test_root: depend
	which gocover-cobertura || go get github.com/t-yuki/gocover-cobertura
	which go2xunit || go get bitbucket.org/tebeka/go2xunit
	rm -rf $(TEST_DIR)/
	mkdir $(TEST_DIR)/
	godep go test -v -coverprofile=$(TEST_DIR)/coverage.txt -covermode count $* | go2xunit > $(TEST_DIR)/test.xml
	gocover-cobertura < $(TEST_DIR)/coverage.txt > $(TEST_DIR)/coverage.xml

test_pkg_%: depend
	godep go test -coverprofile=$(TEST_DIR)/coverage.$*.txt -covermode count $(PACKAGE_NAME)/pkg/$*

build: depend version
	mkdir -p ${BUILD_DIR}
	CGO_ENABLED=0 GOOS=linux godep go build \
		-a -tags netgo \
		-o ${BUILD_DIR}/${APP_NAME} \
		-ldflags "-X main.AppGitState=${GIT_STATE} -X main.AppGitCommit=${GIT_COMMIT} -X main.AppVersion=${APP_VERSION}"

all: test build

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

image: docker_all
	docker build -t $(ACCOUNT)/$(APP_NAME):latest .
	
push: image
	docker push $(ACCOUNT)/$(APP_NAME):latest
