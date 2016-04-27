ACCOUNT=simonswine
APP_NAME=kube-lego

PACKAGE_NAME=github.com/${ACCOUNT}/${APP_NAME}
GO_VERSION=1.6

DOCKER_IMAGE=${ACCOUNT}/${APP_NAME}

BUILD_DIR=_build

CONTAINER_DIR=/go/src/${PACKAGE_NAME}

depend:
	which godep || go get github.com/tools/godep

version:
	$(eval GIT_STATE := $(shell if test -z "`git status --porcelain 2> /dev/null`"; then echo -n "clean"; else echo -n "dirty"; fi))
	$(eval GIT_COMMIT := $(shell git rev-parse HEAD))
	$(eval APP_VERSION := $(shell cat VERSION))

test: depend
	godep go test

build: depend version
	mkdir -p ${BUILD_DIR}
	CGO_ENABLED=0 GOOS=linux godep go build \
		-a -tags netgo \
		-o ${BUILD_DIR}/${APP_NAME} \
		-ldflags "-X main.AppGitState=${GIT_STATE} -X main.AppGitCommit=${GIT_COMMIT} -X main.AppVersion=${APP_VERSION}"

all: test build

docker:
	# create a container
	$(eval CONTAINER_ID := $(shell docker create \
		-i \
		-w $(CONTAINER_DIR) \
		golang:${GO_VERSION} \
		/bin/bash -c "tar xf - && make all" \
	))
	
	# run build inside container
	tar cf - . | docker start -a -i $(CONTAINER_ID)

	# copy artifacts over
	rm -rf $(BUILD_DIR)/
	docker cp $(CONTAINER_ID):$(CONTAINER_DIR)/$(BUILD_DIR)/ .

	# remove container
	docker rm $(CONTAINER_ID)

docker_image: build
	docker build -t $(ACCOUNT)/$(APP_NAME):latest .
	
push: docker_image
	docker push $(ACCOUNT)/$(APP_NAME):latest

