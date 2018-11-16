.PHONY: clean checks test build image dependencies

LEGO_IMAGE := xenolf/lego

TAG_NAME := $(shell git tag -l --contains HEAD)
SHA := $(shell git rev-parse HEAD)
VERSION := $(if $(TAG_NAME),$(TAG_NAME),$(SHA))

default: clean checks test build

clean:
	rm -rf dist/ builds/ cover.out

build: clean
	@echo Version: $(VERSION)
	go build -v -ldflags '-X "main.version=${VERSION}"'

dependencies:
	dep ensure -v

test: clean
	go test -v -cover ./...

checks:
	golangci-lint run

image:
	@echo Version: $(VERSION)
	docker build -t $(LEGO_IMAGE) .
