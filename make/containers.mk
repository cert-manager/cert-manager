# set to "DYNAMIC" to use a dynamic base image
BASE_IMAGE_TYPE:=STATIC

BASE_IMAGE_controller-linux-amd64:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_amd64)
BASE_IMAGE_controller-linux-arm64:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_arm64)
BASE_IMAGE_controller-linux-s390x:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_s390x)
BASE_IMAGE_controller-linux-ppc64le:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_ppc64le)
BASE_IMAGE_controller-linux-arm:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_arm)

BASE_IMAGE_webhook-linux-amd64:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_amd64)
BASE_IMAGE_webhook-linux-arm64:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_arm64)
BASE_IMAGE_webhook-linux-s390x:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_s390x)
BASE_IMAGE_webhook-linux-ppc64le:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_ppc64le)
BASE_IMAGE_webhook-linux-arm:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_arm)

BASE_IMAGE_acmesolver-linux-amd64:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_amd64)
BASE_IMAGE_acmesolver-linux-arm64:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_arm64)
BASE_IMAGE_acmesolver-linux-s390x:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_s390x)
BASE_IMAGE_acmesolver-linux-ppc64le:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_ppc64le)
BASE_IMAGE_acmesolver-linux-arm:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_arm)

BASE_IMAGE_cainjector-linux-amd64:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_amd64)
BASE_IMAGE_cainjector-linux-arm64:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_arm64)
BASE_IMAGE_cainjector-linux-s390x:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_s390x)
BASE_IMAGE_cainjector-linux-ppc64le:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_ppc64le)
BASE_IMAGE_cainjector-linux-arm:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_arm)

BASE_IMAGE_cmctl-linux-amd64:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_amd64)
BASE_IMAGE_cmctl-linux-arm64:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_arm64)
BASE_IMAGE_cmctl-linux-s390x:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_s390x)
BASE_IMAGE_cmctl-linux-ppc64le:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_ppc64le)
BASE_IMAGE_cmctl-linux-arm:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_arm)

bin/containers:
	@mkdir -p $@

.PHONY: all-containers
all-containers: cert-manager-controller-linux cert-manager-webhook-linux cert-manager-acmesolver-linux cert-manager-cainjector-linux cert-manager-ctl-linux

.PHONY: cert-manager-controller-linux
cert-manager-controller-linux: bin/containers/cert-manager-controller-linux-amd64.tar.gz bin/containers/cert-manager-controller-linux-arm64.tar.gz bin/containers/cert-manager-controller-linux-s390x.tar.gz bin/containers/cert-manager-controller-linux-ppc64le.tar.gz bin/containers/cert-manager-controller-linux-arm.tar.gz

bin/containers/cert-manager-controller-linux-amd64.tar.gz bin/containers/cert-manager-controller-linux-arm64.tar.gz bin/containers/cert-manager-controller-linux-s390x.tar.gz bin/containers/cert-manager-controller-linux-ppc64le.tar.gz bin/containers/cert-manager-controller-linux-arm.tar.gz: bin/containers/cert-manager-controller-linux-%.tar.gz: bin/server/controller-linux-% hack/containers/Containerfile.controller bin/scratch/cert-manager.license bin/scratch/cert-manager.licenses_notice bin/release-version | bin/containers bin/scratch/containers/cert-manager-controller-linux-%
	$(eval TAG := cert-manager-controller-$*:$(RELEASE_VERSION))
	$(eval BASE := BASE_IMAGE_$(notdir $<))
	$(eval CONTEXT_DIR := bin/scratch/containers/$(notdir $(@:%.tar.gz=%)))
	@cp $< $(CONTEXT_DIR)/controller
	@cp bin/scratch/cert-manager.license bin/scratch/cert-manager.licenses_notice $(CONTEXT_DIR)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.controller \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(CONTEXT_DIR)
	$(CTR) save $(TAG) | gzip > $@

.PHONY: cert-manager-webhook-linux
cert-manager-webhook-linux: bin/containers/cert-manager-webhook-linux-amd64.tar.gz bin/containers/cert-manager-webhook-linux-arm64.tar.gz bin/containers/cert-manager-webhook-linux-s390x.tar.gz bin/containers/cert-manager-webhook-linux-ppc64le.tar.gz bin/containers/cert-manager-webhook-linux-arm.tar.gz

bin/containers/cert-manager-webhook-linux-amd64.tar.gz bin/containers/cert-manager-webhook-linux-arm64.tar.gz bin/containers/cert-manager-webhook-linux-s390x.tar.gz bin/containers/cert-manager-webhook-linux-ppc64le.tar.gz bin/containers/cert-manager-webhook-linux-arm.tar.gz: bin/containers/cert-manager-webhook-linux-%.tar.gz: bin/server/webhook-linux-% hack/containers/Containerfile.webhook bin/scratch/cert-manager.license bin/scratch/cert-manager.licenses_notice bin/release-version | bin/containers bin/scratch/containers/cert-manager-webhook-linux-%
	$(eval TAG := cert-manager-webhook-$*:$(RELEASE_VERSION))
	$(eval BASE := BASE_IMAGE_$(notdir $<))
	$(eval CONTEXT_DIR := bin/scratch/containers/$(notdir $(@:%.tar.gz=%)))
	@cp $< $(CONTEXT_DIR)/webhook
	@cp bin/scratch/cert-manager.license bin/scratch/cert-manager.licenses_notice $(CONTEXT_DIR)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.webhook \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(CONTEXT_DIR)
	$(CTR) save $(TAG) | gzip > $@

.PHONY: cert-manager-cainjector-linux
cert-manager-cainjector-linux: bin/containers/cert-manager-cainjector-linux-amd64.tar.gz bin/containers/cert-manager-cainjector-linux-arm64.tar.gz bin/containers/cert-manager-cainjector-linux-s390x.tar.gz bin/containers/cert-manager-cainjector-linux-ppc64le.tar.gz bin/containers/cert-manager-cainjector-linux-arm.tar.gz

bin/containers/cert-manager-cainjector-linux-amd64.tar.gz bin/containers/cert-manager-cainjector-linux-arm64.tar.gz bin/containers/cert-manager-cainjector-linux-s390x.tar.gz bin/containers/cert-manager-cainjector-linux-ppc64le.tar.gz bin/containers/cert-manager-cainjector-linux-arm.tar.gz: bin/containers/cert-manager-cainjector-linux-%.tar.gz: bin/server/cainjector-linux-% hack/containers/Containerfile.cainjector bin/scratch/cert-manager.license bin/scratch/cert-manager.licenses_notice bin/release-version | bin/containers bin/scratch/containers/cert-manager-cainjector-linux-%
	$(eval TAG := cert-manager-cainjector-$*:$(RELEASE_VERSION))
	$(eval BASE := BASE_IMAGE_$(notdir $<))
	$(eval CONTEXT_DIR := bin/scratch/containers/$(notdir $(@:%.tar.gz=%)))
	@cp $< $(CONTEXT_DIR)/cainjector
	@cp bin/scratch/cert-manager.license bin/scratch/cert-manager.licenses_notice $(CONTEXT_DIR)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.cainjector \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(CONTEXT_DIR)
	$(CTR) save $(TAG) | gzip > $@

.PHONY: cert-manager-acmesolver-linux
cert-manager-acmesolver-linux: bin/containers/cert-manager-acmesolver-linux-amd64.tar.gz bin/containers/cert-manager-acmesolver-linux-arm64.tar.gz bin/containers/cert-manager-acmesolver-linux-s390x.tar.gz bin/containers/cert-manager-acmesolver-linux-ppc64le.tar.gz bin/containers/cert-manager-acmesolver-linux-arm.tar.gz

bin/containers/cert-manager-acmesolver-linux-amd64.tar.gz bin/containers/cert-manager-acmesolver-linux-arm64.tar.gz bin/containers/cert-manager-acmesolver-linux-s390x.tar.gz bin/containers/cert-manager-acmesolver-linux-ppc64le.tar.gz bin/containers/cert-manager-acmesolver-linux-arm.tar.gz: bin/containers/cert-manager-acmesolver-linux-%.tar.gz: bin/server/acmesolver-linux-% hack/containers/Containerfile.acmesolver bin/scratch/cert-manager.license bin/scratch/cert-manager.licenses_notice bin/release-version | bin/containers bin/scratch/containers/cert-manager-acmesolver-linux-%
	$(eval TAG := cert-manager-acmesolver-$*:$(RELEASE_VERSION))
	$(eval BASE := BASE_IMAGE_$(notdir $<))
	$(eval CONTEXT_DIR := bin/scratch/containers/$(notdir $(@:%.tar.gz=%)))
	@cp $< $(CONTEXT_DIR)/acmesolver
	@cp bin/scratch/cert-manager.license bin/scratch/cert-manager.licenses_notice $(CONTEXT_DIR)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.acmesolver \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(CONTEXT_DIR)
	$(CTR) save $(TAG) | gzip > $@

.PHONY: cert-manager-ctl-linux
cert-manager-ctl-linux: bin/containers/cert-manager-ctl-linux-amd64.tar.gz bin/containers/cert-manager-ctl-linux-arm64.tar.gz bin/containers/cert-manager-ctl-linux-s390x.tar.gz bin/containers/cert-manager-ctl-linux-ppc64le.tar.gz bin/containers/cert-manager-ctl-linux-arm.tar.gz

bin/containers/cert-manager-ctl-linux-amd64.tar.gz bin/containers/cert-manager-ctl-linux-arm64.tar.gz bin/containers/cert-manager-ctl-linux-s390x.tar.gz bin/containers/cert-manager-ctl-linux-ppc64le.tar.gz bin/containers/cert-manager-ctl-linux-arm.tar.gz: bin/containers/cert-manager-ctl-linux-%.tar.gz: bin/cmctl/cmctl-linux-% hack/containers/Containerfile.ctl bin/scratch/cert-manager.license bin/scratch/cert-manager.licenses_notice bin/release-version | bin/containers bin/scratch/containers/cert-manager-ctl-linux-%
	$(eval TAG := cert-manager-ctl-$*:$(RELEASE_VERSION))
	$(eval BASE := BASE_IMAGE_$(notdir $<))
	$(eval CONTEXT_DIR := bin/scratch/containers/$(notdir $(@:%.tar.gz=%)))
	@cp $< $(CONTEXT_DIR)/ctl
	@cp bin/scratch/cert-manager.license bin/scratch/cert-manager.licenses_notice $(CONTEXT_DIR)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.ctl \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(CONTEXT_DIR)
	$(CTR) save $(TAG) | gzip > $@


$(foreach arch,amd64 arm64 s390x ppc64le arm,$(foreach bin,controller acmesolver cainjector webhook ctl, bin/scratch/containers/cert-manager-$(bin)-linux-$(arch))):
	@mkdir -p $@
