# set to "DYNAMIC" to use a dynamic base image
BASE_IMAGE_TYPE:=STATIC

ARCHS = amd64 arm64 s390x ppc64le arm
BINS = controller acmesolver cainjector webhook ctl

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

.PHONY: all-containers
all-containers: cert-manager-controller-linux cert-manager-webhook-linux cert-manager-acmesolver-linux cert-manager-cainjector-linux cert-manager-ctl-linux

.PHONY: cert-manager-controller-linux
cert-manager-controller-linux: bin/containers/cert-manager-controller-linux-amd64.tar.gz bin/containers/cert-manager-controller-linux-arm64.tar.gz bin/containers/cert-manager-controller-linux-s390x.tar.gz bin/containers/cert-manager-controller-linux-ppc64le.tar.gz bin/containers/cert-manager-controller-linux-arm.tar.gz

bin/containers/cert-manager-controller-linux-amd64.tar bin/containers/cert-manager-controller-linux-arm64.tar bin/containers/cert-manager-controller-linux-s390x.tar bin/containers/cert-manager-controller-linux-ppc64le.tar bin/containers/cert-manager-controller-linux-arm.tar: bin/containers/cert-manager-controller-linux-%.tar: bin/scratch/build-context/cert-manager-controller-linux-%/controller hack/containers/Containerfile.controller bin/scratch/build-context/cert-manager-controller-linux-%/cert-manager.license bin/scratch/build-context/cert-manager-controller-linux-%/cert-manager.licenses_notice bin/release-version | bin/containers
	$(eval TAG := cert-manager-controller-$*:$(RELEASE_VERSION))
	$(eval BASE := BASE_IMAGE_controller-linux-$*)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.controller \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(dir $<) >/dev/null
	$(CTR) save $(TAG) -o $@ >/dev/null

.PHONY: cert-manager-webhook-linux
cert-manager-webhook-linux: bin/containers/cert-manager-webhook-linux-amd64.tar.gz bin/containers/cert-manager-webhook-linux-arm64.tar.gz bin/containers/cert-manager-webhook-linux-s390x.tar.gz bin/containers/cert-manager-webhook-linux-ppc64le.tar.gz bin/containers/cert-manager-webhook-linux-arm.tar.gz

bin/containers/cert-manager-webhook-linux-amd64.tar bin/containers/cert-manager-webhook-linux-arm64.tar bin/containers/cert-manager-webhook-linux-s390x.tar bin/containers/cert-manager-webhook-linux-ppc64le.tar bin/containers/cert-manager-webhook-linux-arm.tar: bin/containers/cert-manager-webhook-linux-%.tar: bin/scratch/build-context/cert-manager-webhook-linux-%/webhook hack/containers/Containerfile.webhook bin/scratch/build-context/cert-manager-webhook-linux-%/cert-manager.license bin/scratch/build-context/cert-manager-webhook-linux-%/cert-manager.licenses_notice bin/release-version | bin/containers
	$(eval TAG := cert-manager-webhook-$*:$(RELEASE_VERSION))
	$(eval BASE := BASE_IMAGE_webhook-linux-$*)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.webhook \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(dir $<) >/dev/null
	$(CTR) save $(TAG) -o $@ >/dev/null

.PHONY: cert-manager-cainjector-linux
cert-manager-cainjector-linux: bin/containers/cert-manager-cainjector-linux-amd64.tar.gz bin/containers/cert-manager-cainjector-linux-arm64.tar.gz bin/containers/cert-manager-cainjector-linux-s390x.tar.gz bin/containers/cert-manager-cainjector-linux-ppc64le.tar.gz bin/containers/cert-manager-cainjector-linux-arm.tar.gz

bin/containers/cert-manager-cainjector-linux-amd64.tar bin/containers/cert-manager-cainjector-linux-arm64.tar bin/containers/cert-manager-cainjector-linux-s390x.tar bin/containers/cert-manager-cainjector-linux-ppc64le.tar bin/containers/cert-manager-cainjector-linux-arm.tar: bin/containers/cert-manager-cainjector-linux-%.tar: bin/scratch/build-context/cert-manager-cainjector-linux-%/cainjector hack/containers/Containerfile.cainjector bin/scratch/build-context/cert-manager-cainjector-linux-%/cert-manager.license bin/scratch/build-context/cert-manager-cainjector-linux-%/cert-manager.licenses_notice bin/release-version | bin/containers
	$(eval TAG := cert-manager-cainjector-$*:$(RELEASE_VERSION))
	$(eval BASE := BASE_IMAGE_cainjector-linux-$*)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.cainjector \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(dir $<) >/dev/null
	$(CTR) save $(TAG) -o $@ >/dev/null

.PHONY: cert-manager-acmesolver-linux
cert-manager-acmesolver-linux: bin/containers/cert-manager-acmesolver-linux-amd64.tar.gz bin/containers/cert-manager-acmesolver-linux-arm64.tar.gz bin/containers/cert-manager-acmesolver-linux-s390x.tar.gz bin/containers/cert-manager-acmesolver-linux-ppc64le.tar.gz bin/containers/cert-manager-acmesolver-linux-arm.tar.gz

bin/containers/cert-manager-acmesolver-linux-amd64.tar bin/containers/cert-manager-acmesolver-linux-arm64.tar bin/containers/cert-manager-acmesolver-linux-s390x.tar bin/containers/cert-manager-acmesolver-linux-ppc64le.tar bin/containers/cert-manager-acmesolver-linux-arm.tar: bin/containers/cert-manager-acmesolver-linux-%.tar: bin/scratch/build-context/cert-manager-acmesolver-linux-%/acmesolver hack/containers/Containerfile.acmesolver bin/scratch/build-context/cert-manager-acmesolver-linux-%/cert-manager.license bin/scratch/build-context/cert-manager-acmesolver-linux-%/cert-manager.licenses_notice bin/release-version | bin/containers
	$(eval TAG := cert-manager-acmesolver-$*:$(RELEASE_VERSION))
	$(eval BASE := BASE_IMAGE_acmesolver-linux-$*)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.acmesolver \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(dir $<) >/dev/null
	$(CTR) save $(TAG) -o $@ >/dev/null

.PHONY: cert-manager-ctl-linux
cert-manager-ctl-linux: bin/containers/cert-manager-ctl-linux-amd64.tar.gz bin/containers/cert-manager-ctl-linux-arm64.tar.gz bin/containers/cert-manager-ctl-linux-s390x.tar.gz bin/containers/cert-manager-ctl-linux-ppc64le.tar.gz bin/containers/cert-manager-ctl-linux-arm.tar.gz

$(foreach arch,$(ARCHS),bin/containers/cert-manager-ctl-linux-$(arch).tar): bin/containers/cert-manager-ctl-linux-%.tar: bin/scratch/build-context/cert-manager-ctl-linux-%/ctl hack/containers/Containerfile.ctl bin/scratch/build-context/cert-manager-ctl-linux-%/cert-manager.license bin/scratch/build-context/cert-manager-ctl-linux-%/cert-manager.licenses_notice bin/release-version | bin/containers
	$(eval TAG := cert-manager-ctl-$*:$(RELEASE_VERSION))
	$(eval BASE := BASE_IMAGE_cmctl-linux-$*)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.ctl \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(dir $<) >/dev/null
	$(CTR) save $(TAG) -o $@ >/dev/null

.INTERMEDIATE: $(foreach arch,$(ARCHS),$(foreach bin,$(BINS),bin/containers/cert-manager-$(bin)-linux-$(arch).tar)) bin/containers/cert-manager-webhook-linux-amd64.tar.gz
bin/containers/cert-manager-%.tar.gz: bin/containers/cert-manager-%.tar
	gzip -c $< > $@

bin/containers:
	@mkdir -p $@

# When running "docker build .", the "build context" was getting too big (1.1 GB
# when all binaries for all archs are built). Even with a very strict
# .dockerignore, each "docker build" command would last for more than 10 seconds
# each due to the copying happening. To avoid that, we set a different folder
# for each "docker build" command, which reduces the copying to ~50 MB per
# "docker build".
#
# Note that we can't use symlinks in the build context. In order to avoid the
# cost of multiple copies of the same binary, we use hard links which shouldn't
# be a problem since the bin/ folder is entirely managed by make.

$(foreach arch,$(ARCHS),$(foreach bin,$(BINS), bin/scratch/build-context/cert-manager-$(bin)-linux-$(arch))):
	@mkdir -p $@

bin/scratch/build-context/cert-manager-%/cert-manager.license: bin/scratch/cert-manager.license | bin/scratch/build-context/cert-manager-%
	@ln -f $< $@

bin/scratch/build-context/cert-manager-%/cert-manager.licenses_notice: bin/scratch/cert-manager.licenses_notice | bin/scratch/build-context/cert-manager-%
	@ln -f $< $@

bin/scratch/build-context/cert-manager-%/controller bin/scratch/build-context/cert-manager-%/acmesolver bin/scratch/build-context/cert-manager-%/cainjector bin/scratch/build-context/cert-manager-%/webhook: bin/server/% | bin/scratch/build-context/cert-manager-%
	@ln -f $< $@

bin/scratch/build-context/cert-manager-ctl-%/ctl: bin/cmctl/cmctl-% | bin/scratch/build-context/cert-manager-ctl-%
	@ln -f $< $@
