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
cert-manager-controller-linux: $(BINDIR)/containers/cert-manager-controller-linux-amd64.tar.gz $(BINDIR)/containers/cert-manager-controller-linux-arm64.tar.gz $(BINDIR)/containers/cert-manager-controller-linux-s390x.tar.gz $(BINDIR)/containers/cert-manager-controller-linux-ppc64le.tar.gz $(BINDIR)/containers/cert-manager-controller-linux-arm.tar.gz

$(BINDIR)/containers/cert-manager-controller-linux-amd64.tar $(BINDIR)/containers/cert-manager-controller-linux-arm64.tar $(BINDIR)/containers/cert-manager-controller-linux-s390x.tar $(BINDIR)/containers/cert-manager-controller-linux-ppc64le.tar $(BINDIR)/containers/cert-manager-controller-linux-arm.tar: $(BINDIR)/containers/cert-manager-controller-linux-%.tar: $(BINDIR)/scratch/build-context/cert-manager-controller-linux-%/controller hack/containers/Containerfile.controller $(BINDIR)/scratch/build-context/cert-manager-controller-linux-%/cert-manager.license $(BINDIR)/scratch/build-context/cert-manager-controller-linux-%/cert-manager.licenses_notice $(BINDIR)/release-version | $(BINDIR)/containers
	@$(eval TAG := cert-manager-controller-$*:$(RELEASE_VERSION))
	@$(eval BASE := BASE_IMAGE_controller-linux-$*)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.controller \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(dir $<) >/dev/null
	$(CTR) save $(TAG) -o $@ >/dev/null

.PHONY: cert-manager-webhook-linux
cert-manager-webhook-linux: $(BINDIR)/containers/cert-manager-webhook-linux-amd64.tar.gz $(BINDIR)/containers/cert-manager-webhook-linux-arm64.tar.gz $(BINDIR)/containers/cert-manager-webhook-linux-s390x.tar.gz $(BINDIR)/containers/cert-manager-webhook-linux-ppc64le.tar.gz $(BINDIR)/containers/cert-manager-webhook-linux-arm.tar.gz

$(BINDIR)/containers/cert-manager-webhook-linux-amd64.tar $(BINDIR)/containers/cert-manager-webhook-linux-arm64.tar $(BINDIR)/containers/cert-manager-webhook-linux-s390x.tar $(BINDIR)/containers/cert-manager-webhook-linux-ppc64le.tar $(BINDIR)/containers/cert-manager-webhook-linux-arm.tar: $(BINDIR)/containers/cert-manager-webhook-linux-%.tar: $(BINDIR)/scratch/build-context/cert-manager-webhook-linux-%/webhook hack/containers/Containerfile.webhook $(BINDIR)/scratch/build-context/cert-manager-webhook-linux-%/cert-manager.license $(BINDIR)/scratch/build-context/cert-manager-webhook-linux-%/cert-manager.licenses_notice $(BINDIR)/release-version | $(BINDIR)/containers
	@$(eval TAG := cert-manager-webhook-$*:$(RELEASE_VERSION))
	@$(eval BASE := BASE_IMAGE_webhook-linux-$*)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.webhook \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(dir $<) >/dev/null
	$(CTR) save $(TAG) -o $@ >/dev/null

.PHONY: cert-manager-cainjector-linux
cert-manager-cainjector-linux: $(BINDIR)/containers/cert-manager-cainjector-linux-amd64.tar.gz $(BINDIR)/containers/cert-manager-cainjector-linux-arm64.tar.gz $(BINDIR)/containers/cert-manager-cainjector-linux-s390x.tar.gz $(BINDIR)/containers/cert-manager-cainjector-linux-ppc64le.tar.gz $(BINDIR)/containers/cert-manager-cainjector-linux-arm.tar.gz

$(BINDIR)/containers/cert-manager-cainjector-linux-amd64.tar $(BINDIR)/containers/cert-manager-cainjector-linux-arm64.tar $(BINDIR)/containers/cert-manager-cainjector-linux-s390x.tar $(BINDIR)/containers/cert-manager-cainjector-linux-ppc64le.tar $(BINDIR)/containers/cert-manager-cainjector-linux-arm.tar: $(BINDIR)/containers/cert-manager-cainjector-linux-%.tar: $(BINDIR)/scratch/build-context/cert-manager-cainjector-linux-%/cainjector hack/containers/Containerfile.cainjector $(BINDIR)/scratch/build-context/cert-manager-cainjector-linux-%/cert-manager.license $(BINDIR)/scratch/build-context/cert-manager-cainjector-linux-%/cert-manager.licenses_notice $(BINDIR)/release-version | $(BINDIR)/containers
	@$(eval TAG := cert-manager-cainjector-$*:$(RELEASE_VERSION))
	@$(eval BASE := BASE_IMAGE_cainjector-linux-$*)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.cainjector \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(dir $<) >/dev/null
	$(CTR) save $(TAG) -o $@ >/dev/null

.PHONY: cert-manager-acmesolver-linux
cert-manager-acmesolver-linux: $(BINDIR)/containers/cert-manager-acmesolver-linux-amd64.tar.gz $(BINDIR)/containers/cert-manager-acmesolver-linux-arm64.tar.gz $(BINDIR)/containers/cert-manager-acmesolver-linux-s390x.tar.gz $(BINDIR)/containers/cert-manager-acmesolver-linux-ppc64le.tar.gz $(BINDIR)/containers/cert-manager-acmesolver-linux-arm.tar.gz

$(BINDIR)/containers/cert-manager-acmesolver-linux-amd64.tar $(BINDIR)/containers/cert-manager-acmesolver-linux-arm64.tar $(BINDIR)/containers/cert-manager-acmesolver-linux-s390x.tar $(BINDIR)/containers/cert-manager-acmesolver-linux-ppc64le.tar $(BINDIR)/containers/cert-manager-acmesolver-linux-arm.tar: $(BINDIR)/containers/cert-manager-acmesolver-linux-%.tar: $(BINDIR)/scratch/build-context/cert-manager-acmesolver-linux-%/acmesolver hack/containers/Containerfile.acmesolver $(BINDIR)/scratch/build-context/cert-manager-acmesolver-linux-%/cert-manager.license $(BINDIR)/scratch/build-context/cert-manager-acmesolver-linux-%/cert-manager.licenses_notice $(BINDIR)/release-version | $(BINDIR)/containers
	@$(eval TAG := cert-manager-acmesolver-$*:$(RELEASE_VERSION))
	@$(eval BASE := BASE_IMAGE_acmesolver-linux-$*)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.acmesolver \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(dir $<) >/dev/null
	$(CTR) save $(TAG) -o $@ >/dev/null

.PHONY: cert-manager-ctl-linux
cert-manager-ctl-linux: $(BINDIR)/containers/cert-manager-ctl-linux-amd64.tar.gz $(BINDIR)/containers/cert-manager-ctl-linux-arm64.tar.gz $(BINDIR)/containers/cert-manager-ctl-linux-s390x.tar.gz $(BINDIR)/containers/cert-manager-ctl-linux-ppc64le.tar.gz $(BINDIR)/containers/cert-manager-ctl-linux-arm.tar.gz

$(foreach arch,$(ARCHS),$(BINDIR)/containers/cert-manager-ctl-linux-$(arch).tar): $(BINDIR)/containers/cert-manager-ctl-linux-%.tar: $(BINDIR)/scratch/build-context/cert-manager-ctl-linux-%/ctl hack/containers/Containerfile.ctl $(BINDIR)/scratch/build-context/cert-manager-ctl-linux-%/cert-manager.license $(BINDIR)/scratch/build-context/cert-manager-ctl-linux-%/cert-manager.licenses_notice $(BINDIR)/release-version | $(BINDIR)/containers
	@$(eval TAG := cert-manager-ctl-$*:$(RELEASE_VERSION))
	@$(eval BASE := BASE_IMAGE_cmctl-linux-$*)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.ctl \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(dir $<) >/dev/null
	$(CTR) save $(TAG) -o $@ >/dev/null

# At first, we used .INTERMEDIATE to remove the intermediate .tar files.
# But it meant "make install" would always have to rebuild
# the tar files.
$(BINDIR)/containers/cert-manager-%.tar.gz: $(BINDIR)/containers/cert-manager-%.tar
	gzip -c $< > $@

$(BINDIR)/containers:
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
# be a problem since the $(BINDIR)/ folder is entirely managed by make.

$(foreach arch,$(ARCHS),$(foreach bin,$(BINS), $(BINDIR)/scratch/build-context/cert-manager-$(bin)-linux-$(arch))):
	@mkdir -p $@

$(BINDIR)/scratch/build-context/cert-manager-%/cert-manager.license: $(BINDIR)/scratch/cert-manager.license | $(BINDIR)/scratch/build-context/cert-manager-%
	@ln -f $< $@

$(BINDIR)/scratch/build-context/cert-manager-%/cert-manager.licenses_notice: $(BINDIR)/scratch/cert-manager.licenses_notice | $(BINDIR)/scratch/build-context/cert-manager-%
	@ln -f $< $@

$(BINDIR)/scratch/build-context/cert-manager-%/controller $(BINDIR)/scratch/build-context/cert-manager-%/acmesolver $(BINDIR)/scratch/build-context/cert-manager-%/cainjector $(BINDIR)/scratch/build-context/cert-manager-%/webhook: $(BINDIR)/server/% | $(BINDIR)/scratch/build-context/cert-manager-%
	@ln -f $< $@

$(BINDIR)/scratch/build-context/cert-manager-ctl-%/ctl: $(BINDIR)/cmctl/cmctl-% | $(BINDIR)/scratch/build-context/cert-manager-ctl-%
	@ln -f $< $@
