# Copyright 2023 The cert-manager Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# set to "DYNAMIC" to use a dynamic base image
BASE_IMAGE_TYPE:=STATIC

ARCHS = amd64 arm64 s390x ppc64le arm
BINS = controller acmesolver cainjector webhook startupapicheck

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

BASE_IMAGE_startupapicheck-linux-amd64:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_amd64)
BASE_IMAGE_startupapicheck-linux-arm64:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_arm64)
BASE_IMAGE_startupapicheck-linux-s390x:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_s390x)
BASE_IMAGE_startupapicheck-linux-ppc64le:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_ppc64le)
BASE_IMAGE_startupapicheck-linux-arm:=$($(BASE_IMAGE_TYPE)_BASE_IMAGE_arm)

.PHONY: all-containers
all-containers: cert-manager-controller-linux cert-manager-webhook-linux cert-manager-acmesolver-linux cert-manager-cainjector-linux cert-manager-startupapicheck-linux

.PHONY: cert-manager-controller-linux
cert-manager-controller-linux: $(bin_dir)/containers/cert-manager-controller-linux-amd64.tar.gz $(bin_dir)/containers/cert-manager-controller-linux-arm64.tar.gz $(bin_dir)/containers/cert-manager-controller-linux-s390x.tar.gz $(bin_dir)/containers/cert-manager-controller-linux-ppc64le.tar.gz $(bin_dir)/containers/cert-manager-controller-linux-arm.tar.gz

$(bin_dir)/containers/cert-manager-controller-linux-amd64.tar $(bin_dir)/containers/cert-manager-controller-linux-arm64.tar $(bin_dir)/containers/cert-manager-controller-linux-s390x.tar $(bin_dir)/containers/cert-manager-controller-linux-ppc64le.tar $(bin_dir)/containers/cert-manager-controller-linux-arm.tar: $(bin_dir)/containers/cert-manager-controller-linux-%.tar: $(bin_dir)/scratch/build-context/cert-manager-controller-linux-%/controller hack/containers/Containerfile.controller $(bin_dir)/scratch/build-context/cert-manager-controller-linux-%/cert-manager.license $(bin_dir)/scratch/build-context/cert-manager-controller-linux-%/cert-manager.licenses_notice $(bin_dir)/release-version | $(bin_dir)/containers
	@$(eval TAG := cert-manager-controller-$*:$(VERSION))
	@$(eval BASE := BASE_IMAGE_controller-linux-$*)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.controller \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(dir $<) >/dev/null
	$(CTR) save $(TAG) -o $@ >/dev/null

.PHONY: cert-manager-webhook-linux
cert-manager-webhook-linux: $(bin_dir)/containers/cert-manager-webhook-linux-amd64.tar.gz $(bin_dir)/containers/cert-manager-webhook-linux-arm64.tar.gz $(bin_dir)/containers/cert-manager-webhook-linux-s390x.tar.gz $(bin_dir)/containers/cert-manager-webhook-linux-ppc64le.tar.gz $(bin_dir)/containers/cert-manager-webhook-linux-arm.tar.gz

$(bin_dir)/containers/cert-manager-webhook-linux-amd64.tar $(bin_dir)/containers/cert-manager-webhook-linux-arm64.tar $(bin_dir)/containers/cert-manager-webhook-linux-s390x.tar $(bin_dir)/containers/cert-manager-webhook-linux-ppc64le.tar $(bin_dir)/containers/cert-manager-webhook-linux-arm.tar: $(bin_dir)/containers/cert-manager-webhook-linux-%.tar: $(bin_dir)/scratch/build-context/cert-manager-webhook-linux-%/webhook hack/containers/Containerfile.webhook $(bin_dir)/scratch/build-context/cert-manager-webhook-linux-%/cert-manager.license $(bin_dir)/scratch/build-context/cert-manager-webhook-linux-%/cert-manager.licenses_notice $(bin_dir)/release-version | $(bin_dir)/containers
	@$(eval TAG := cert-manager-webhook-$*:$(VERSION))
	@$(eval BASE := BASE_IMAGE_webhook-linux-$*)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.webhook \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(dir $<) >/dev/null
	$(CTR) save $(TAG) -o $@ >/dev/null

.PHONY: cert-manager-cainjector-linux
cert-manager-cainjector-linux: $(bin_dir)/containers/cert-manager-cainjector-linux-amd64.tar.gz $(bin_dir)/containers/cert-manager-cainjector-linux-arm64.tar.gz $(bin_dir)/containers/cert-manager-cainjector-linux-s390x.tar.gz $(bin_dir)/containers/cert-manager-cainjector-linux-ppc64le.tar.gz $(bin_dir)/containers/cert-manager-cainjector-linux-arm.tar.gz

$(bin_dir)/containers/cert-manager-cainjector-linux-amd64.tar $(bin_dir)/containers/cert-manager-cainjector-linux-arm64.tar $(bin_dir)/containers/cert-manager-cainjector-linux-s390x.tar $(bin_dir)/containers/cert-manager-cainjector-linux-ppc64le.tar $(bin_dir)/containers/cert-manager-cainjector-linux-arm.tar: $(bin_dir)/containers/cert-manager-cainjector-linux-%.tar: $(bin_dir)/scratch/build-context/cert-manager-cainjector-linux-%/cainjector hack/containers/Containerfile.cainjector $(bin_dir)/scratch/build-context/cert-manager-cainjector-linux-%/cert-manager.license $(bin_dir)/scratch/build-context/cert-manager-cainjector-linux-%/cert-manager.licenses_notice $(bin_dir)/release-version | $(bin_dir)/containers
	@$(eval TAG := cert-manager-cainjector-$*:$(VERSION))
	@$(eval BASE := BASE_IMAGE_cainjector-linux-$*)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.cainjector \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(dir $<) >/dev/null
	$(CTR) save $(TAG) -o $@ >/dev/null

.PHONY: cert-manager-acmesolver-linux
cert-manager-acmesolver-linux: $(bin_dir)/containers/cert-manager-acmesolver-linux-amd64.tar.gz $(bin_dir)/containers/cert-manager-acmesolver-linux-arm64.tar.gz $(bin_dir)/containers/cert-manager-acmesolver-linux-s390x.tar.gz $(bin_dir)/containers/cert-manager-acmesolver-linux-ppc64le.tar.gz $(bin_dir)/containers/cert-manager-acmesolver-linux-arm.tar.gz

$(bin_dir)/containers/cert-manager-acmesolver-linux-amd64.tar $(bin_dir)/containers/cert-manager-acmesolver-linux-arm64.tar $(bin_dir)/containers/cert-manager-acmesolver-linux-s390x.tar $(bin_dir)/containers/cert-manager-acmesolver-linux-ppc64le.tar $(bin_dir)/containers/cert-manager-acmesolver-linux-arm.tar: $(bin_dir)/containers/cert-manager-acmesolver-linux-%.tar: $(bin_dir)/scratch/build-context/cert-manager-acmesolver-linux-%/acmesolver hack/containers/Containerfile.acmesolver $(bin_dir)/scratch/build-context/cert-manager-acmesolver-linux-%/cert-manager.license $(bin_dir)/scratch/build-context/cert-manager-acmesolver-linux-%/cert-manager.licenses_notice $(bin_dir)/release-version | $(bin_dir)/containers
	@$(eval TAG := cert-manager-acmesolver-$*:$(VERSION))
	@$(eval BASE := BASE_IMAGE_acmesolver-linux-$*)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.acmesolver \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(dir $<) >/dev/null
	$(CTR) save $(TAG) -o $@ >/dev/null

.PHONY: cert-manager-startupapicheck-linux
cert-manager-startupapicheck-linux: $(bin_dir)/containers/cert-manager-startupapicheck-linux-amd64.tar.gz $(bin_dir)/containers/cert-manager-startupapicheck-linux-arm64.tar.gz $(bin_dir)/containers/cert-manager-startupapicheck-linux-s390x.tar.gz $(bin_dir)/containers/cert-manager-startupapicheck-linux-ppc64le.tar.gz $(bin_dir)/containers/cert-manager-startupapicheck-linux-arm.tar.gz

$(bin_dir)/containers/cert-manager-startupapicheck-linux-amd64.tar $(bin_dir)/containers/cert-manager-startupapicheck-linux-arm64.tar $(bin_dir)/containers/cert-manager-startupapicheck-linux-s390x.tar $(bin_dir)/containers/cert-manager-startupapicheck-linux-ppc64le.tar $(bin_dir)/containers/cert-manager-startupapicheck-linux-arm.tar: $(bin_dir)/containers/cert-manager-startupapicheck-linux-%.tar: $(bin_dir)/scratch/build-context/cert-manager-startupapicheck-linux-%/startupapicheck hack/containers/Containerfile.startupapicheck $(bin_dir)/scratch/build-context/cert-manager-startupapicheck-linux-%/cert-manager.license $(bin_dir)/scratch/build-context/cert-manager-startupapicheck-linux-%/cert-manager.licenses_notice $(bin_dir)/release-version | $(bin_dir)/containers
	@$(eval TAG := cert-manager-startupapicheck-$*:$(VERSION))
	@$(eval BASE := BASE_IMAGE_startupapicheck-linux-$*)
	$(CTR) build --quiet \
		-f hack/containers/Containerfile.startupapicheck \
		--build-arg BASE_IMAGE=$($(BASE)) \
		-t $(TAG) \
		$(dir $<) >/dev/null
	$(CTR) save $(TAG) -o $@ >/dev/null

# At first, we used .INTERMEDIATE to remove the intermediate .tar files.
# But it meant "make install" would always have to rebuild
# the tar files.
$(bin_dir)/containers/cert-manager-%.tar.gz: $(bin_dir)/containers/cert-manager-%.tar
	gzip -c $< > $@

$(bin_dir)/containers:
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
# be a problem since the $(bin_dir)/ folder is entirely managed by make.

$(foreach arch,$(ARCHS),$(foreach bin,$(BINS), $(bin_dir)/scratch/build-context/cert-manager-$(bin)-linux-$(arch))):
	@mkdir -p $@

$(bin_dir)/scratch/build-context/cert-manager-%/cert-manager.license: $(bin_dir)/scratch/cert-manager.license | $(bin_dir)/scratch/build-context/cert-manager-%
	@ln -f $< $@

$(bin_dir)/scratch/build-context/cert-manager-%/cert-manager.licenses_notice: $(bin_dir)/scratch/cert-manager.licenses_notice | $(bin_dir)/scratch/build-context/cert-manager-%
	@ln -f $< $@

$(bin_dir)/scratch/build-context/cert-manager-%/controller $(bin_dir)/scratch/build-context/cert-manager-%/acmesolver $(bin_dir)/scratch/build-context/cert-manager-%/cainjector $(bin_dir)/scratch/build-context/cert-manager-%/webhook $(bin_dir)/scratch/build-context/cert-manager-%/startupapicheck: $(bin_dir)/server/% | $(bin_dir)/scratch/build-context/cert-manager-%
	@ln -f $< $@
