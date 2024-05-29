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

## Set this as an environment variable to enable signing commands using cmrel.
## Format should be:
## projects/<project>/locations/<location>/keyRings/<keyring>/cryptoKeys/<keyname>/cryptoKeyVersions/<keyversion>
##
## @category Release
CMREL_KEY ?=

## Set this as an environment variable when uploading a release to GCS. This is generally
## only needed in CI. Should be the name of a GCS bucket.
##
## @category Release
RELEASE_TARGET_BUCKET ?=

.PHONY: release-artifacts
## Build all release artifacts which might be run or used locally, except
## for anything which requires signing. Note that since the manifests bundle
## requires signing, this command will not build the exact cert-manager-manifests.tar.gz
## which would form part of a release, but will instead build an unsigned tarball.
##
## Useful to check that all binaries and manifests on all platforms can be
## built without errors. Not useful for an actual release - instead, use `make release` for that.
##
## @category Release
release-artifacts: server-binaries helm-chart release-containers release-manifests

.PHONY: release-artifacts-signed
# Same as `release-artifacts`, except also signs the Helm chart. Requires CMREL_KEY
# to be configured.
# Note that this doesn't sign containers, since it's tricky to do that before
# a release is staged. Instead we sign them after we push them to a registry.
release-artifacts-signed: release-artifacts release-manifests-signed

.PHONY: release
## Create a complete release ready to be staged, including containers bundled for
## distribution and all signatures.
##
## Since this command signs artifacts, this requires CMREL_KEY to be configured.
## Prefer `make release-artifacts` locally.
##
## @category Release
release: release-artifacts-signed
	$(MAKE) --no-print-directory $(bin_dir)/release/metadata.json

.PHONY: upload-release
## Create a complete release and then upload it to a target GCS bucket specified by
## RELEASE_TARGET_BUCKET
##
## @category Release
upload-release: release | $(NEEDS_RCLONE)
ifeq ($(strip $(RELEASE_TARGET_BUCKET)),)
	$(error Trying to upload-release but RELEASE_TARGET_BUCKET is empty)
endif
	$(RCLONE) --gcs-bucket-policy-only copyto ./$(bin_dir)/release :gcs:$(RELEASE_TARGET_BUCKET)/stage/gcb/release/$(VERSION)

# Takes all metadata files in $(bin_dir)/metadata and combines them into one.

$(bin_dir)/release/metadata.json: $(wildcard $(bin_dir)/metadata/*.json) | $(bin_dir)/release
	jq -n \
		--arg releaseVersion "$(VERSION)" \
		--arg buildSource "make" \
		--arg gitCommitRef "$(GITCOMMIT)" \
		'.releaseVersion = $$releaseVersion | .gitCommitRef = $$gitCommitRef | .buildSource = $$buildSource | .artifacts += [inputs]' $^ > $@

.PHONY: release-containers
release-containers: release-container-bundles release-container-metadata

.PHONY: release-container-bundles
release-container-bundles: $(bin_dir)/release/cert-manager-server-linux-amd64.tar.gz $(bin_dir)/release/cert-manager-server-linux-arm64.tar.gz $(bin_dir)/release/cert-manager-server-linux-s390x.tar.gz $(bin_dir)/release/cert-manager-server-linux-ppc64le.tar.gz $(bin_dir)/release/cert-manager-server-linux-arm.tar.gz

$(bin_dir)/release/cert-manager-server-linux-amd64.tar.gz $(bin_dir)/release/cert-manager-server-linux-arm64.tar.gz $(bin_dir)/release/cert-manager-server-linux-s390x.tar.gz $(bin_dir)/release/cert-manager-server-linux-ppc64le.tar.gz $(bin_dir)/release/cert-manager-server-linux-arm.tar.gz: $(bin_dir)/release/cert-manager-server-linux-%.tar.gz: $(bin_dir)/containers/cert-manager-acmesolver-linux-%.tar.gz $(bin_dir)/containers/cert-manager-cainjector-linux-%.tar.gz $(bin_dir)/containers/cert-manager-controller-linux-%.tar.gz $(bin_dir)/containers/cert-manager-webhook-linux-%.tar.gz $(bin_dir)/containers/cert-manager-startupapicheck-linux-%.tar.gz $(bin_dir)/scratch/cert-manager.license | $(bin_dir)/release $(bin_dir)/scratch
	@# use basename twice to strip both "tar" and "gz"
	@$(eval CTR_BASENAME := $(basename $(basename $(notdir $@))))
	@$(eval CTR_SCRATCHDIR := $(bin_dir)/scratch/release-container-bundle/$(CTR_BASENAME))
	mkdir -p $(CTR_SCRATCHDIR)/server/images
	echo "$(VERSION)" > $(CTR_SCRATCHDIR)/version
	echo "$(VERSION)" > $(CTR_SCRATCHDIR)/server/images/acmesolver.docker_tag
	echo "$(VERSION)" > $(CTR_SCRATCHDIR)/server/images/cainjector.docker_tag
	echo "$(VERSION)" > $(CTR_SCRATCHDIR)/server/images/controller.docker_tag
	echo "$(VERSION)" > $(CTR_SCRATCHDIR)/server/images/webhook.docker_tag
	echo "$(VERSION)" > $(CTR_SCRATCHDIR)/server/images/startupapicheck.docker_tag
	cp $(bin_dir)/scratch/cert-manager.license $(CTR_SCRATCHDIR)/LICENSES
	gunzip -c $(bin_dir)/containers/cert-manager-acmesolver-linux-$*.tar.gz >$(CTR_SCRATCHDIR)/server/images/acmesolver.tar
	gunzip -c $(bin_dir)/containers/cert-manager-cainjector-linux-$*.tar.gz >$(CTR_SCRATCHDIR)/server/images/cainjector.tar
	gunzip -c $(bin_dir)/containers/cert-manager-controller-linux-$*.tar.gz >$(CTR_SCRATCHDIR)/server/images/controller.tar
	gunzip -c $(bin_dir)/containers/cert-manager-webhook-linux-$*.tar.gz >$(CTR_SCRATCHDIR)/server/images/webhook.tar
	gunzip -c $(bin_dir)/containers/cert-manager-startupapicheck-linux-$*.tar.gz >$(CTR_SCRATCHDIR)/server/images/startupapicheck.tar
	chmod -R 755 $(CTR_SCRATCHDIR)/server/images/*
	tar czf $@ -C $(bin_dir)/scratch/release-container-bundle $(CTR_BASENAME)
	rm -rf $(CTR_SCRATCHDIR)

.PHONY: release-container-metadata
release-container-metadata: $(bin_dir)/metadata/cert-manager-server-linux-amd64.tar.gz.metadata.json $(bin_dir)/metadata/cert-manager-server-linux-arm64.tar.gz.metadata.json $(bin_dir)/metadata/cert-manager-server-linux-s390x.tar.gz.metadata.json $(bin_dir)/metadata/cert-manager-server-linux-ppc64le.tar.gz.metadata.json $(bin_dir)/metadata/cert-manager-server-linux-arm.tar.gz.metadata.json

$(bin_dir)/metadata/cert-manager-server-linux-amd64.tar.gz.metadata.json $(bin_dir)/metadata/cert-manager-server-linux-arm64.tar.gz.metadata.json $(bin_dir)/metadata/cert-manager-server-linux-s390x.tar.gz.metadata.json $(bin_dir)/metadata/cert-manager-server-linux-ppc64le.tar.gz.metadata.json $(bin_dir)/metadata/cert-manager-server-linux-arm.tar.gz.metadata.json: $(bin_dir)/metadata/cert-manager-server-linux-%.tar.gz.metadata.json: $(bin_dir)/release/cert-manager-server-linux-%.tar.gz hack/artifact-metadata.template.json | $(bin_dir)/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "linux" \
		--arg architecture "$*" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@

# This target allows us to set all the modified times for all files in bin to the same time, which
# is similar to what bazel does. We might not want this, and it's not currently used.
.PHONY: forcetime
forcetime: | $(bin_dir)
	find $(bin_dir) | xargs touch -d "2000-01-01 00:00:00" -

$(bin_dir)/release $(bin_dir)/metadata:
	@mkdir -p $@

# Example of how we can generate a SHA256SUMS file and sign it using cosign
#$(bin_dir)/SHA256SUMS: $(wildcard ...)
#	@# The patsubst means "all dependencies, but with "$(bin_dir)/" trimmed off the beginning
#	@# We cd into bin so that SHA256SUMS file doesn't have a prefix of `bin` on everything
#	cd $(dir $@) && sha256sum $(patsubst $(bin_dir)/%,%,$^) > $(notdir $@)

#$(bin_dir)/SHA256SUMS.sig: $(bin_dir)/SHA256SUMS | $(NEEDS_COSIGN)
#	$(COSIGN) sign-blob --key $(COSIGN_KEY) $< > $@
