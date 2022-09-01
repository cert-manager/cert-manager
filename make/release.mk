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
release-artifacts: server-binaries cmctl kubectl-cert_manager helm-chart release-containers release-manifests

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
	$(MAKE) --no-print-directory $(BINDIR)/release/metadata.json

.PHONY: upload-release
## Create a complete release and then upload it to a target GCS bucket specified by
## RELEASE_TARGET_BUCKET
##
## @category Release
upload-release: release | $(NEEDS_RCLONE)
ifeq ($(strip $(RELEASE_TARGET_BUCKET)),)
	$(error Trying to upload-release but RELEASE_TARGET_BUCKET is empty)
endif
	$(RCLONE) copyto ./$(BINDIR)/release :gcs:$(RELEASE_TARGET_BUCKET)/stage/gcb/release/$(RELEASE_VERSION)

# Takes all metadata files in $(BINDIR)/metadata and combines them into one.

$(BINDIR)/release/metadata.json: $(wildcard $(BINDIR)/metadata/*.json) | $(BINDIR)/release
	jq -n \
		--arg releaseVersion "$(RELEASE_VERSION)" \
		--arg buildSource "make" \
		--arg gitCommitRef "$(GITCOMMIT)" \
		'.releaseVersion = $$releaseVersion | .gitCommitRef = $$gitCommitRef | .buildSource = $$buildSource | .artifacts += [inputs]' $^ > $@

.PHONY: release-containers
release-containers: release-container-bundles release-container-metadata

.PHONY: release-container-bundles
release-container-bundles: $(BINDIR)/release/cert-manager-server-linux-amd64.tar.gz $(BINDIR)/release/cert-manager-server-linux-arm64.tar.gz $(BINDIR)/release/cert-manager-server-linux-s390x.tar.gz $(BINDIR)/release/cert-manager-server-linux-ppc64le.tar.gz $(BINDIR)/release/cert-manager-server-linux-arm.tar.gz

$(BINDIR)/release/cert-manager-server-linux-amd64.tar.gz $(BINDIR)/release/cert-manager-server-linux-arm64.tar.gz $(BINDIR)/release/cert-manager-server-linux-s390x.tar.gz $(BINDIR)/release/cert-manager-server-linux-ppc64le.tar.gz $(BINDIR)/release/cert-manager-server-linux-arm.tar.gz: $(BINDIR)/release/cert-manager-server-linux-%.tar.gz: $(BINDIR)/containers/cert-manager-acmesolver-linux-%.tar.gz $(BINDIR)/containers/cert-manager-cainjector-linux-%.tar.gz $(BINDIR)/containers/cert-manager-controller-linux-%.tar.gz $(BINDIR)/containers/cert-manager-webhook-linux-%.tar.gz $(BINDIR)/containers/cert-manager-ctl-linux-%.tar.gz $(BINDIR)/scratch/cert-manager.license | $(BINDIR)/release $(BINDIR)/scratch
	@# use basename twice to strip both "tar" and "gz"
	@$(eval CTR_BASENAME := $(basename $(basename $(notdir $@))))
	@$(eval CTR_SCRATCHDIR := $(BINDIR)/scratch/release-container-bundle/$(CTR_BASENAME))
	mkdir -p $(CTR_SCRATCHDIR)/server/images
	echo "$(RELEASE_VERSION)" > $(CTR_SCRATCHDIR)/version
	echo "$(RELEASE_VERSION)" > $(CTR_SCRATCHDIR)/server/images/acmesolver.docker_tag
	echo "$(RELEASE_VERSION)" > $(CTR_SCRATCHDIR)/server/images/cainjector.docker_tag
	echo "$(RELEASE_VERSION)" > $(CTR_SCRATCHDIR)/server/images/controller.docker_tag
	echo "$(RELEASE_VERSION)" > $(CTR_SCRATCHDIR)/server/images/webhook.docker_tag
	echo "$(RELEASE_VERSION)" > $(CTR_SCRATCHDIR)/server/images/ctl.docker_tag
	cp $(BINDIR)/scratch/cert-manager.license $(CTR_SCRATCHDIR)/LICENSES
	gunzip -c $(BINDIR)/containers/cert-manager-acmesolver-linux-$*.tar.gz >$(CTR_SCRATCHDIR)/server/images/acmesolver.tar
	gunzip -c $(BINDIR)/containers/cert-manager-cainjector-linux-$*.tar.gz >$(CTR_SCRATCHDIR)/server/images/cainjector.tar
	gunzip -c $(BINDIR)/containers/cert-manager-controller-linux-$*.tar.gz >$(CTR_SCRATCHDIR)/server/images/controller.tar
	gunzip -c $(BINDIR)/containers/cert-manager-webhook-linux-$*.tar.gz >$(CTR_SCRATCHDIR)/server/images/webhook.tar
	gunzip -c $(BINDIR)/containers/cert-manager-ctl-linux-$*.tar.gz >$(CTR_SCRATCHDIR)/server/images/ctl.tar
	chmod -R 755 $(CTR_SCRATCHDIR)/server/images/*
	tar czf $@ -C $(BINDIR)/scratch/release-container-bundle $(CTR_BASENAME)
	rm -rf $(CTR_SCRATCHDIR)

.PHONY: release-container-metadata
release-container-metadata: $(BINDIR)/metadata/cert-manager-server-linux-amd64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-server-linux-arm64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-server-linux-s390x.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-server-linux-ppc64le.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-server-linux-arm.tar.gz.metadata.json

$(BINDIR)/metadata/cert-manager-server-linux-amd64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-server-linux-arm64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-server-linux-s390x.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-server-linux-ppc64le.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-server-linux-arm.tar.gz.metadata.json: $(BINDIR)/metadata/cert-manager-server-linux-%.tar.gz.metadata.json: $(BINDIR)/release/cert-manager-server-linux-%.tar.gz hack/artifact-metadata.template.json | $(BINDIR)/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "linux" \
		--arg architecture "$*" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@

# This target allows us to set all the modified times for all files in bin to the same time, which
# is similar to what bazel does. We might not want this, and it's not currently used.
.PHONY: forcetime
forcetime: | $(BINDIR)
	find $(BINDIR) | xargs touch -d "2000-01-01 00:00:00" -

$(BINDIR)/release $(BINDIR)/metadata:
	@mkdir -p $@

# Example of how we can generate a SHA256SUMS file and sign it using cosign
#$(BINDIR)/SHA256SUMS: $(wildcard ...)
#	@# The patsubst means "all dependencies, but with "$(BINDIR)/" trimmed off the beginning
#	@# We cd into bin so that SHA256SUMS file doesn't have a prefix of `bin` on everything
#	cd $(dir $@) && sha256sum $(patsubst $(BINDIR)/%,%,$^) > $(notdir $@)

#$(BINDIR)/SHA256SUMS.sig: $(BINDIR)/SHA256SUMS | $(NEEDS_COSIGN)
#	$(COSIGN) sign-blob --key $(COSIGN_KEY) $< > $@
