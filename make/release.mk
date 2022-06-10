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
	$(MAKE) --no-print-directory bin/release/metadata.json

.PHONY: upload-release
## Create a complete release and then upload it to a target GCS bucket specified by
## RELEASE_TARGET_BUCKET
##
## @category Release
upload-release: release | bin/tools/rclone
ifeq ($(strip $(RELEASE_TARGET_BUCKET)),)
	$(error Trying to upload-release but RELEASE_TARGET_BUCKET is empty)
endif
	./bin/tools/rclone copyto ./bin/release :gcs:$(RELEASE_TARGET_BUCKET)/stage/gcb/release/$(RELEASE_VERSION)

# Example of how we can generate a SHA256SUMS file and sign it using cosign
#bin/SHA256SUMS: $(wildcard ...)
#	@# The patsubst means "all dependencies, but with "bin/" trimmed off the beginning
#	@# We cd into bin so that SHA256SUMS file doesn't have a prefix of `bin` on everything
#	cd $(dir $@) && sha256sum $(patsubst bin/%,%,$^) > $(notdir $@)

#bin/SHA256SUMS.sig: bin/SHA256SUMS bin/tools/cosign
#	bin/tools/cosign sign-blob --key $(COSIGN_KEY) $< > $@

# Takes all metadata files in bin/metadata and combines them into one.

bin/release/metadata.json: $(wildcard bin/metadata/*.json) | bin/release
	jq -n \
		--arg releaseVersion "$(RELEASE_VERSION)" \
		--arg buildSource "make" \
		--arg gitCommitRef "$(GITCOMMIT)" \
		'.releaseVersion = $$releaseVersion | .gitCommitRef = $$gitCommitRef | .buildSource = $$buildSource | .artifacts += [inputs]' $^ > $@

.PHONY: release-containers
release-containers: release-container-bundles release-container-metadata

.PHONY: release-container-bundles
release-container-bundles: bin/release/cert-manager-server-linux-amd64.tar.gz bin/release/cert-manager-server-linux-arm64.tar.gz bin/release/cert-manager-server-linux-s390x.tar.gz bin/release/cert-manager-server-linux-ppc64le.tar.gz bin/release/cert-manager-server-linux-arm.tar.gz

bin/release/cert-manager-server-linux-amd64.tar.gz bin/release/cert-manager-server-linux-arm64.tar.gz bin/release/cert-manager-server-linux-s390x.tar.gz bin/release/cert-manager-server-linux-ppc64le.tar.gz bin/release/cert-manager-server-linux-arm.tar.gz: bin/release/cert-manager-server-linux-%.tar.gz: bin/containers/cert-manager-acmesolver-linux-%.tar.gz bin/containers/cert-manager-cainjector-linux-%.tar.gz bin/containers/cert-manager-controller-linux-%.tar.gz bin/containers/cert-manager-webhook-linux-%.tar.gz bin/containers/cert-manager-ctl-linux-%.tar.gz bin/scratch/cert-manager.license | bin/release bin/scratch
	@# use basename twice to strip both "tar" and "gz"
	@$(eval CTR_BASENAME := $(basename $(basename $(notdir $@))))
	@$(eval CTR_SCRATCHDIR := bin/scratch/release-container-bundle/$(CTR_BASENAME))
	mkdir -p $(CTR_SCRATCHDIR)/server/images
	echo "$(RELEASE_VERSION)" > $(CTR_SCRATCHDIR)/version
	echo "$(RELEASE_VERSION)" > $(CTR_SCRATCHDIR)/server/images/acmesolver.docker_tag
	echo "$(RELEASE_VERSION)" > $(CTR_SCRATCHDIR)/server/images/cainjector.docker_tag
	echo "$(RELEASE_VERSION)" > $(CTR_SCRATCHDIR)/server/images/controller.docker_tag
	echo "$(RELEASE_VERSION)" > $(CTR_SCRATCHDIR)/server/images/webhook.docker_tag
	echo "$(RELEASE_VERSION)" > $(CTR_SCRATCHDIR)/server/images/ctl.docker_tag
	cp bin/scratch/cert-manager.license $(CTR_SCRATCHDIR)/LICENSES
	gunzip -c bin/containers/cert-manager-acmesolver-linux-$*.tar.gz >$(CTR_SCRATCHDIR)/server/images/acmesolver.tar
	gunzip -c bin/containers/cert-manager-cainjector-linux-$*.tar.gz >$(CTR_SCRATCHDIR)/server/images/cainjector.tar
	gunzip -c bin/containers/cert-manager-controller-linux-$*.tar.gz >$(CTR_SCRATCHDIR)/server/images/controller.tar
	gunzip -c bin/containers/cert-manager-webhook-linux-$*.tar.gz >$(CTR_SCRATCHDIR)/server/images/webhook.tar
	gunzip -c bin/containers/cert-manager-ctl-linux-$*.tar.gz >$(CTR_SCRATCHDIR)/server/images/ctl.tar
	chmod -R 755 $(CTR_SCRATCHDIR)/server/images/*
	tar czf $@ -C bin/scratch/release-container-bundle $(CTR_BASENAME)
	rm -rf $(CTR_SCRATCHDIR)

.PHONY: release-container-metadata
release-container-metadata: bin/metadata/cert-manager-server-linux-amd64.tar.gz.metadata.json bin/metadata/cert-manager-server-linux-arm64.tar.gz.metadata.json bin/metadata/cert-manager-server-linux-s390x.tar.gz.metadata.json bin/metadata/cert-manager-server-linux-ppc64le.tar.gz.metadata.json bin/metadata/cert-manager-server-linux-arm.tar.gz.metadata.json

bin/metadata/cert-manager-server-linux-amd64.tar.gz.metadata.json bin/metadata/cert-manager-server-linux-arm64.tar.gz.metadata.json bin/metadata/cert-manager-server-linux-s390x.tar.gz.metadata.json bin/metadata/cert-manager-server-linux-ppc64le.tar.gz.metadata.json bin/metadata/cert-manager-server-linux-arm.tar.gz.metadata.json: bin/metadata/cert-manager-server-linux-%.tar.gz.metadata.json: bin/release/cert-manager-server-linux-%.tar.gz hack/artifact-metadata.template.json | bin/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "linux" \
		--arg architecture "$*" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@

# This target allows us to set all the modified times for all files in bin to the same time, which
# is similar to what bazel does. We might not want this, and it's not currently used.
.PHONY: forcetime
forcetime: | bin
	find bin | xargs touch -d "2000-01-01 00:00:00" -

bin/release bin/metadata:
	@mkdir -p $@
