## Set this as an environment variable to enable signing commands using cmrel.
## Format should be:
## projects/<project>/locations/<location>/keyRings/<keyring>/cryptoKeys/<keyname>/cryptoKeyVersions/<keyversion>
##
## @category Release
CMREL_KEY ?=

.PHONY: release-artifacts
# Build all release artifacts which might be run or used locally, except
# for anything signed.
release-artifacts: server-binaries cmctl kubectl-cert_manager helm-chart release-container-bundles release-manifests

.PHONY: release-artifacts-signed
# Same as `release`, except it also signs the Helm chart. Requires CMREL_KEY
# to be configured.
release-artifacts-signed: release-artifacts
	$(MAKE) --no-print-directory helm-chart-signature

.PHONY: release
## Create a full release ready to be staged, including containers bundled for
## distribution. Requires CMREL_KEY to be configured.
##
## @category Release
release: release-artifacts-signed
	$(MAKE) --no-print-directory bin/release/metadata.json

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
