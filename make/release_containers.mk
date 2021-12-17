.PHONY: release-containers
release-containers: release-container-bundles release-container-metadata

.PHONY: release-container-bundles
release-container-bundles: bin/release/cert-manager-server-linux-amd64.tar.gz bin/release/cert-manager-server-linux-arm64.tar.gz bin/release/cert-manager-server-linux-s390x.tar.gz bin/release/cert-manager-server-linux-ppc64le.tar.gz bin/release/cert-manager-server-linux-arm.tar.gz

bin/release/cert-manager-server-linux-amd64.tar.gz bin/release/cert-manager-server-linux-arm64.tar.gz bin/release/cert-manager-server-linux-s390x.tar.gz bin/release/cert-manager-server-linux-ppc64le.tar.gz bin/release/cert-manager-server-linux-arm.tar.gz: bin/release/cert-manager-server-linux-%.tar.gz: bin/containers/cert-manager-acmesolver-linux-%.tar.gz bin/containers/cert-manager-cainjector-linux-%.tar.gz bin/containers/cert-manager-controller-linux-%.tar.gz bin/containers/cert-manager-webhook-linux-%.tar.gz bin/containers/cert-manager-ctl-linux-%.tar.gz bin/scratch/cert-manager.license | bin/release bin/scratch
	@# use basename twice to strip both "tar" and "gz"
	$(eval CTR_BASENAME := $(basename $(basename $(notdir $@))))
	$(eval CTR_SCRATCHDIR := bin/scratch/release-container-bundle/$(CTR_BASENAME))
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
