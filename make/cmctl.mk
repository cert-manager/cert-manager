CMCTL_GOLDFLAGS := $(GOLDFLAGS) -X "github.com/cert-manager/cert-manager/cmd/ctl/pkg/build.name=cmctl" -X "github.com/cert-manager/cert-manager/cmd/ctl/pkg/build/commands.registerCompletion=true"

KUBECTL_PLUGIN_GOLDFLAGS := $(GOLDFLAGS) -X "github.com/cert-manager/cert-manager/cmd/ctl/pkg/build.name=kubectl cert-manager" -X "github.com/cert-manager/cert-manager/cmd/ctl/pkg/build/commands.registerCompletion=false"

$(BINDIR)/cmctl:
	@mkdir -p $@

$(BINDIR)/kubectl-cert_manager:
	@mkdir -p $@

.PHONY: cmctl
cmctl: cmctl-linux cmctl-linux-tarballs cmctl-linux-metadata cmctl-darwin cmctl-darwin-tarballs cmctl-darwin-metadata cmctl-windows cmctl-windows-tarballs cmctl-windows-metadata | $(BINDIR)/cmctl

.PHONY: cmctl-linux
cmctl-linux: $(BINDIR)/cmctl/cmctl-linux-amd64 $(BINDIR)/cmctl/cmctl-linux-arm64 $(BINDIR)/cmctl/cmctl-linux-s390x $(BINDIR)/cmctl/cmctl-linux-ppc64le $(BINDIR)/cmctl/cmctl-linux-arm | $(BINDIR)/cmctl

.PHONY: cmctl-linux-tarballs
cmctl-linux-tarballs: $(BINDIR)/release/cert-manager-cmctl-linux-amd64.tar.gz $(BINDIR)/release/cert-manager-cmctl-linux-arm64.tar.gz $(BINDIR)/release/cert-manager-cmctl-linux-s390x.tar.gz $(BINDIR)/release/cert-manager-cmctl-linux-ppc64le.tar.gz $(BINDIR)/release/cert-manager-cmctl-linux-arm.tar.gz | $(BINDIR)/release

.PHONY: cmctl-linux-metadata
cmctl-linux-metadata: $(BINDIR)/metadata/cert-manager-cmctl-linux-amd64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-cmctl-linux-arm64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-cmctl-linux-s390x.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-cmctl-linux-ppc64le.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-cmctl-linux-arm.tar.gz.metadata.json | $(BINDIR)/metadata

$(BINDIR)/cmctl/cmctl-linux-amd64 $(BINDIR)/cmctl/cmctl-linux-arm64 $(BINDIR)/cmctl/cmctl-linux-s390x $(BINDIR)/cmctl/cmctl-linux-ppc64le: $(BINDIR)/cmctl/cmctl-linux-%: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/cmctl
	GOOS=linux GOARCH=$* $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(CMCTL_GOLDFLAGS)' cmd/ctl/main.go

$(BINDIR)/cmctl/cmctl-linux-arm: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/cmctl
	GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(CMCTL_GOLDFLAGS)' cmd/ctl/main.go

$(BINDIR)/release/cert-manager-cmctl-linux-amd64.tar.gz $(BINDIR)/release/cert-manager-cmctl-linux-arm64.tar.gz $(BINDIR)/release/cert-manager-cmctl-linux-s390x.tar.gz $(BINDIR)/release/cert-manager-cmctl-linux-ppc64le.tar.gz $(BINDIR)/release/cert-manager-cmctl-linux-arm.tar.gz: $(BINDIR)/release/cert-manager-cmctl-linux-%.tar.gz: $(BINDIR)/cmctl/cmctl-linux-% $(BINDIR)/scratch/cert-manager.license | $(BINDIR)/scratch $(BINDIR)/release
	@$(eval TARDIR := $(BINDIR)/scratch/$(notdir $@))
	mkdir -p $(TARDIR)
	cp $< $(TARDIR)/cmctl
	cp $(BINDIR)/scratch/cert-manager.license $(TARDIR)/LICENSE
	# removes leading ./ from archived paths
	find $(TARDIR) -maxdepth 1 -mindepth 1 | sed 's|.*/||' | tar czf $@ -C $(TARDIR) -T -
	rm -rf $(TARDIR)

$(BINDIR)/metadata/cert-manager-cmctl-linux-amd64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-cmctl-linux-arm64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-cmctl-linux-s390x.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-cmctl-linux-ppc64le.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-cmctl-linux-arm.tar.gz.metadata.json: $(BINDIR)/metadata/cert-manager-cmctl-linux-%.tar.gz.metadata.json: $(BINDIR)/release/cert-manager-cmctl-linux-%.tar.gz hack/artifact-metadata.template.json | $(BINDIR)/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "linux" \
		--arg architecture "$*" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@

.PHONY: cmctl-darwin
cmctl-darwin: $(BINDIR)/cmctl/cmctl-darwin-amd64 $(BINDIR)/cmctl/cmctl-darwin-arm64 | $(BINDIR)/cmctl

.PHONY: cmctl-darwin-tarballs
cmctl-darwin-tarballs: $(BINDIR)/release/cert-manager-cmctl-darwin-amd64.tar.gz $(BINDIR)/release/cert-manager-cmctl-darwin-arm64.tar.gz | $(BINDIR)/release

.PHONY: cmctl-darwin-metadata
cmctl-darwin-metadata: $(BINDIR)/metadata/cert-manager-cmctl-darwin-amd64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-cmctl-darwin-arm64.tar.gz.metadata.json | $(BINDIR)/metadata

$(BINDIR)/cmctl/cmctl-darwin-amd64 $(BINDIR)/cmctl/cmctl-darwin-arm64:  $(BINDIR)/cmctl/cmctl-darwin-%: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/cmctl
	GOOS=darwin GOARCH=$* $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(CMCTL_GOLDFLAGS)' cmd/ctl/main.go

$(BINDIR)/release/cert-manager-cmctl-darwin-amd64.tar.gz $(BINDIR)/release/cert-manager-cmctl-darwin-arm64.tar.gz: $(BINDIR)/release/cert-manager-cmctl-darwin-%.tar.gz:  $(BINDIR)/cmctl/cmctl-darwin-% $(BINDIR)/scratch/cert-manager.license | $(BINDIR)/scratch $(BINDIR)/release
	@$(eval TARDIR := $(BINDIR)/scratch/$(notdir $@))
	mkdir -p $(TARDIR)
	cp $< $(TARDIR)/cmctl
	cp $(BINDIR)/scratch/cert-manager.license $(TARDIR)/LICENSE
	# removes leading ./ from archived paths
	find $(TARDIR) -maxdepth 1 -mindepth 1 | sed 's|.*/||' | tar czf $@ -C $(TARDIR) -T -
	rm -rf $(TARDIR)

$(BINDIR)/metadata/cert-manager-cmctl-darwin-amd64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-cmctl-darwin-arm64.tar.gz.metadata.json: $(BINDIR)/metadata/cert-manager-cmctl-darwin-%.tar.gz.metadata.json: $(BINDIR)/release/cert-manager-cmctl-darwin-%.tar.gz hack/artifact-metadata.template.json | $(BINDIR)/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "darwin" \
		--arg architecture "$*" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@

.PHONY: cmctl-windows
cmctl-windows: $(BINDIR)/cmctl/cmctl-windows-amd64.exe | $(BINDIR)/cmctl

.PHONY: cmctl-windows-tarballs
cmctl-windows-tarballs: $(BINDIR)/release/cert-manager-cmctl-windows-amd64.tar.gz $(BINDIR)/release/cert-manager-cmctl-windows-amd64.zip | $(BINDIR)/release

.PHONY: cmctl-windows-metadata
cmctl-windows-metadata: $(BINDIR)/metadata/cert-manager-cmctl-windows-amd64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-cmctl-windows-amd64.zip.metadata.json | $(BINDIR)/release

$(BINDIR)/cmctl/cmctl-windows-amd64.exe: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/cmctl
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(CMCTL_GOLDFLAGS)' cmd/ctl/main.go

$(BINDIR)/release/cert-manager-cmctl-windows-amd64.zip: $(BINDIR)/cmctl/cmctl-windows-amd64.exe $(BINDIR)/scratch/cert-manager.license | $(BINDIR)/scratch $(BINDIR)/release
	@$(eval TARDIR := $(BINDIR)/scratch/$(notdir $@))
	mkdir -p $(TARDIR)
	cp $< $(TARDIR)/cmctl.exe
	cp $(BINDIR)/scratch/cert-manager.license $(TARDIR)/LICENSE
	pushd $(TARDIR) && zip -r $(notdir $@) . && popd && mv $(TARDIR)/$(notdir $@) $@
	rm -rf $(TARDIR)

$(BINDIR)/release/cert-manager-cmctl-windows-amd64.tar.gz: $(BINDIR)/cmctl/cmctl-windows-amd64.exe $(BINDIR)/scratch/cert-manager.license | $(BINDIR)/scratch $(BINDIR)/release
	@$(eval TARDIR := $(BINDIR)/scratch/$(notdir $@))
	mkdir -p $(TARDIR)
	cp $< $(TARDIR)/cmctl.exe
	cp $(BINDIR)/scratch/cert-manager.license $(TARDIR)/LICENSE
	# removes leading ./ from archived paths
	find $(TARDIR) -maxdepth 1 -mindepth 1 | sed 's|.*/||' | tar czf $@ -C $(TARDIR) -T -
	rm -rf $(TARDIR)

$(BINDIR)/metadata/cert-manager-cmctl-windows-amd64.tar.gz.metadata.json: $(BINDIR)/release/cert-manager-cmctl-windows-amd64.tar.gz hack/artifact-metadata.template.json | $(BINDIR)/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "windows" \
		--arg architecture "amd64" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@

$(BINDIR)/metadata/cert-manager-cmctl-windows-amd64.zip.metadata.json: $(BINDIR)/release/cert-manager-cmctl-windows-amd64.zip hack/artifact-metadata.template.json | $(BINDIR)/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "windows" \
		--arg architecture "amd64" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@

.PHONY: kubectl-cert_manager
kubectl-cert_manager: kubectl-cert_manager-linux kubectl-cert_manager-linux-tarballs kubectl-cert_manager-linux-metadata kubectl-cert_manager-darwin kubectl-cert_manager-darwin-tarballs kubectl-cert_manager-darwin-metadata kubectl-cert_manager-windows kubectl-cert_manager-windows-tarballs kubectl-cert_manager-windows-metadata | $(BINDIR)/kubectl-cert_manager

.PHONY: kubectl-cert_manager-linux
kubectl-cert_manager-linux: $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-linux-amd64 $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-linux-arm64 $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-linux-s390x $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-linux-ppc64le $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-linux-arm | $(BINDIR)/kubectl-cert_manager

.PHONY: kubectl-cert_manager-linux-tarballs
kubectl-cert_manager-linux-tarballs: $(BINDIR)/release/cert-manager-kubectl-cert_manager-linux-amd64.tar.gz $(BINDIR)/release/cert-manager-kubectl-cert_manager-linux-arm64.tar.gz $(BINDIR)/release/cert-manager-kubectl-cert_manager-linux-s390x.tar.gz $(BINDIR)/release/cert-manager-kubectl-cert_manager-linux-ppc64le.tar.gz $(BINDIR)/release/cert-manager-kubectl-cert_manager-linux-arm.tar.gz | $(BINDIR)/release

.PHONY: kubectl-cert_manager-linux-metadata
kubectl-cert_manager-linux-metadata: $(BINDIR)/metadata/cert-manager-kubectl-cert_manager-linux-amd64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-kubectl-cert_manager-linux-arm64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-kubectl-cert_manager-linux-s390x.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-kubectl-cert_manager-linux-ppc64le.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-kubectl-cert_manager-linux-arm.tar.gz.metadata.json | $(BINDIR)/metadata

$(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-linux-amd64 $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-linux-arm64 $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-linux-s390x $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-linux-ppc64le: $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-linux-%: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/kubectl-cert_manager
	GOOS=linux GOARCH=$* $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(KUBECTL_PLUGIN_GOLDFLAGS)' cmd/ctl/main.go

$(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-linux-arm: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/kubectl-cert_manager
	GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(KUBECTL_PLUGIN_GOLDFLAGS)' cmd/ctl/main.go

$(BINDIR)/release/cert-manager-kubectl-cert_manager-linux-amd64.tar.gz $(BINDIR)/release/cert-manager-kubectl-cert_manager-linux-arm64.tar.gz $(BINDIR)/release/cert-manager-kubectl-cert_manager-linux-s390x.tar.gz $(BINDIR)/release/cert-manager-kubectl-cert_manager-linux-ppc64le.tar.gz $(BINDIR)/release/cert-manager-kubectl-cert_manager-linux-arm.tar.gz: $(BINDIR)/release/cert-manager-kubectl-cert_manager-linux-%.tar.gz: $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-linux-% $(BINDIR)/scratch/cert-manager.license | $(BINDIR)/scratch $(BINDIR)/release
	@$(eval TARDIR := $(BINDIR)/scratch/$(notdir $@))
	mkdir -p $(TARDIR)
	cp $< $(TARDIR)/kubectl-cert_manager
	cp $(BINDIR)/scratch/cert-manager.license $(TARDIR)/LICENSE
	# removes leading ./ from archived paths
	find $(TARDIR) -maxdepth 1 -mindepth 1 | sed 's|.*/||' | tar czf $@ -C $(TARDIR) -T -
	rm -rf $(TARDIR)

$(BINDIR)/metadata/cert-manager-kubectl-cert_manager-linux-amd64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-kubectl-cert_manager-linux-arm64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-kubectl-cert_manager-linux-s390x.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-kubectl-cert_manager-linux-ppc64le.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-kubectl-cert_manager-linux-arm.tar.gz.metadata.json: $(BINDIR)/metadata/cert-manager-kubectl-cert_manager-linux-%.tar.gz.metadata.json: $(BINDIR)/release/cert-manager-kubectl-cert_manager-linux-%.tar.gz hack/artifact-metadata.template.json | $(BINDIR)/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "linux" \
		--arg architecture "$*" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@

.PHONY: kubectl-cert_manager-darwin
kubectl-cert_manager-darwin: $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-darwin-amd64 $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-darwin-arm64 | $(BINDIR)/kubectl-cert_manager

.PHONY: kubectl-cert_manager-darwin-tarballs
kubectl-cert_manager-darwin-tarballs: $(BINDIR)/release/cert-manager-kubectl-cert_manager-darwin-amd64.tar.gz $(BINDIR)/release/cert-manager-kubectl-cert_manager-darwin-arm64.tar.gz | $(BINDIR)/release

.PHONY: kubectl-cert_manager-darwin-metadata
kubectl-cert_manager-darwin-metadata: $(BINDIR)/metadata/cert-manager-kubectl-cert_manager-darwin-amd64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-kubectl-cert_manager-darwin-arm64.tar.gz.metadata.json | $(BINDIR)/metadata

$(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-darwin-amd64 $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-darwin-arm64:  $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-darwin-%: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/kubectl-cert_manager
	GOOS=darwin GOARCH=$* $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(KUBECTL_PLUGIN_GOLDFLAGS)' cmd/ctl/main.go

$(BINDIR)/release/cert-manager-kubectl-cert_manager-darwin-amd64.tar.gz $(BINDIR)/release/cert-manager-kubectl-cert_manager-darwin-arm64.tar.gz: $(BINDIR)/release/cert-manager-kubectl-cert_manager-darwin-%.tar.gz:  $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-darwin-% $(BINDIR)/scratch/cert-manager.license | $(BINDIR)/scratch $(BINDIR)/release
	@$(eval TARDIR := $(BINDIR)/scratch/$(notdir $@))
	mkdir -p $(TARDIR)
	cp $< $(TARDIR)/kubectl-cert_manager
	cp $(BINDIR)/scratch/cert-manager.license $(TARDIR)/LICENSE
	# removes leading ./ from archived paths
	find $(TARDIR) -maxdepth 1 -mindepth 1 | sed 's|.*/||' | tar czf $@ -C $(TARDIR) -T -
	rm -rf $(TARDIR)

$(BINDIR)/metadata/cert-manager-kubectl-cert_manager-darwin-amd64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-kubectl-cert_manager-darwin-arm64.tar.gz.metadata.json: $(BINDIR)/metadata/cert-manager-kubectl-cert_manager-darwin-%.tar.gz.metadata.json: $(BINDIR)/release/cert-manager-kubectl-cert_manager-darwin-%.tar.gz hack/artifact-metadata.template.json | $(BINDIR)/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "darwin" \
		--arg architecture "$*" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@

.PHONY: kubectl-cert_manager-windows
kubectl-cert_manager-windows: $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-windows-amd64.exe | $(BINDIR)/kubectl-cert_manager

.PHONY: kubectl-cert_manager-windows-tarballs
kubectl-cert_manager-windows-tarballs: $(BINDIR)/release/cert-manager-kubectl-cert_manager-windows-amd64.tar.gz $(BINDIR)/release/cert-manager-kubectl-cert_manager-windows-amd64.zip | $(BINDIR)/release

.PHONY: kubectl-cert_manager-windows-metadata
kubectl-cert_manager-windows-metadata: $(BINDIR)/metadata/cert-manager-kubectl-cert_manager-windows-amd64.tar.gz.metadata.json $(BINDIR)/metadata/cert-manager-kubectl-cert_manager-windows-amd64.zip.metadata.json | $(BINDIR)/release

$(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-windows-amd64.exe: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/kubectl-cert_manager
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(KUBECTL_PLUGIN_GOLDFLAGS)' cmd/ctl/main.go

$(BINDIR)/release/cert-manager-kubectl-cert_manager-windows-amd64.zip: $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-windows-amd64.exe $(BINDIR)/scratch/cert-manager.license | $(BINDIR)/scratch $(BINDIR)/release
	@$(eval TARDIR := $(BINDIR)/scratch/$(notdir $@))
	mkdir -p $(TARDIR)
	cp $< $(TARDIR)/kubectl-cert_manager.exe
	cp $(BINDIR)/scratch/cert-manager.license $(TARDIR)/LICENSE
	pushd $(TARDIR) && zip -r $(notdir $@) . && popd && mv $(TARDIR)/$(notdir $@) $@
	rm -rf $(TARDIR)

$(BINDIR)/release/cert-manager-kubectl-cert_manager-windows-amd64.tar.gz: $(BINDIR)/kubectl-cert_manager/kubectl-cert_manager-windows-amd64.exe $(BINDIR)/scratch/cert-manager.license | $(BINDIR)/scratch $(BINDIR)/release
	@$(eval TARDIR := $(BINDIR)/scratch/$(notdir $@))
	mkdir -p $(TARDIR)
	cp $< $(TARDIR)/kubectl-cert_manager.exe
	cp $(BINDIR)/scratch/cert-manager.license $(TARDIR)/LICENSE
	# removes leading ./ from archived paths
	find $(TARDIR) -maxdepth 1 -mindepth 1 | sed 's|.*/||' | tar czf $@ -C $(TARDIR) -T -
	rm -rf $(TARDIR)

$(BINDIR)/metadata/cert-manager-kubectl-cert_manager-windows-amd64.tar.gz.metadata.json: $(BINDIR)/release/cert-manager-kubectl-cert_manager-windows-amd64.tar.gz hack/artifact-metadata.template.json | $(BINDIR)/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "windows" \
		--arg architecture "amd64" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@

$(BINDIR)/metadata/cert-manager-kubectl-cert_manager-windows-amd64.zip.metadata.json: $(BINDIR)/release/cert-manager-kubectl-cert_manager-windows-amd64.zip hack/artifact-metadata.template.json | $(BINDIR)/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "windows" \
		--arg architecture "amd64" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@
