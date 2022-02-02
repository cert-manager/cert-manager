CMCTL_GOFLAGS=$(GOFLAGS) -ldflags '-X "github.com/cert-manager/cert-manager/cmd/ctl/pkg/build.name=cmctl" -X "github.com/cert-manager/cert-manager/cmd/ctl/pkg/build/commands.registerCompletion=true"'

KUBECTL_PLUGIN_GOFLAGS=$(GOFLAGS) -ldflags '-X "github.com/cert-manager/cert-manager/cmd/ctl/pkg/build.name=kubectl cert-manager" -X "github.com/cert-manager/cert-manager/cmd/ctl/pkg/build/commands.registerCompletion=false"'

bin/cmctl:
	@mkdir -p $@

bin/kubectl-cert_manager:
	@mkdir -p $@

.PHONY: cmctl
cmctl: cmctl-linux cmctl-linux-tarballs cmctl-linux-metadata cmctl-darwin cmctl-darwin-tarballs cmctl-darwin-metadata cmctl-windows cmctl-windows-tarballs cmctl-windows-metadata | bin/cmctl

.PHONY: cmctl-linux
cmctl-linux: bin/cmctl/cmctl-linux-amd64 bin/cmctl/cmctl-linux-arm64 bin/cmctl/cmctl-linux-s390x bin/cmctl/cmctl-linux-ppc64le bin/cmctl/cmctl-linux-arm | bin/cmctl

.PHONY: cmctl-linux-tarballs
cmctl-linux-tarballs: bin/release/cert-manager-cmctl-linux-amd64.tar.gz bin/release/cert-manager-cmctl-linux-arm64.tar.gz bin/release/cert-manager-cmctl-linux-s390x.tar.gz bin/release/cert-manager-cmctl-linux-ppc64le.tar.gz bin/release/cert-manager-cmctl-linux-arm.tar.gz | bin/release

.PHONY: cmctl-linux-metadata
cmctl-linux-metadata: bin/metadata/cert-manager-cmctl-linux-amd64.tar.gz.metadata.json bin/metadata/cert-manager-cmctl-linux-arm64.tar.gz.metadata.json bin/metadata/cert-manager-cmctl-linux-s390x.tar.gz.metadata.json bin/metadata/cert-manager-cmctl-linux-ppc64le.tar.gz.metadata.json bin/metadata/cert-manager-cmctl-linux-arm.tar.gz.metadata.json | bin/metadata

bin/cmctl/cmctl-linux-amd64 bin/cmctl/cmctl-linux-arm64 bin/cmctl/cmctl-linux-s390x bin/cmctl/cmctl-linux-ppc64le: bin/cmctl/cmctl-linux-%: $(SOURCES) | bin/cmctl
	GOOS=linux GOARCH=$* $(GOBUILD) -o $@ $(CMCTL_GOFLAGS) cmd/ctl/main.go

bin/cmctl/cmctl-linux-arm: $(SOURCES) | bin/cmctl
	GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o $@ $(CMCTL_GOFLAGS) cmd/ctl/main.go

bin/release/cert-manager-cmctl-linux-amd64.tar.gz bin/release/cert-manager-cmctl-linux-arm64.tar.gz bin/release/cert-manager-cmctl-linux-s390x.tar.gz bin/release/cert-manager-cmctl-linux-ppc64le.tar.gz bin/release/cert-manager-cmctl-linux-arm.tar.gz: bin/release/cert-manager-cmctl-linux-%.tar.gz: bin/cmctl/cmctl-linux-% bin/scratch/cert-manager.license | bin/scratch bin/release
	$(eval TARDIR := bin/scratch/$(notdir $@))
	mkdir -p $(TARDIR)
	cp $< $(TARDIR)/cmctl
	cp bin/scratch/cert-manager.license $(TARDIR)/LICENSE
	tar czf $@ -C $(TARDIR) .
	rm -rf $(TARDIR)

bin/metadata/cert-manager-cmctl-linux-amd64.tar.gz.metadata.json bin/metadata/cert-manager-cmctl-linux-arm64.tar.gz.metadata.json bin/metadata/cert-manager-cmctl-linux-s390x.tar.gz.metadata.json bin/metadata/cert-manager-cmctl-linux-ppc64le.tar.gz.metadata.json bin/metadata/cert-manager-cmctl-linux-arm.tar.gz.metadata.json: bin/metadata/cert-manager-cmctl-linux-%.tar.gz.metadata.json: bin/release/cert-manager-cmctl-linux-%.tar.gz hack/artifact-metadata.template.json | bin/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "linux" \
		--arg architecture "$*" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@

.PHONY: cmctl-darwin
cmctl-darwin: bin/cmctl/cmctl-darwin-amd64 bin/cmctl/cmctl-darwin-arm64 | bin/cmctl

.PHONY: cmctl-darwin-tarballs
cmctl-darwin-tarballs: bin/release/cert-manager-cmctl-darwin-amd64.tar.gz bin/release/cert-manager-cmctl-darwin-arm64.tar.gz | bin/release

.PHONY: cmctl-darwin-metadata
cmctl-darwin-metadata: bin/metadata/cert-manager-cmctl-darwin-amd64.tar.gz.metadata.json bin/metadata/cert-manager-cmctl-darwin-arm64.tar.gz.metadata.json | bin/metadata

bin/cmctl/cmctl-darwin-amd64 bin/cmctl/cmctl-darwin-arm64:  bin/cmctl/cmctl-darwin-%: $(SOURCES) | bin/cmctl
	GOOS=darwin GOARCH=$* $(GOBUILD) -o $@ $(CMCTL_GOFLAGS) cmd/ctl/main.go

bin/release/cert-manager-cmctl-darwin-amd64.tar.gz bin/release/cert-manager-cmctl-darwin-arm64.tar.gz: bin/release/cert-manager-cmctl-darwin-%.tar.gz:  bin/cmctl/cmctl-darwin-% bin/scratch/cert-manager.license | bin/scratch bin/release
	$(eval TARDIR := bin/scratch/$(notdir $@))
	mkdir -p $(TARDIR)
	cp $< $(TARDIR)/cmctl
	cp bin/scratch/cert-manager.license $(TARDIR)/LICENSE
	tar czf $@ -C $(TARDIR) .
	rm -rf $(TARDIR)

bin/metadata/cert-manager-cmctl-darwin-amd64.tar.gz.metadata.json bin/metadata/cert-manager-cmctl-darwin-arm64.tar.gz.metadata.json: bin/metadata/cert-manager-cmctl-darwin-%.tar.gz.metadata.json: bin/release/cert-manager-cmctl-darwin-%.tar.gz hack/artifact-metadata.template.json | bin/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "darwin" \
		--arg architecture "$*" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@

.PHONY: cmctl-windows
cmctl-windows: bin/cmctl/cmctl-windows-amd64.exe | bin/cmctl

.PHONY: cmctl-windows-tarballs
cmctl-windows-tarballs: bin/release/cert-manager-cmctl-windows-amd64.tar.gz bin/release/cert-manager-cmctl-windows-amd64.zip | bin/release

.PHONY: cmctl-windows-metadata
cmctl-windows-metadata: bin/metadata/cert-manager-cmctl-windows-amd64.tar.gz.metadata.json bin/metadata/cert-manager-cmctl-windows-amd64.zip.metadata.json | bin/release

bin/cmctl/cmctl-windows-amd64.exe: $(SOURCES) | bin/cmctl
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $@ $(CMCTL_GOFLAGS) cmd/ctl/main.go

bin/release/cert-manager-cmctl-windows-amd64.zip: bin/cmctl/cmctl-windows-amd64.exe bin/scratch/cert-manager.license | bin/scratch bin/release
	$(eval TARDIR := bin/scratch/$(notdir $@))
	mkdir -p $(TARDIR)
	cp $< $(TARDIR)/cmctl.exe
	cp bin/scratch/cert-manager.license $(TARDIR)/LICENSE
	pushd $(TARDIR) && zip -r $(notdir $@) . && popd && mv $(TARDIR)/$(notdir $@) $@
	rm -rf $(TARDIR)

bin/release/cert-manager-cmctl-windows-amd64.tar.gz: bin/cmctl/cmctl-windows-amd64.exe bin/scratch/cert-manager.license | bin/scratch bin/release
	$(eval TARDIR := bin/scratch/$(notdir $@))
	mkdir -p $(TARDIR)
	cp $< $(TARDIR)/cmctl.exe
	cp bin/scratch/cert-manager.license $(TARDIR)/LICENSE
	tar czf $@ -C $(TARDIR) .
	rm -rf $(TARDIR)

bin/metadata/cert-manager-cmctl-windows-amd64.tar.gz.metadata.json: bin/release/cert-manager-cmctl-windows-amd64.tar.gz hack/artifact-metadata.template.json | bin/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "windows" \
		--arg architecture "amd64" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@

bin/metadata/cert-manager-cmctl-windows-amd64.zip.metadata.json: bin/release/cert-manager-cmctl-windows-amd64.zip hack/artifact-metadata.template.json | bin/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "windows" \
		--arg architecture "amd64" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@

.PHONY: kubectl-cert_manager
kubectl-cert_manager: kubectl-cert_manager-linux kubectl-cert_manager-linux-tarballs kubectl-cert_manager-linux-metadata kubectl-cert_manager-darwin kubectl-cert_manager-darwin-tarballs kubectl-cert_manager-darwin-metadata kubectl-cert_manager-windows kubectl-cert_manager-windows-tarballs kubectl-cert_manager-windows-metadata | bin/kubectl-cert_manager

.PHONY: kubectl-cert_manager-linux
kubectl-cert_manager-linux: bin/kubectl-cert_manager/kubectl-cert_manager-linux-amd64 bin/kubectl-cert_manager/kubectl-cert_manager-linux-arm64 bin/kubectl-cert_manager/kubectl-cert_manager-linux-s390x bin/kubectl-cert_manager/kubectl-cert_manager-linux-ppc64le bin/kubectl-cert_manager/kubectl-cert_manager-linux-arm | bin/kubectl-cert_manager

.PHONY: kubectl-cert_manager-linux-tarballs
kubectl-cert_manager-linux-tarballs: bin/release/cert-manager-kubectl-cert_manager-linux-amd64.tar.gz bin/release/cert-manager-kubectl-cert_manager-linux-arm64.tar.gz bin/release/cert-manager-kubectl-cert_manager-linux-s390x.tar.gz bin/release/cert-manager-kubectl-cert_manager-linux-ppc64le.tar.gz bin/release/cert-manager-kubectl-cert_manager-linux-arm.tar.gz | bin/release

.PHONY: kubectl-cert_manager-linux-metadata
kubectl-cert_manager-linux-metadata: bin/metadata/cert-manager-kubectl-cert_manager-linux-amd64.tar.gz.metadata.json bin/metadata/cert-manager-kubectl-cert_manager-linux-arm64.tar.gz.metadata.json bin/metadata/cert-manager-kubectl-cert_manager-linux-s390x.tar.gz.metadata.json bin/metadata/cert-manager-kubectl-cert_manager-linux-ppc64le.tar.gz.metadata.json bin/metadata/cert-manager-kubectl-cert_manager-linux-arm.tar.gz.metadata.json | bin/metadata

bin/kubectl-cert_manager/kubectl-cert_manager-linux-amd64 bin/kubectl-cert_manager/kubectl-cert_manager-linux-arm64 bin/kubectl-cert_manager/kubectl-cert_manager-linux-s390x bin/kubectl-cert_manager/kubectl-cert_manager-linux-ppc64le: bin/kubectl-cert_manager/kubectl-cert_manager-linux-%: $(SOURCES) | bin/kubectl-cert_manager
	GOOS=linux GOARCH=$* $(GOBUILD) -o $@ $(KUBECTL_PLUGIN_GOFLAGS) cmd/ctl/main.go

bin/kubectl-cert_manager/kubectl-cert_manager-linux-arm: $(SOURCES) | bin/kubectl-cert_manager
	GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o $@ $(KUBECTL_PLUGIN_GOFLAGS) cmd/ctl/main.go

bin/release/cert-manager-kubectl-cert_manager-linux-amd64.tar.gz bin/release/cert-manager-kubectl-cert_manager-linux-arm64.tar.gz bin/release/cert-manager-kubectl-cert_manager-linux-s390x.tar.gz bin/release/cert-manager-kubectl-cert_manager-linux-ppc64le.tar.gz bin/release/cert-manager-kubectl-cert_manager-linux-arm.tar.gz: bin/release/cert-manager-kubectl-cert_manager-linux-%.tar.gz: bin/kubectl-cert_manager/kubectl-cert_manager-linux-% bin/scratch/cert-manager.license | bin/scratch bin/release
	$(eval TARDIR := bin/scratch/$(notdir $@))
	mkdir -p $(TARDIR)
	cp $< $(TARDIR)/kubectl-cert_manager
	cp bin/scratch/cert-manager.license $(TARDIR)/LICENSE
	tar czf $@ -C $(TARDIR) .
	rm -rf $(TARDIR)

bin/metadata/cert-manager-kubectl-cert_manager-linux-amd64.tar.gz.metadata.json bin/metadata/cert-manager-kubectl-cert_manager-linux-arm64.tar.gz.metadata.json bin/metadata/cert-manager-kubectl-cert_manager-linux-s390x.tar.gz.metadata.json bin/metadata/cert-manager-kubectl-cert_manager-linux-ppc64le.tar.gz.metadata.json bin/metadata/cert-manager-kubectl-cert_manager-linux-arm.tar.gz.metadata.json: bin/metadata/cert-manager-kubectl-cert_manager-linux-%.tar.gz.metadata.json: bin/release/cert-manager-kubectl-cert_manager-linux-%.tar.gz hack/artifact-metadata.template.json | bin/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "linux" \
		--arg architecture "$*" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@

.PHONY: kubectl-cert_manager-darwin
kubectl-cert_manager-darwin: bin/kubectl-cert_manager/kubectl-cert_manager-darwin-amd64 bin/kubectl-cert_manager/kubectl-cert_manager-darwin-arm64 | bin/kubectl-cert_manager

.PHONY: kubectl-cert_manager-darwin-tarballs
kubectl-cert_manager-darwin-tarballs: bin/release/cert-manager-kubectl-cert_manager-darwin-amd64.tar.gz bin/release/cert-manager-kubectl-cert_manager-darwin-arm64.tar.gz | bin/release

.PHONY: kubectl-cert_manager-darwin-metadata
kubectl-cert_manager-darwin-metadata: bin/metadata/cert-manager-kubectl-cert_manager-darwin-amd64.tar.gz.metadata.json bin/metadata/cert-manager-kubectl-cert_manager-darwin-arm64.tar.gz.metadata.json | bin/metadata

bin/kubectl-cert_manager/kubectl-cert_manager-darwin-amd64 bin/kubectl-cert_manager/kubectl-cert_manager-darwin-arm64:  bin/kubectl-cert_manager/kubectl-cert_manager-darwin-%: $(SOURCES) | bin/kubectl-cert_manager
	GOOS=darwin GOARCH=$* $(GOBUILD) -o $@ $(KUBECTL_PLUGIN_GOFLAGS) cmd/ctl/main.go

bin/release/cert-manager-kubectl-cert_manager-darwin-amd64.tar.gz bin/release/cert-manager-kubectl-cert_manager-darwin-arm64.tar.gz: bin/release/cert-manager-kubectl-cert_manager-darwin-%.tar.gz:  bin/kubectl-cert_manager/kubectl-cert_manager-darwin-% bin/scratch/cert-manager.license | bin/scratch bin/release
	$(eval TARDIR := bin/scratch/$(notdir $@))
	mkdir -p $(TARDIR)
	cp $< $(TARDIR)/kubectl-cert_manager
	cp bin/scratch/cert-manager.license $(TARDIR)/LICENSE
	tar czf $@ -C $(TARDIR) .
	rm -rf $(TARDIR)

bin/metadata/cert-manager-kubectl-cert_manager-darwin-amd64.tar.gz.metadata.json bin/metadata/cert-manager-kubectl-cert_manager-darwin-arm64.tar.gz.metadata.json: bin/metadata/cert-manager-kubectl-cert_manager-darwin-%.tar.gz.metadata.json: bin/release/cert-manager-kubectl-cert_manager-darwin-%.tar.gz hack/artifact-metadata.template.json | bin/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "darwin" \
		--arg architecture "$*" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@

.PHONY: kubectl-cert_manager-windows
kubectl-cert_manager-windows: bin/kubectl-cert_manager/kubectl-cert_manager-windows-amd64.exe | bin/kubectl-cert_manager

.PHONY: kubectl-cert_manager-windows-tarballs
kubectl-cert_manager-windows-tarballs: bin/release/cert-manager-kubectl-cert_manager-windows-amd64.tar.gz bin/release/cert-manager-kubectl-cert_manager-windows-amd64.zip | bin/release

.PHONY: kubectl-cert_manager-windows-metadata
kubectl-cert_manager-windows-metadata: bin/metadata/cert-manager-kubectl-cert_manager-windows-amd64.tar.gz.metadata.json bin/metadata/cert-manager-kubectl-cert_manager-windows-amd64.zip.metadata.json | bin/release

bin/kubectl-cert_manager/kubectl-cert_manager-windows-amd64.exe: $(SOURCES) | bin/kubectl-cert_manager
	GOOS=windows GOARCH=amd64 $(GOBUILD) -o $@ $(KUBECTL_PLUGIN_GOFLAGS) cmd/ctl/main.go

bin/release/cert-manager-kubectl-cert_manager-windows-amd64.zip: bin/kubectl-cert_manager/kubectl-cert_manager-windows-amd64.exe bin/scratch/cert-manager.license | bin/scratch bin/release
	$(eval TARDIR := bin/scratch/$(notdir $@))
	mkdir -p $(TARDIR)
	cp $< $(TARDIR)/kubectl-cert_manager.exe
	cp bin/scratch/cert-manager.license $(TARDIR)/LICENSE
	pushd $(TARDIR) && zip -r $(notdir $@) . && popd && mv $(TARDIR)/$(notdir $@) $@
	rm -rf $(TARDIR)

bin/release/cert-manager-kubectl-cert_manager-windows-amd64.tar.gz: bin/kubectl-cert_manager/kubectl-cert_manager-windows-amd64.exe bin/scratch/cert-manager.license | bin/scratch bin/release
	$(eval TARDIR := bin/scratch/$(notdir $@))
	mkdir -p $(TARDIR)
	cp $< $(TARDIR)/kubectl-cert_manager.exe
	cp bin/scratch/cert-manager.license $(TARDIR)/LICENSE
	tar czf $@ -C $(TARDIR) .
	rm -rf $(TARDIR)

bin/metadata/cert-manager-kubectl-cert_manager-windows-amd64.tar.gz.metadata.json: bin/release/cert-manager-kubectl-cert_manager-windows-amd64.tar.gz hack/artifact-metadata.template.json | bin/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "windows" \
		--arg architecture "amd64" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@

bin/metadata/cert-manager-kubectl-cert_manager-windows-amd64.zip.metadata.json: bin/release/cert-manager-kubectl-cert_manager-windows-amd64.zip hack/artifact-metadata.template.json | bin/metadata
	jq --arg name "$(notdir $<)" \
		--arg sha256 "$(shell ./hack/util/hash.sh $<)" \
		--arg os "windows" \
		--arg architecture "amd64" \
		'.name = $$name | .sha256 = $$sha256 | .os = $$os | .architecture = $$architecture' \
		hack/artifact-metadata.template.json > $@
