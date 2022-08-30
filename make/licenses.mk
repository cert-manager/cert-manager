# LICENSE_YEAR is the value which will be substituted into licenses when they're generated
# It would be possible to make this more dynamic, but there's seemingly no need:
# https://stackoverflow.com/a/2391555/1615417
# As such, this is hardcoded to avoid needless complexity
LICENSE_YEAR=2022

# Creates the boilerplate header for YAML files, assumed to be the same as the one in
# shell scripts (hence the use of boilerplate.sh.txt)
$(BINDIR)/scratch/license.yaml: hack/boilerplate/boilerplate.sh.txt | $(BINDIR)/scratch
	sed -e "s/YEAR/$(LICENSE_YEAR)/g" < $< > $@

# The references LICENSES file is 1.4MB at the time of writing. Bundling it into every container image
# seems wasteful in terms of bytes stored and bytes transferred on the wire just to add a file
# which presumably nobody will ever read or care about. Instead, just add a little footnote pointing
# to the cert-manager repo in case anybody actually decides that they care.
$(BINDIR)/scratch/license-footnote.yaml: | $(BINDIR)/scratch
	@echo -e "# To view licenses for cert-manager dependencies, see the LICENSES file in the\n# cert-manager repo: https://github.com/cert-manager/cert-manager/blob/$(GITCOMMIT)/LICENSES" > $@

$(BINDIR)/scratch/cert-manager.license: $(BINDIR)/scratch/license.yaml $(BINDIR)/scratch/license-footnote.yaml | $(BINDIR)/scratch
	cat $^ > $@

$(BINDIR)/scratch/cert-manager.licenses_notice: $(BINDIR)/scratch/license-footnote.yaml | $(BINDIR)/scratch
	cp $< $@

LICENSES $(BINDIR)/scratch/LATEST-LICENSES: go.mod go.sum | $(NEEDS_GO-LICENSES)
	$(GO-LICENSES) csv ./...  > $@
