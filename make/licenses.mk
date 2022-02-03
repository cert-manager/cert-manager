# LICENSE_YEAR is the value which will be substituted into licenses when they're generated
# It would be possible to make this more dynamic, but there's seemingly no need:
# https://stackoverflow.com/a/2391555/1615417
# As such, this is hardcoded to avoid needless complexity
LICENSE_YEAR=2021

# Creates the boilerplate header for YAML files, assumed to be the same as the one in
# shell scripts (hence the use of boilerplate.sh.txt)
bin/scratch/license.yaml: hack/boilerplate/boilerplate.sh.txt | bin/scratch
	sed -e "s/YEAR/$(LICENSE_YEAR)/g" < $< > $@

# The references LICENSES file is 1.4MB at the time of writing. Bundling it into every container image
# seems wasteful in terms of bytes stored and bytes transferred on the wire just to add a file
# which presumably nobody will ever read or care about. Instead, just add a little footnote pointing
# to the cert-manager repo in case anybody actually decides that they care.
bin/scratch/license-footnote.yaml: | bin/scratch
	@echo -e "# To view licenses for cert-manager dependencies, see the LICENSES file in the\n# cert-manager repo: https://github.com/cert-manager/cert-manager/blob/$(GITCOMMIT)/LICENSES" > $@

bin/scratch/cert-manager.license: bin/scratch/license.yaml bin/scratch/license-footnote.yaml | bin/scratch
	cat $^ > $@

bin/scratch/cert-manager.licenses_notice: bin/scratch/license-footnote.yaml | bin/scratch
	cp $< $@
