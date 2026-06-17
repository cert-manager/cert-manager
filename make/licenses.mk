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

# LICENSE_YEAR is the value which will be substituted into licenses when they're generated
# It would be possible to make this more dynamic, but there's seemingly no need:
# https://stackoverflow.com/a/2391555/1615417
# As such, this is hardcoded to avoid needless complexity. There's generally no need to update
# this and create regular diffs which do nothing but update the license year.
LICENSE_YEAR=2022

# Creates the boilerplate header for YAML files from the template in hack/
$(bin_dir)/scratch/license.yaml: hack/boilerplate-yaml.txt | $(bin_dir)/scratch
	sed -e "s/YEAR/$(LICENSE_YEAR)/g" < $< > $@

# The references LICENSES file is 1.4MB at the time of writing. Bundling it into every container image
# seems wasteful in terms of bytes stored and bytes transferred on the wire just to add a file
# which presumably nobody will ever read or care about. Instead, just add a little footnote pointing
# to the cert-manager repo in case anybody actually decides that they care.
$(bin_dir)/scratch/license-footnote.yaml: | $(bin_dir)/scratch
	@echo -e "# To view licenses for cert-manager dependencies, see the LICENSES file in the\n# cert-manager repo: https://github.com/cert-manager/cert-manager/blob/$(GITCOMMIT)/LICENSES" > $@

$(bin_dir)/scratch/cert-manager.license: $(bin_dir)/scratch/license.yaml $(bin_dir)/scratch/license-footnote.yaml | $(bin_dir)/scratch
	cat $^ > $@

$(bin_dir)/scratch/cert-manager.licenses_notice: $(bin_dir)/scratch/license-footnote.yaml | $(bin_dir)/scratch
	cp $< $@
