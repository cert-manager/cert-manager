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

ifndef bin_dir
$(error bin_dir is not set)
endif

ifndef images_amd64
$(error images_amd64 is not set)
endif

ifndef images_arm64
$(error images_arm64 is not set)
endif

##########################################

images := $(images_$(HOST_ARCH))

images_tar_dir := $(bin_dir)/downloaded/containers/$(HOST_ARCH)
images_tars := $(foreach image,$(images),$(images_tar_dir)/$(subst :,+,$(image)).tar)

# Download the images as tarballs. After downloading the image using
# its digest, we use image-tool to modify the .[0].RepoTags[0] value in
# the manifest.json file to have the correct tag (instead of "i-was-a-digest"
# which is set when the image is pulled using its digest). This tag is used
# to reference the image after it has been imported using docker or kind. Otherwise,
# the image would be imported with the tag "i-was-a-digest" which is not very useful.
# We would have to use digests to reference the image everywhere which might
# not always be possible and does not match the default behavior of eg. our helm charts.
# NOTE: the tag is fully determined based on the input, we fully allow the remote
# tag to point to a different digest. This prevents CI from breaking due to upstream
# changes. However, it also means that we can incorrectly combine digests with tags,
# hence caution is advised.
$(images_tars): $(images_tar_dir)/%.tar: | $(NEEDS_IMAGE-TOOL) $(NEEDS_CRANE) $(NEEDS_GOJQ)
	@$(eval full_image=$(subst +,:,$*))
	@$(eval bare_image=$(word 1,$(subst :, ,$(full_image))))
	@$(eval digest=$(word 2,$(subst @, ,$(full_image))))
	@$(eval tag=$(word 2,$(subst :, ,$(word 1,$(subst @, ,$(full_image))))))
	@mkdir -p $(dir $@)
	$(CRANE) pull "$(bare_image)@$(digest)" $@ --platform=linux/$(HOST_ARCH)
	$(IMAGE-TOOL) tag-docker-tar $@ "$(bare_image):$(tag)"

# $1 = image
# $2 = image:tag@sha256:digest
define image_variables
$1.TAR      := $(images_tar_dir)/$(subst :,+,$2).tar
$1.REPO     := $1
$1.TAG      := $(word 2,$(subst :, ,$(word 1,$(subst @, ,$2))))
$1.FULL     := $(word 1,$(subst @, ,$2))
endef

$(foreach image,$(images),$(eval $(call image_variables,$(word 1,$(subst :, ,$(image))),$(image))))

.PHONY: images-preload
## Preload images.
## @category [shared] Kind cluster
images-preload: | $(images_tars)
