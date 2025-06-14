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

include $(dir $(lastword $(MAKEFILE_LIST)))/00_kind_image_versions.mk

images_amd64 ?=
images_arm64 ?=

# K8S_VERSION can be used to specify a specific
# kubernetes version to use with Kind.
K8S_VERSION ?=
ifeq ($(K8S_VERSION),)
images_amd64 += $(kind_image_latest_amd64)
images_arm64 += $(kind_image_latest_arm64)
else
fatal_if_undefined = $(if $(findstring undefined,$(origin $1)),$(error $1 is not set))
$(call fatal_if_undefined,kind_image_kube_$(K8S_VERSION)_amd64)
$(call fatal_if_undefined,kind_image_kube_$(K8S_VERSION)_arm64)

images_amd64 += $(kind_image_kube_$(K8S_VERSION)_amd64)
images_arm64 += $(kind_image_kube_$(K8S_VERSION)_arm64)
endif
