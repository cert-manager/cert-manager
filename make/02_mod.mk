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

GOBUILD := CGO_ENABLED=$(CGO_ENABLED) GOEXPERIMENT=$(GOEXPERIMENT) GOMAXPROCS=$(GOBUILDPROCS) $(GO) build
GOTEST := CGO_ENABLED=$(CGO_ENABLED) GOEXPERIMENT=$(GOEXPERIMENT) $(GO) test

# overwrite $(GOTESTSUM) and add relevant environment variables
GOTESTSUM := CGO_ENABLED=$(CGO_ENABLED) GOEXPERIMENT=$(GOEXPERIMENT) $(GOTESTSUM)

# Version of Gateway API install bundle https://gateway-api.sigs.k8s.io/v1alpha2/guides/#installing-gateway-api
GATEWAY_API_VERSION=v1.0.0

$(bin_dir)/scratch/gateway-api-$(GATEWAY_API_VERSION).yaml: | $(bin_dir)/scratch
	$(CURL) https://github.com/kubernetes-sigs/gateway-api/releases/download/$(GATEWAY_API_VERSION)/experimental-install.yaml -o $@

include make/ci.mk
include make/test.mk
include make/base_images.mk
include make/server.mk
include make/containers.mk
include make/release.mk
include make/manifests.mk
include make/licenses.mk
include make/e2e-setup.mk
include make/scan.mk
include make/ko.mk

.PHONY: tidy
tidy: generate-go-mod-tidy

.PHONY: update-base-images
update-base-images: | $(NEEDS_CRANE)
	CRANE=$(CRANE) ./hack/latest-base-images.sh

.PHONY: update-licenses
update-licenses: generate-licenses

.PHONY: verify-licenses
verify-licenses: verify-generate-licenses
