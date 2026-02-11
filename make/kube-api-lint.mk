# Copyright 2026 The cert-manager Authors.
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

KUBE_API_LINT := $(bin_dir)/tools/kube-api-lint

$(KUBE_API_LINT): | $(NEEDS_GO) $(NEEDS_GOLANGCI-LINT) $(bin_dir)/scratch
	@echo "Building kube-api-lint custom golangci-lint binary"
	GOVERSION=$(VENDORED_GO_VERSION) \
		$(GOLANGCI-LINT) custom -v \
		--destination $(bin_dir)/tools \
		--name kube-api-lint

.PHONY: verify-kube-api-lint
## Verify all APIs using Kube API Linter
## @category [shared] Generate/ Verify
verify-kube-api-lint: | $(NEEDS_GO) $(KUBE_API_LINT)
	@echo "Running kube-api-lint"
	GOVERSION=$(VENDORED_GO_VERSION) \
		$(KUBE_API_LINT) run -c $(CURDIR)/.golangci-kal.yml

shared_verify_targets_dirty += verify-kube-api-lint

.PHONY: fix-kube-api-lint
## Fix all APIs using Kube API Linter
## @category [shared] Generate/ Verify
fix-kube-api-lint: | $(NEEDS_GO) $(KUBE_API_LINT)
	@echo "Running kube-api-lint with --fix"
	GOVERSION=$(VENDORED_GO_VERSION) \
		$(KUBE_API_LINT) run --fix -c $(CURDIR)/.golangci-kal.yml
