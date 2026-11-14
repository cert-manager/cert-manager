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

ifndef kube_api_linter_config
$(error kube_api_linter_config is not set)
endif

kube_api_linter_timeout ?= 10m

.PHONY: verify-kube-api-lint
## Verify Kubernetes API types using Kube API Linter
## @category [shared] Generate/ Verify
verify-kube-api-lint: | $(NEEDS_GO) $(NEEDS_KUBE-API-LINTER)
	GOVERSION=$(VENDORED_GO_VERSION) $(KUBE-API-LINTER) run -c $(CURDIR)/$(kube_api_linter_config) --timeout $(kube_api_linter_timeout)

shared_verify_targets_dirty += verify-kube-api-lint

.PHONY: fix-kube-api-lint
## Fix Kubernetes API types using Kube API Linter
## @category [shared] Generate/ Verify
fix-kube-api-lint: | $(NEEDS_GO) $(NEEDS_KUBE-API-LINTER)
	GOVERSION=$(VENDORED_GO_VERSION) $(KUBE-API-LINTER) run --fix -c $(CURDIR)/$(kube_api_linter_config) --timeout $(kube_api_linter_timeout)
