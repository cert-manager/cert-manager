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

# Targets in this file are legacy holdovers from before the migration to make.
# They're preserved here in case they're used in some third party CI system or script,
# but are liable to being removed or broken without warning.

.PHONY: verify
verify: ci-presubmit test
	$(warning "The '$@' target is deprecated and may be removed. Use 'make $^' instead.")

.PHONY: verify_deps
verify_deps:
	$(warning "The '$@' target is deprecated and may be removed. This target is a no-op with the new make flow.")

.PHONY: cluster
cluster: e2e-setup-kind
	$(warning "The '$@' target is deprecated and may be removed. Use 'make $^' instead.")

.PHONY: verify_chart
verify_chart: verify-chart
	$(warning "The '$@' target is deprecated and may be removed. Use 'make $^' instead.")

.PHONY: verify_upgrade
verify_upgrade: test-upgrade
	$(warning "The '$@' target is deprecated and may be removed. Use 'make $^' instead.")
