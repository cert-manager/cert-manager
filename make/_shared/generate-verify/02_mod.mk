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

.PHONY: generate
## Generate all generate targets.
## @category [shared] Generate/ Verify
generate: $$(shared_generate_targets)

verify_script := $(dir $(lastword $(MAKEFILE_LIST)))/util/verify.sh

# Run the supplied make target argument in a temporary workspace and diff the results.
verify-%: FORCE
	$(verify_script) $(MAKE) -s $*

verify_generated_targets = $(shared_generate_targets:%=verify-%)

.PHONY: verify
## Verify code and generate targets.
## @category [shared] Generate/ Verify
verify: $$(verify_generated_targets) $$(shared_verify_targets)
	@echo "The following targets create temporary files in the current directory, that is why they have to be run last:"
	$(MAKE) noop $(shared_verify_targets_dirty)
