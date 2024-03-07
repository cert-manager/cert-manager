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

.PHONY: generate-klone
## Generate klone shared Makefiles
## @category [shared] Generate/ Verify
generate-klone: | $(NEEDS_KLONE)
	$(KLONE) sync

shared_generate_targets += generate-klone

.PHONY: upgrade-klone
## Upgrade klone Makefile modules to latest version
## @category [shared] Self-upgrade
upgrade-klone: | $(NEEDS_KLONE)
	$(KLONE) upgrade
