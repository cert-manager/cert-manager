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

ifndef repo_name
$(error repo_name is not set)
endif

repository_base_dir := $(dir $(lastword $(MAKEFILE_LIST)))/base/

.PHONY: generate-base
## Generate base files in the repository
## @category [shared] Generate/ Verify
generate-base:
	cp -r $(repository_base_dir)/. ./
	cd $(repository_base_dir) && \
		find . -type f | while read file; do \
			sed "s|{{REPLACE:GH-REPOSITORY}}|$(repo_name:github.com/%=%)|g" "$$file" > "$(CURDIR)/$$file"; \
		done

shared_generate_targets += generate-base
