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

base_dir := $(dir $(lastword $(MAKEFILE_LIST)))/base/
base_dependabot_dir := $(dir $(lastword $(MAKEFILE_LIST)))/base-dependabot/

ifdef repository_base_no_dependabot
.PHONY: generate-base
## Generate base files in the repository
## @category [shared] Generate/ Verify
generate-base:
	cp -r $(base_dir)/. ./
else
.PHONY: generate-base
## Generate base files in the repository
## @category [shared] Generate/ Verify
generate-base:
	cp -r $(base_dir)/. ./
	cp -r $(base_dependabot_dir)/. ./
endif

shared_generate_targets += generate-base
