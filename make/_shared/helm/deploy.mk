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

ifndef deploy_name
$(error deploy_name is not set)
endif

ifndef deploy_namespace
$(error deploy_namespace is not set)
endif

# Install options allows the user configuration of extra flags
INSTALL_OPTIONS ?=

##########################################

.PHONY: install
## Install controller helm chart on the current active K8S cluster.
## @category [shared] Deployment
install: $(helm_chart_archive) | $(NEEDS_HELM)
	$(HELM) upgrade $(deploy_name) $(helm_chart_archive) \
		--wait \
		--install \
		--create-namespace \
		$(INSTALL_OPTIONS) \
		--namespace $(deploy_namespace)

.PHONY: uninstall
## Uninstall controller helm chart from the current active K8S cluster.
## @category [shared] Deployment
uninstall: | $(NEEDS_HELM)
	$(HELM) uninstall $(deploy_name)  \
		--wait \
		--namespace $(deploy_namespace)

.PHONY: template
## Template the helm chart.
## @category [shared] Deployment
template: $(helm_chart_archive) | $(NEEDS_HELM)
	@$(HELM) template $(deploy_name) $(helm_chart_archive) \
		--create-namespace \
		$(INSTALL_OPTIONS) \
		--namespace $(deploy_namespace)
