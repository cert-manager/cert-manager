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

.PHONY: trivy-scan-all
## trivy-scan-all runs a scan using Trivy (https://github.com/aquasecurity/trivy)
## against all containers that cert-manager builds. If one of the containers
## fails a scan, then all scans will be aborted; if you need to check a specific
## container, use "trivy-scan-<name>", e.g., "make trivy-scan-controller"
##
## @category Development
trivy-scan-all: trivy-scan-controller trivy-scan-acmesolver trivy-scan-webhook trivy-scan-cainjector trivy-scan-startupapicheck

.PHONY: trivy-scan-controller
trivy-scan-controller: docker-tarball-controller | $(NEEDS_TRIVY)
	$(TRIVY) image --input $(docker_tarball_path_controller) --format json --exit-code 1

.PHONY: trivy-scan-acmesolver
trivy-scan-acmesolver: docker-tarball-acmesolver | $(NEEDS_TRIVY)
	$(TRIVY) image --input $(docker_tarball_path_acmesolver) --format json --exit-code 1

.PHONY: trivy-scan-webhook
trivy-scan-webhook: docker-tarball-webhook | $(NEEDS_TRIVY)
	$(TRIVY) image --input $(docker_tarball_path_webhook) --format json --exit-code 1

.PHONY: trivy-scan-cainjector
trivy-scan-cainjector: docker-tarball-cainjector | $(NEEDS_TRIVY)
	$(TRIVY) image --input $(docker_tarball_path_cainjector) --format json --exit-code 1

.PHONY: trivy-scan-startupapicheck
trivy-scan-startupapicheck: docker-tarball-startupapicheck | $(NEEDS_TRIVY)
	$(TRIVY) image --input $(docker_tarball_path_startupapicheck) --format json --exit-code 1
