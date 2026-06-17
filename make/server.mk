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

.PHONY: server-binaries
server-binaries: controller acmesolver webhook cainjector

$(bin_dir)/server:
	@mkdir -p $@

.PHONY: controller
controller: $(bin_dir)/server/controller-linux-amd64 $(bin_dir)/server/controller-linux-arm64 $(bin_dir)/server/controller-linux-s390x $(bin_dir)/server/controller-linux-ppc64le $(bin_dir)/server/controller-linux-arm | $(NEEDS_GO) $(bin_dir)/server

$(bin_dir)/server/controller-linux-amd64: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/controller && GOOS=linux GOARCH=amd64 $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/controller-linux-arm64: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/controller && GOOS=linux GOARCH=arm64 $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/controller-linux-s390x: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/controller && GOOS=linux GOARCH=s390x $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/controller-linux-ppc64le: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/controller && GOOS=linux GOARCH=ppc64le $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/controller-linux-arm: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/controller && GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

.PHONY: acmesolver
acmesolver: $(bin_dir)/server/acmesolver-linux-amd64 $(bin_dir)/server/acmesolver-linux-arm64 $(bin_dir)/server/acmesolver-linux-s390x $(bin_dir)/server/acmesolver-linux-ppc64le $(bin_dir)/server/acmesolver-linux-arm | $(NEEDS_GO) $(bin_dir)/server

$(bin_dir)/server/acmesolver-linux-amd64: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/acmesolver && GOOS=linux GOARCH=amd64 $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/acmesolver-linux-arm64: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/acmesolver && GOOS=linux GOARCH=arm64 $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/acmesolver-linux-s390x: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/acmesolver && GOOS=linux GOARCH=s390x $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/acmesolver-linux-ppc64le: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/acmesolver && GOOS=linux GOARCH=ppc64le $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/acmesolver-linux-arm: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/acmesolver && GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

.PHONY: webhook
webhook: $(bin_dir)/server/webhook-linux-amd64 $(bin_dir)/server/webhook-linux-arm64 $(bin_dir)/server/webhook-linux-s390x $(bin_dir)/server/webhook-linux-ppc64le $(bin_dir)/server/webhook-linux-arm | $(NEEDS_GO) $(bin_dir)/server

$(bin_dir)/server/webhook-linux-amd64: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/webhook && GOOS=linux GOARCH=amd64 $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/webhook-linux-arm64: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/webhook && GOOS=linux GOARCH=arm64 $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/webhook-linux-s390x: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/webhook && GOOS=linux GOARCH=s390x $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/webhook-linux-ppc64le: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/webhook && GOOS=linux GOARCH=ppc64le $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/webhook-linux-arm: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/webhook && GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

.PHONY: cainjector
cainjector: $(bin_dir)/server/cainjector-linux-amd64 $(bin_dir)/server/cainjector-linux-arm64 $(bin_dir)/server/cainjector-linux-s390x $(bin_dir)/server/cainjector-linux-ppc64le $(bin_dir)/server/cainjector-linux-arm | $(NEEDS_GO) $(bin_dir)/server

$(bin_dir)/server/cainjector-linux-amd64: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/cainjector && GOOS=linux GOARCH=amd64 $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/cainjector-linux-arm64: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/cainjector && GOOS=linux GOARCH=arm64 $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/cainjector-linux-s390x: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/cainjector && GOOS=linux GOARCH=s390x $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/cainjector-linux-ppc64le: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/cainjector && GOOS=linux GOARCH=ppc64le $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/cainjector-linux-arm: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/cainjector && GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

.PHONY: startupapicheck
cainjector: $(bin_dir)/server/startupapicheck-linux-amd64 $(bin_dir)/server/startupapicheck-linux-arm64 $(bin_dir)/server/startupapicheck-linux-s390x $(bin_dir)/server/startupapicheck-linux-ppc64le $(bin_dir)/server/startupapicheck-linux-arm | $(NEEDS_GO) $(bin_dir)/server

$(bin_dir)/server/startupapicheck-linux-amd64: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/startupapicheck && GOOS=linux GOARCH=amd64 $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/startupapicheck-linux-arm64: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/startupapicheck && GOOS=linux GOARCH=arm64 $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/startupapicheck-linux-s390x: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/startupapicheck && GOOS=linux GOARCH=s390x $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/startupapicheck-linux-ppc64le: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/startupapicheck && GOOS=linux GOARCH=ppc64le $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go

$(bin_dir)/server/startupapicheck-linux-arm: $(SOURCES) | $(NEEDS_GO) $(bin_dir)/server
	cd cmd/startupapicheck && GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o ../../$@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' main.go
