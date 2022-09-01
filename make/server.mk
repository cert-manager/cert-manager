.PHONY: server-binaries
server-binaries: controller acmesolver webhook cainjector

$(BINDIR)/server:
	@mkdir -p $@

.PHONY: controller
controller: $(BINDIR)/server/controller-linux-amd64 $(BINDIR)/server/controller-linux-arm64 $(BINDIR)/server/controller-linux-s390x $(BINDIR)/server/controller-linux-ppc64le $(BINDIR)/server/controller-linux-arm | $(NEEDS_GO) $(BINDIR)/server

$(BINDIR)/server/controller-linux-amd64: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/controller/main.go

$(BINDIR)/server/controller-linux-arm64: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/controller/main.go

$(BINDIR)/server/controller-linux-s390x: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=s390x $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/controller/main.go

$(BINDIR)/server/controller-linux-ppc64le: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=ppc64le $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/controller/main.go

$(BINDIR)/server/controller-linux-arm: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/controller/main.go

.PHONY: acmesolver
acmesolver: $(BINDIR)/server/acmesolver-linux-amd64 $(BINDIR)/server/acmesolver-linux-arm64 $(BINDIR)/server/acmesolver-linux-s390x $(BINDIR)/server/acmesolver-linux-ppc64le $(BINDIR)/server/acmesolver-linux-arm | $(NEEDS_GO) $(BINDIR)/server

$(BINDIR)/server/acmesolver-linux-amd64: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/acmesolver/main.go

$(BINDIR)/server/acmesolver-linux-arm64: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/acmesolver/main.go

$(BINDIR)/server/acmesolver-linux-s390x: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=s390x $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/acmesolver/main.go

$(BINDIR)/server/acmesolver-linux-ppc64le: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=ppc64le $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/acmesolver/main.go

$(BINDIR)/server/acmesolver-linux-arm: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/acmesolver/main.go

.PHONY: webhook
webhook: $(BINDIR)/server/webhook-linux-amd64 $(BINDIR)/server/webhook-linux-arm64 $(BINDIR)/server/webhook-linux-s390x $(BINDIR)/server/webhook-linux-ppc64le $(BINDIR)/server/webhook-linux-arm | $(NEEDS_GO) $(BINDIR)/server

$(BINDIR)/server/webhook-linux-amd64: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/webhook/main.go

$(BINDIR)/server/webhook-linux-arm64: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/webhook/main.go

$(BINDIR)/server/webhook-linux-s390x: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=s390x $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/webhook/main.go

$(BINDIR)/server/webhook-linux-ppc64le: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=ppc64le $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/webhook/main.go

$(BINDIR)/server/webhook-linux-arm: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/webhook/main.go

.PHONY: cainjector
cainjector: $(BINDIR)/server/cainjector-linux-amd64 $(BINDIR)/server/cainjector-linux-arm64 $(BINDIR)/server/cainjector-linux-s390x $(BINDIR)/server/cainjector-linux-ppc64le $(BINDIR)/server/cainjector-linux-arm | $(NEEDS_GO) $(BINDIR)/server

$(BINDIR)/server/cainjector-linux-amd64: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/cainjector/main.go

$(BINDIR)/server/cainjector-linux-arm64: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/cainjector/main.go

$(BINDIR)/server/cainjector-linux-s390x: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=s390x $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/cainjector/main.go

$(BINDIR)/server/cainjector-linux-ppc64le: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=ppc64le $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/cainjector/main.go

$(BINDIR)/server/cainjector-linux-arm: $(SOURCES) | $(NEEDS_GO) $(BINDIR)/server
	GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o $@ $(GOFLAGS) -ldflags '$(GOLDFLAGS)' cmd/cainjector/main.go
