.PHONY: server-binaries
server-binaries: controller acmesolver webhook cainjector

bin/server:
	@mkdir -p $@

.PHONY: controller
controller: bin/server/controller-linux-amd64 bin/server/controller-linux-arm64 bin/server/controller-linux-s390x bin/server/controller-linux-ppc64le bin/server/controller-linux-arm | bin/server bin/tools/go

bin/server/controller-linux-amd64: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $@ $(GOFLAGS) cmd/controller/main.go

bin/server/controller-linux-arm64: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $@ $(GOFLAGS) cmd/controller/main.go

bin/server/controller-linux-s390x: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=s390x $(GOBUILD) -o $@ $(GOFLAGS) cmd/controller/main.go

bin/server/controller-linux-ppc64le: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=ppc64le $(GOBUILD) -o $@ $(GOFLAGS) cmd/controller/main.go

bin/server/controller-linux-arm: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o $@ $(GOFLAGS) cmd/controller/main.go

.PHONY: acmesolver
acmesolver: bin/server/acmesolver-linux-amd64 bin/server/acmesolver-linux-arm64 bin/server/acmesolver-linux-s390x bin/server/acmesolver-linux-ppc64le bin/server/acmesolver-linux-arm | bin/server bin/tools/go

bin/server/acmesolver-linux-amd64: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $@ $(GOFLAGS) cmd/acmesolver/main.go

bin/server/acmesolver-linux-arm64: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $@ $(GOFLAGS) cmd/acmesolver/main.go

bin/server/acmesolver-linux-s390x: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=s390x $(GOBUILD) -o $@ $(GOFLAGS) cmd/acmesolver/main.go

bin/server/acmesolver-linux-ppc64le: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=ppc64le $(GOBUILD) -o $@ $(GOFLAGS) cmd/acmesolver/main.go

bin/server/acmesolver-linux-arm: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o $@ $(GOFLAGS) cmd/acmesolver/main.go

.PHONY: webhook
webhook: bin/server/webhook-linux-amd64 bin/server/webhook-linux-arm64 bin/server/webhook-linux-s390x bin/server/webhook-linux-ppc64le bin/server/webhook-linux-arm | bin/server bin/tools/go

bin/server/webhook-linux-amd64: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $@ $(GOFLAGS) cmd/webhook/main.go

bin/server/webhook-linux-arm64: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $@ $(GOFLAGS) cmd/webhook/main.go

bin/server/webhook-linux-s390x: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=s390x $(GOBUILD) -o $@ $(GOFLAGS) cmd/webhook/main.go

bin/server/webhook-linux-ppc64le: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=ppc64le $(GOBUILD) -o $@ $(GOFLAGS) cmd/webhook/main.go

bin/server/webhook-linux-arm: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o $@ $(GOFLAGS) cmd/webhook/main.go

.PHONY: cainjector
cainjector: bin/server/cainjector-linux-amd64 bin/server/cainjector-linux-arm64 bin/server/cainjector-linux-s390x bin/server/cainjector-linux-ppc64le bin/server/cainjector-linux-arm | bin/server bin/tools/go

bin/server/cainjector-linux-amd64: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=amd64 $(GOBUILD) -o $@ $(GOFLAGS) cmd/cainjector/main.go

bin/server/cainjector-linux-arm64: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=arm64 $(GOBUILD) -o $@ $(GOFLAGS) cmd/cainjector/main.go

bin/server/cainjector-linux-s390x: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=s390x $(GOBUILD) -o $@ $(GOFLAGS) cmd/cainjector/main.go

bin/server/cainjector-linux-ppc64le: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=ppc64le $(GOBUILD) -o $@ $(GOFLAGS) cmd/cainjector/main.go

bin/server/cainjector-linux-arm: $(SOURCES) | bin/server bin/tools/go
	GOOS=linux GOARCH=arm GOARM=7 $(GOBUILD) -o $@ $(GOFLAGS) cmd/cainjector/main.go
