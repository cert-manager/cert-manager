GOFLAGS ?= $(GOFLAGS:)

get: gofmt
	go get $(GOFLAGS) ./...

build: get
	env GOOS=linux   GOARCH=amd64 go build -ldflags '-s -w' -o bin/linux/vcert         ./cmd/vcert
	env GOOS=linux   GOARCH=386   go build -ldflags '-s -w' -o bin/linux/vcert86       ./cmd/vcert
	env GOOS=darwin  GOARCH=amd64 go build -ldflags '-s -w' -o bin/darwin/vcert        ./cmd/vcert
	env GOOS=darwin  GOARCH=386   go build -ldflags '-s -w' -o bin/darwin/vcert86      ./cmd/vcert
	env GOOS=windows GOARCH=amd64 go build -ldflags '-s -w' -o bin/windows/vcert.exe   ./cmd/vcert
	env GOOS=windows GOARCH=386   go build -ldflags '-s -w' -o bin/windows/vcert86.exe ./cmd/vcert

cucumber:
	rm -rf ./aruba/bin/
	mkdir -p ./aruba/bin/ && cp ./bin/linux/vcert ./aruba/bin/vcert
	docker build --tag vcert.auto aruba/
	if [ -z "$(FEATURE)" ]; then \
		cd aruba && ./cucumber.sh; \
	else \
		cd aruba && ./cucumber.sh $(FEATURE); \
	fi

gofmt:
	! gofmt -l . | grep -v ^vendor/ | grep .

test: get
	go test -v -cover .
	go test -v -cover ./pkg/certificate
	go test -v -cover ./pkg/endpoint
	go test -v -cover ./pkg/venafi/fake
	go test -v -cover ./cmd/vcert/output
	go test -v -cover ./cmd/vcert

tpp_test: get
	go test -v $(GOFLAGS) ./pkg/venafi/tpp     \
		-tpp-url       "${VCERT_TPP_URL}"      \
		-tpp-user      "${VCERT_TPP_USER}"     \
		-tpp-password  "${VCERT_TPP_PASSWORD}" \
		-tpp-zone      "${VCERT_TPP_ZONE}"                       

cloud_test: get
	go test -v $(GOFLAGS) ./pkg/venafi/cloud   \
		-cloud-url     "${VCERT_CLOUD_URL}"    \
		-cloud-api-key "${VCERT_CLOUD_APIKEY}" \
		-cloud-zone    "${VCERT_CLOUD_ZONE}"

