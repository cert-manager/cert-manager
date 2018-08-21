.PHONY: setup
setup:
	go get -u gopkg.in/alecthomas/gometalinter.v1
	gometalinter.v1 --install

.PHONY: test
test: validate lint
	@echo "==> Running tests"
	go test -v

.PHONY: validate
validate:
# misspell finds the work adresář (used in bzr.go) as a mispelling of
# address. It finds adres. An issue has been filed at
# https://github.com/client9/misspell/issues/99. In the meantime adding
# adres to the ignore list.
	@echo "==> Running static validations"
	@gometalinter.v1 \
	  --disable-all \
	  --linter "misspell:misspell -i adres -j 1 {path}/*.go:PATH:LINE:COL:MESSAGE" \
	  --enable deadcode \
	  --severity deadcode:error \
	  --enable gofmt \
	  --enable gosimple \
	  --enable ineffassign \
	  --enable misspell \
	  --enable vet \
	  --tests \
	  --vendor \
	  --deadline 60s \
	  ./... || exit_code=1

.PHONY: lint
lint:
	@echo "==> Running linters"
	@gometalinter.v1 \
	  --disable-all \
	  --enable golint \
	  --vendor \
	  --deadline 60s \
	  ./... || :
