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

ifndef bin_dir
$(error bin_dir is not set)
endif

ifndef repo_name
$(error repo_name is not set)
endif

ifndef golangci_lint_config
$(error golangci_lint_config is not set)
endif

golangci_lint_override := $(dir $(lastword $(MAKEFILE_LIST)))/.golangci.override.yaml

.PHONY: go-workspace
go-workspace: export GOWORK?=$(abspath go.work)
## Create a go.work file in the repository root (or GOWORK)
##
## @category Development
go-workspace: | $(NEEDS_GO)
	@rm -f $(GOWORK)
	$(GO) work init
	@find . -name go.mod -not \( -path "./$(bin_dir)/*" -or -path "./make/_shared/*" \) \
		| while read d; do \
				target=$$(dirname $${d}); \
				$(GO) work use "$${target}"; \
			done

.PHONY: go-tidy
## Alias for `make generate-go-mod-tidy`
## @category [shared] Generate/ Verify
go-tidy: generate-go-mod-tidy

.PHONY: generate-go-mod-tidy
## Run `go mod tidy` on all Go modules
## @category [shared] Generate/ Verify
generate-go-mod-tidy: | $(NEEDS_GO)
	@find . -name go.mod -not \( -path "./$(bin_dir)/*" -or -path "./make/_shared/*" \) \
		| while read d; do \
				target=$$(dirname $${d}); \
				echo "Running 'go mod tidy' in directory '$${target}'"; \
				pushd "$${target}" >/dev/null; \
				$(GO) mod tidy || exit; \
				$(GO) get toolchain@none || exit; \
				popd >/dev/null; \
				echo ""; \
			done

shared_generate_targets := generate-go-mod-tidy $(shared_generate_targets)

ifndef dont_generate_govulncheck

govulncheck_base_dir := $(dir $(lastword $(MAKEFILE_LIST)))/base/

.PHONY: generate-govulncheck
## Generate base files in the repository
## @category [shared] Generate/ Verify
generate-govulncheck:
	cp -r $(govulncheck_base_dir)/. ./
	cd $(govulncheck_base_dir) && \
		find . -type f | while read file; do \
			sed "s|{{REPLACE:GH-REPOSITORY}}|$(repo_name:github.com/%=%)|g" "$$file" > "$(CURDIR)/$$file"; \
		done

shared_generate_targets += generate-govulncheck

endif # dont_generate_govulncheck

.PHONY: verify-govulncheck
## Verify all Go modules for vulnerabilities using govulncheck
## @category [shared] Generate/ Verify
#
# Runs `govulncheck` on all Go modules related to the project.
# Ignores Go modules among the temporary build artifacts in _bin, to avoid
# scanning the code of the vendored Go, after running make vendor-go.
# Ignores Go modules in make/_shared, because those will be checked in centrally
# in the makefile_modules repository.
#
# `verify-govulncheck` not added to the `shared_verify_targets` variable and is
# not run by `make verify`, because `make verify` is run for each PR, and we do
# not want new vulnerabilities in existing code to block the merging of PRs.
# Instead `make verify-govulncheck` is intended to be run periodically by a CI job.
verify-govulncheck: | $(NEEDS_GOVULNCHECK)
	@find . -name go.mod -not \( -path "./$(bin_dir)/*" -or -path "./make/_shared/*" \) \
		| while read d; do \
				target=$$(dirname $${d}); \
				echo "Running 'GOTOOLCHAIN=go$(VENDORED_GO_VERSION) $(bin_dir)/tools/govulncheck ./...' in directory '$${target}'"; \
				pushd "$${target}" >/dev/null; \
				GOTOOLCHAIN=go$(VENDORED_GO_VERSION) $(GOVULNCHECK) ./... || exit; \
				popd >/dev/null; \
				echo ""; \
			done

.PHONY: generate-golangci-lint-config
## Generate a golangci-lint configuration file
## @category [shared] Generate/ Verify
generate-golangci-lint-config: | $(NEEDS_GOLANGCI-LINT) $(NEEDS_YQ) $(bin_dir)/scratch
	if [ "$$($(YQ) eval 'has("version") | not' $(golangci_lint_config))" == "true" ]; then \
		$(GOLANGCI-LINT) migrate -c $(golangci_lint_config); \
		rm $(basename $(golangci_lint_config)).bck$(suffix $(golangci_lint_config)); \
	fi

	cp $(golangci_lint_config) $(bin_dir)/scratch/golangci-lint.yaml.tmp
	$(YQ) -i 'del(.linters.enable)' $(bin_dir)/scratch/golangci-lint.yaml.tmp
	$(YQ) eval-all -i '. as $$item ireduce ({}; . * $$item)' $(bin_dir)/scratch/golangci-lint.yaml.tmp $(golangci_lint_override)
	mv $(bin_dir)/scratch/golangci-lint.yaml.tmp $(golangci_lint_config)

shared_generate_targets += generate-golangci-lint-config

golangci_lint_timeout ?= 10m

.PHONY: verify-golangci-lint
## Verify all Go modules using golangci-lint
## @category [shared] Generate/ Verify
verify-golangci-lint: | $(NEEDS_GO) $(NEEDS_GOLANGCI-LINT) $(NEEDS_YQ) $(bin_dir)/scratch
	@find . -name go.mod -not \( -path "./$(bin_dir)/*" -or -path "./make/_shared/*" \) \
		| while read d; do \
				target=$$(dirname $${d}); \
				echo "Running 'GOVERSION=$(VENDORED_GO_VERSION) $(bin_dir)/tools/golangci-lint run -c $(CURDIR)/$(golangci_lint_config) --timeout $(golangci_lint_timeout)' in directory '$${target}'"; \
				pushd "$${target}" >/dev/null; \
				GOVERSION=$(VENDORED_GO_VERSION) $(GOLANGCI-LINT) run -c $(CURDIR)/$(golangci_lint_config) --timeout $(golangci_lint_timeout) || exit; \
				popd >/dev/null; \
				echo ""; \
			done

shared_verify_targets_dirty += verify-golangci-lint

.PHONY: fix-golangci-lint
## Fix all Go modules using golangci-lint
## @category [shared] Generate/ Verify
fix-golangci-lint: | $(NEEDS_GOLANGCI-LINT) $(NEEDS_YQ) $(NEEDS_GCI) $(bin_dir)/scratch
	@find . -name go.mod -not \( -path "./$(bin_dir)/*" -or -path "./make/_shared/*" \) \
		| while read d; do \
				target=$$(dirname $${d}); \
				echo "Running 'GOVERSION=$(VENDORED_GO_VERSION) $(bin_dir)/tools/golangci-lint run --fix -c $(CURDIR)/$(golangci_lint_config) --timeout $(golangci_lint_timeout)' in directory '$${target}'"; \
				pushd "$${target}" >/dev/null; \
				GOVERSION=$(VENDORED_GO_VERSION) $(GOLANGCI-LINT) run --fix -c $(CURDIR)/$(golangci_lint_config) --timeout $(golangci_lint_timeout) || exit; \
				popd >/dev/null; \
				echo ""; \
			done
