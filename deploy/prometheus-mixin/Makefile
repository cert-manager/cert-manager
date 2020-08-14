# Prometheus Mixin Makefile
# Heavily copied from upstream project kubenetes-mixin

JSONNET_FMT := jsonnetfmt
PROMETHEUS_IMAGE := prom/prometheus:latest

all: fmt prometheus_alerts.yaml prometheus_rules.yaml dashboards_out lint test ## Generate files, lint and test

fmt: ## Format Jsonnet
	find . -name 'vendor' -prune -o -name '*.libsonnet' -print -o -name '*.jsonnet' -print | \
		xargs -n 1 -- $(JSONNET_FMT) -i

prometheus_alerts.yaml: mixin.libsonnet lib/alerts.jsonnet alerts/*.libsonnet ## Generate Alerts YAML
	@mkdir -p manifests
	jsonnet -S lib/alerts.jsonnet > manifests/$@

prometheus_rules.yaml: mixin.libsonnet lib/rules.jsonnet rules/*.libsonnet ## Generate Rules YAML
	@mkdir -p manifests
	jsonnet -S lib/rules.jsonnet > manifests/$@

dashboards_out: mixin.libsonnet lib/dashboards.jsonnet dashboards/*.libsonnet ## Generate Dashboards JSON
	jsonnet -J vendor -m manifests lib/dashboards.jsonnet

lint: prometheus_alerts.yaml prometheus_rules.yaml ## Lint and check YAML
	find . -name 'vendor' -prune -o -name '*.libsonnet' -print -o -name '*.jsonnet' -print | \
		while read f; do \
			$(JSONNET_FMT) "$$f" | diff -u "$$f" -; \
		done
	docker run \
		-v $(PWD)/manifests:/tmp \
		--entrypoint '/bin/promtool' \
		$(PROMETHEUS_IMAGE) \
		check rules /tmp/prometheus_rules.yaml; \
	docker run \
		-v $(PWD)/manifests:/tmp \
		--entrypoint '/bin/promtool' \
		$(PROMETHEUS_IMAGE) \
		check rules /tmp/prometheus_alerts.yaml

clean: ## Clean up generated files
	rm -rf manifests/

# TODO: Find out why official prom images segfaults during `test rules` if not root
test: prometheus_alerts.yaml prometheus_rules.yaml ## Test generated files
	docker run \
		-v $(PWD):/tmp \
		--user root \
		--entrypoint '/bin/promtool' \
		$(PROMETHEUS_IMAGE) \
		test rules /tmp/tests.yaml

.PHONY: help
help:
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | sort | awk 'BEGIN {FS = ":.*?## "}; {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}'
