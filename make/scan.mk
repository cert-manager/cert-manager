.PHONY: trivy-scan-all
## trivy-scan-all runs a scan using Trivy (https://github.com/aquasecurity/trivy)
## against all containers that cert-manager builds. If one of the containers
## fails a scan, then all scans will be aborted; if you need to check a specific
## container, use "trivy-scan-<name>", e.g. "make trivy-scan-controller"
##
## @category Development
trivy-scan-all: trivy-scan-controller trivy-scan-acmesolver trivy-scan-webhook trivy-scan-cainjector trivy-scan-ctl

.PHONY: trivy-scan-controller
trivy-scan-controller: $(BINDIR)/containers/cert-manager-controller-linux-amd64.tar | $(NEEDS_TRIVY)
	$(TRIVY) image --input $< --format json --exit-code 1

.PHONY: trivy-scan-acmesolver
trivy-scan-acmesolver: $(BINDIR)/containers/cert-manager-acmesolver-linux-amd64.tar | $(NEEDS_TRIVY)
	$(TRIVY) image --input $< --format json --exit-code 1

.PHONY: trivy-scan-webhook
trivy-scan-webhook: $(BINDIR)/containers/cert-manager-webhook-linux-amd64.tar | $(NEEDS_TRIVY)
	$(TRIVY) image --input $< --format json --exit-code 1

.PHONY: trivy-scan-cainjector
trivy-scan-cainjector: $(BINDIR)/containers/cert-manager-cainjector-linux-amd64.tar | $(NEEDS_TRIVY)
	$(TRIVY) image --input $< --format json --exit-code 1

.PHONY: trivy-scan-ctl
trivy-scan-ctl: $(BINDIR)/containers/cert-manager-ctl-linux-amd64.tar | $(NEEDS_TRIVY)
	$(TRIVY) image --input $< --format json --exit-code 1
