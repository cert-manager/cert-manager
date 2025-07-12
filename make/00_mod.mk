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

repo_name := github.com/cert-manager/cert-manager

kind_cluster_name := cert-manager
kind_cluster_config := $(bin_dir)/scratch/kind_cluster.yaml

build_names := controller acmesolver webhook cainjector startupapicheck

## Extra linking flags passed to 'go' via '-ldflags' when building.
goldflags := \
	-X github.com/cert-manager/cert-manager/pkg/util.AppVersion=$(VERSION) \
    -X github.com/cert-manager/cert-manager/pkg/util.AppGitCommit=$(GITCOMMIT)

go_controller_main_dir := .
go_controller_mod_dir := ./cmd/controller
go_controller_ldflags := $(goldflags)
oci_controller_base_image_flavor := static
oci_controller_image_name := quay.io/jetstack/cert-manager-controller
oci_controller_image_tag := $(VERSION)
oci_controller_image_name_development := cert-manager.local/cert-manager-controller

go_acmesolver_main_dir := .
go_acmesolver_mod_dir := ./cmd/acmesolver
go_acmesolver_ldflags := $(goldflags)
oci_acmesolver_base_image_flavor := static
oci_acmesolver_image_name := quay.io/jetstack/cert-manager-acmesolver
oci_acmesolver_image_tag := $(VERSION)
oci_acmesolver_image_name_development := cert-manager.local/cert-manager-acmesolver

go_webhook_main_dir := .
go_webhook_mod_dir := ./cmd/webhook
go_webhook_ldflags := $(goldflags)
oci_webhook_base_image_flavor := static
oci_webhook_image_name := quay.io/jetstack/cert-manager-webhook
oci_webhook_image_tag := $(VERSION)
oci_webhook_image_name_development := cert-manager.local/cert-manager-webhook

go_cainjector_main_dir := .
go_cainjector_mod_dir := ./cmd/cainjector
go_cainjector_ldflags := $(goldflags)
oci_cainjector_base_image_flavor := static
oci_cainjector_image_name := quay.io/jetstack/cert-manager-cainjector
oci_cainjector_image_tag := $(VERSION)
oci_cainjector_image_name_development := cert-manager.local/cert-manager-cainjector

go_startupapicheck_main_dir := .
go_startupapicheck_mod_dir := ./cmd/startupapicheck
go_startupapicheck_ldflags := $(goldflags)
oci_startupapicheck_base_image_flavor := static
oci_startupapicheck_image_name := quay.io/jetstack/cert-manager-startupapicheck
oci_startupapicheck_image_tag := $(VERSION)
oci_startupapicheck_image_name_development := cert-manager.local/cert-manager-startupapicheck

deploy_name := cert-manager
deploy_namespace := cert-manager

crds_expression := or .Values.crds.enabled .Values.installCRDs

helm_chart_source_dir := deploy/charts/cert-manager
helm_chart_image_name := quay.io/jetstack/charts/cert-manager
helm_chart_version := $(VERSION)
helm_labels_template_name := cert-manager.crd-labels

golangci_lint_config := .golangci.yaml

repository_base_no_dependabot := 1

define helm_values_mutation_function
$(YQ) \
	'( .image.repository = "$(oci_controller_image_name)" ) | \
	( .image.tag = "$(oci_controller_image_tag)" ) | \
	( .cainjector.image.repository = "$(oci_cainjector_image_name)" ) | \
	( .cainjector.image.tag = "$(oci_cainjector_image_tag)" ) | \
	( .webhook.image.repository = "$(oci_webhook_image_name)" ) | \
	( .webhook.image.tag = "$(oci_webhook_image_tag)" ) | \
	( .acmesolver.image.repository = "$(oci_acmesolver_image_name)" ) | \
	( .acmesolver.image.tag = "$(oci_acmesolver_image_tag)" ) | \
	( .startupapicheck.image.repository = "$(oci_startupapicheck_image_name)" ) | \
	( .startupapicheck.image.tag = "$(oci_startupapicheck_image_tag)" )' \
	$1 --inplace
endef

GINKGO_VERSION ?= $(shell awk '/ginkgo\/v2/ {print $$2}' test/e2e/go.mod)

images_amd64 += registry.k8s.io/ingress-nginx/controller:v1.12.3@sha256:aadad8e26329d345dea3a69b8deb9f3c52899a97cbaf7e702b8dfbeae3082c15
images_amd64 += ghcr.io/kyverno/kyverno:v1.12.3@sha256:127def0e41f49fea6e260abf7b1662fe7bdfb9f33e8f9047fb74d0162a5697bb
images_amd64 += ghcr.io/kyverno/kyvernopre:v1.12.3@sha256:d388cd67b38fb4f55eb5e38107dbbce9e06208b8e3839f0b63f8631f286181be
images_amd64 += docker.io/hashicorp/vault:1.14.1@sha256:436d056e8e2a96c7356720069c29229970466f4f686886289dcc94dfa21d3155
images_amd64 += docker.io/ubuntu/bind9:9.18-22.04_beta@sha256:c69abb9ab122bf82d3c3141a60b5eac20ad5574382e419a1d483becd657d1afe
images_amd64 += ghcr.io/cert-manager/sample-external-issuer/controller:v0.4.0@sha256:964b378fe0dda7fc38ce3f211c3b24c780e44cef13c39d3206de985bad67f294
images_amd64 += ghcr.io/projectcontour/contour:v1.29.1@sha256:bb7af851ac5832c315e0863d12ed583cee54c495d58a206f1d0897647505ed70

images_arm64 += registry.k8s.io/ingress-nginx/controller:v1.12.3@sha256:800048a4cdf4ad487a17f56d22ec6be7a34248fc18900d945bc869fee4ccb2f7
images_arm64 += ghcr.io/kyverno/kyverno:v1.12.3@sha256:c076a1ba9e0fb33d8eca3e7499caddfa3bb4f5e52e9dee589d8476ae1688cd34
images_arm64 += ghcr.io/kyverno/kyvernopre:v1.12.3@sha256:d8d750012ed4bb46fd41d8892e92af6fb9fd212317bc23e68a2a47199646b04a
images_arm64 += docker.io/hashicorp/vault:1.14.1@sha256:27dd264f3813c71a66792191db5382f0cf9eeaf1ae91770634911facfcfe4837
images_arm64 += docker.io/ubuntu/bind9:9.18-22.04_beta@sha256:d098e53507bd8c19d514b93c3cb0842464e8a5dd561b643727382b5aa314b5dc
images_arm64 += ghcr.io/cert-manager/sample-external-issuer/controller:v0.4.0@sha256:bdff00089ec7581c0d12414ce5ad1c6ccf5b6cacbfb0b0804fefe5043a1cb849
images_arm64 += ghcr.io/projectcontour/contour:v1.29.1@sha256:dbfec77951e123bf383a09412a51df218b716aaf3fe7b2778bb2f208ac495dc5
