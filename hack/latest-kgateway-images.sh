#!/usr/bin/env bash

# Copyright 2026 The cert-manager Authors.
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


set -eu -o pipefail

# This script is used to update the kgateway version pins in the file:
# ./make/e2e-setup.mk.
#
# The kgateway helm chart and controller image are released in lockstep with
# the same version, so a single version below drives:
# - KGATEWAY_HELM_VERSION, the version of the kgateway and kgateway-crds
#   helm charts installed by the e2e-setup-gwapi-provider target, and
# - IMAGE_kgateway_amd64 / IMAGE_kgateway_arm64, the pinned per-architecture
#   controller image digests.
#
# The image pins must be the per-architecture image manifest digests, not the
# digest of the multi-arch image index: the image-tar rule in
# ./make/e2e-setup.mk verifies each pinned digest against
# `crane manifest --platform=linux/<arch>`. This script reads the per-arch
# digests from the image index published to ghcr.io.

# kgateway version is maintained by Renovate using a custom regex manager
# renovate: datasource=docker packageName=cr.kgateway.dev/kgateway-dev/charts/kgateway
kgateway_version=v2.4.4

image_repository=kgateway-dev/kgateway
image=ghcr.io/${image_repository}
makefile=./make/e2e-setup.mk

token=$(curl -fsSL "https://ghcr.io/token?scope=repository:${image_repository}:pull" | jq -r '.token')
index=$(curl -fsSL \
  -H "Authorization: Bearer ${token}" \
  -H "Accept: application/vnd.oci.image.index.v1+json,application/vnd.docker.distribution.manifest.list.v2+json" \
  "https://ghcr.io/v2/${image_repository}/manifests/${kgateway_version}")

digest_for_arch() {
  jq -er --arg arch "$1" \
    'first(.manifests[] | select(.platform.os == "linux" and .platform.architecture == $arch)) | .digest' \
    <<<"${index}"
}
amd64_digest=$(digest_for_arch amd64)
arm64_digest=$(digest_for_arch arm64)

# sed -i is not portable between GNU and BSD sed, so write to a temporary file
# and move it into place, like hack/latest-kind-images.sh does.
sed \
  -e "s|^IMAGE_kgateway_amd64 := .*|IMAGE_kgateway_amd64 := ${image}:${kgateway_version}@${amd64_digest}|" \
  -e "s|^IMAGE_kgateway_arm64 := .*|IMAGE_kgateway_arm64 := ${image}:${kgateway_version}@${arm64_digest}|" \
  -e "s|KGATEWAY_HELM_VERSION=v[0-9][0-9.]*|KGATEWAY_HELM_VERSION=${kgateway_version}|" \
  "${makefile}" > "${makefile}.tmp"
mv "${makefile}.tmp" "${makefile}"
