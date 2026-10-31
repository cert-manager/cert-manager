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

# Update the checksums of the vendored Go toolchain to match
# VENDORED_GO_VERSION in the tools module. Renovate runs this after it bumps
# the Go version on a release branch; see .github/renovate.json5.
#
# The checksums are read from the .sha256 files that Go publishes next to each
# archive, so this script does not need the toolchain or any other tool.

mod_file="make/_shared/tools/00_mod.mk"

version=$(sed -nE 's/^VENDORED_GO_VERSION := (.+)$/\1/p' "${mod_file}")
if [[ -z "${version}" ]]; then
  echo "error: VENDORED_GO_VERSION not found in ${mod_file}" >&2
  exit 1
fi

for os in linux darwin; do
  for arch in amd64 arm64; do
    sha=$(curl -fsSL "https://dl.google.com/go/go${version}.${os}-${arch}.tar.gz.sha256")
    if [[ ! "${sha}" =~ ^[0-9a-f]{64}$ ]]; then
      echo "error: unexpected checksum for go${version} ${os}/${arch}: ${sha}" >&2
      exit 1
    fi
    sed -i -E "s/^(go_${os}_${arch}_SHA256SUM=).*$/\1${sha}/" "${mod_file}"
  done
done

grep -E '^go_[a-z0-9_]+_SHA256SUM=' "${mod_file}"
