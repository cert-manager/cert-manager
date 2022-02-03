#!/usr/bin/env bash
# Copyright 2020 The cert-manager Authors.
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

set -o errexit
set -o nounset
set -o pipefail

version="$1"
platforms='darwin-amd64 linux-amd64 linux-arm linux-arm64 windows-amd64'
for platform in $platforms
do
  curl -sSL -O $"https://github.com/cert-manager/cert-manager/releases/download/${version}/kubectl-cert_manager-${platform}.tar.gz"
  sha256sum "kubectl-cert_manager-${platform}.tar.gz"
  rm "kubectl-cert_manager-${platform}.tar.gz"
done
