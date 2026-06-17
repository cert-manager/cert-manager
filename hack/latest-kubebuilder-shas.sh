#!/usr/bin/env bash

# Copyright 2022 The cert-manager Authors.
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

# This script can be used to view the latest SHAs of kubebuilder-tools.
# kubebuilder-tools can get re-pushed for the same version of Kubernetes, so the
# SHAs can change https://kubernetes.slack.com/archives/CAR30FCJZ/p1665057725119059?thread_ts=1665057082.715119&cid=CAR30FCJZ

if [ $# -ne 1 ]; 
    then echo "error: incorrect number of args: usage ${0} <kubebuilder-tools-version>"
    echo "you can discover available versions by running gsutil ls gs://kubebuilder-tools"
    exit 1
fi

BINDIR="${BINDIR:-"_bin"}"

version=$1

kubebuilder_tools_storage_url="https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools"

os_arches=("linux-amd64" "darwin-amd64" "darwin-arm64" "linux-arm64")

output=$(printf "Kubebuilder tools SHAs for version %s:" "$version")

for os_arch in ${os_arches[@]}; do
  filePath="${BINDIR}/kubebuilder-tools-${version}-${os_arch}"
  curl -L "${kubebuilder_tools_storage_url}-${version}-${os_arch}.tar.gz" \
    -o "${filePath}"
    shasum=$(sha256sum $filePath | cut -d ' ' -f1)
    os_arch="${os_arch//$'-'/'_'}"
    output=$(printf "%s\nKUBEBUILDER_TOOLS_%s_SHA256SUM=%s\n" "$output" "$os_arch" "$shasum")
    rm -rf "${filePath}"
done

output=$(printf "%s\nYou can update the SHAs in ./make/tools.mk if needed.\nCheck https://github.com/kubernetes-sigs/kubebuilder/tree/tools-releases for latest changes that may have caused new binaries published for a version." "$output")

echo "$output"
