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

SCRIPT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"

if [[ $# -eq 4 ]]; then # Running inside bazel
  echo "Updating generated clients..." >&2
elif ! command -v bazel &>/dev/null; then
  echo "Install bazel at https://bazel.build" >&2
  exit 1
else
  (
    set -o xtrace
    bazel build //test/integration/versionchecker/testdata:test_manifests.tar
    cp -f "$(bazel info bazel-bin)/test/integration/versionchecker/testdata/test_manifests.tar" "$SCRIPT_ROOT"
  )
  exit 0
fi

CURRENT_VERSION=$(cat "$1")           # $(location //:version)
current_version_yaml=$(realpath "$2") # $(location //deploy/manifests:cert-manager.yaml)
tags=$(cat "$3")                      # $(location :git_tags.txt)
test_manifests_tar=$(realpath "$4")        # $(location test_manifests.tar)

shift 4

# copy current version's manifest to current folder (will get included in tar)
cp "$current_version_yaml" "$CURRENT_VERSION.yaml"

manifest_urls=""
for tag in $tags
do
    # The "v1.2.0-alpha.1" manifest contains duplicate CRD resources
    # (2 CRD resources with the same name); don't download this manifest
    # as it will cause the test to fail when adding the CRD resources
    # to the fake client
    if [[ $tag == "v1.2.0-alpha.1" ]]; then
        continue
    fi

    manifest_urls+=",$tag"
done

# remove leading "," in string
manifest_urls=${manifest_urls#","}

# download all manifests
#  --compressed: try gzip compressed download
#  -s: don't show progress bar
#  -f: fail if non success code
#  -L: follow redirects
#  -o: output to "#1.yaml" 
curl --compressed -sfLo "#1.yaml" "https://github.com/cert-manager/cert-manager/releases/download/{$manifest_urls}/cert-manager.yaml"

tar -cvf "$test_manifests_tar" *.yaml
