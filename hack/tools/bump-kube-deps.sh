#!/bin/bash

# Copyright 2018 The Jetstack cert-manager contributors.
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

## This script will print Gopkg.toml configuration that can be used to pin
## a repository to a specific revision of the Kubernetes libraries.

## It will **not** automatically detect required revision of transitive
## dependencies, in an *attempt* to allow these to be automatically upgrade
## with a standard dep workflow.
## In reality, this will probably not go so well.

set -o errexit

## This script requires:
## * jq
## * curl

VERSION="${VERSION:-kubernetes-1.10.0}"

REPOS=(api apimachinery client-go code-generator apiextensions-apiserver apiserver)

for r in "${REPOS[@]}"; do
	ref=$(curl "https://api.github.com/repos/kubernetes/${r}/git/refs/tags/${VERSION}" 2>/dev/null | \
		jq -r '.object.sha')
	echo -e "[[override]]\n  name = \"k8s.io/${r}\"\n  revision = \"${ref}\"\n"
done
