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

set -o nounset
set -o errexit
set -o pipefail

function usage_and_exit() {
	echo "usage: $0 <path-to-go> <path-to-controller-gen> <path-to-yq>"
	exit 1
}

go=${1:-}
controllergen=${2:-}
yq=${3:-}

if [[ -z $go ]]; then
	usage_and_exit
fi

if [[ -z $controllergen ]]; then
	usage_and_exit
fi

if [[ -z $yq ]]; then
	usage_and_exit
fi

echo "+++ verifying that generated CRDs are up-to-date..." >&2
tmpdir="$(mktemp -d tmp-CHECKCRD-XXXXXXXXX)"
trap 'rm -r $tmpdir' EXIT

make PATCH_CRD_OUTPUT_DIR=$tmpdir patch-crds

# Avoid diff -N so we handle empty files correctly
diff=$(diff -upr -x README.md "./deploy/crds" "$tmpdir" 2>/dev/null || true)

if [[ -n "${diff}" ]]; then
  echo "${diff}" >&2
  echo >&2
  echo "fatal: CRDs are out of date. Run 'make update-crds'" >&2
  exit 1
fi

echo "+++ success: generated CRDs are up-to-date" >&2

# Verify that CRDs don't contain status fields as that causes issues when they
# are managed by some CD tools. This check is necessary because currently
# controller-gen adds a status field that needs to be removed manually.
# See https://github.com/cert-manager/cert-manager/pull/4379 for context

echo "+++ verifying that CRDs don't contain .status fields..."

for file in ${tmpdir}/*.yaml; do
  name=$($yq e '.metadata.name' $file)
  echo "checking $name"
  # Exit 1 if status is non-null
  $yq e --exit-status=1 '.status==null' $file >/dev/null
done

echo "+++ success: generated CRDs don't contain any status fields"
