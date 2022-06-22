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

set -o errexit
set -o nounset
set -o pipefail

if [[ -z "${1:-}" ]]; then
	echo "usage: $0 <path-to-goimports>" >&2
	exit 1
fi

goimports=$(realpath "$1")

# passing "-local" would be ideal, but it'll conflict with auto generated files ATM
# and cause churn when we want to update those files
#common_flags="-local github.com/cert-manager/cert-manager"

common_flags=""

echo "+++ running goimports" >&2

godirs=$(make --silent print-source-dirs)

output=$($goimports $common_flags -l $godirs)

if [ ! -z "${output}" ]; then
	echo "${output}" | sed "s/^/goimports: broken file: /"
	echo "+++ goimports failed; the following command may fix:" >&2
	echo "+++ $goimports $common_flags -w $godirs" >&2
	exit 1
fi
