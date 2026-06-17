#!/usr/bin/env bash

# Copyright 2021 The cert-manager Authors.
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

while (($#)); do
	f=$1
	if [[ ! -f "$f" ]]; then
		echo "$f doesn't exist, exiting" 1>&2
		exit 1
	fi

	# The YAML spec requires that a YAML directive only appears once in a document
	# We probably won't have any directives, so we just check for any directive and
	# fail if there's one in any of the files
	# https://yaml.org/spec/1.2.2/#681-yaml-directives
	if grep -q "%YAML" "$f"; then
		echo "found %YAML directive in file; this can't be handled safely by this script" 1>&2
		exit 1
	fi

	cat "$f"

	shift

	# if there's at least one more file left, output the YAML file separator
	if [[ $# -gt 0 ]]; then
		echo ""
		echo "---"
	fi
done
