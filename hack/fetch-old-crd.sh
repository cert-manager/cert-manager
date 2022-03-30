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

# This script fetches old CRDs from GitHub releases but gracefully exits without an error
# if it encounters a 404. This handles the case where a git tag exists but no release
# exists, which would otherwise cause fetching the CRDs to fail.

function print_help() {
	echo "usage: $0 <url-to-fetch> <file-to-write>" > /dev/stderr
}

if [[ -z "${1:-}" ]]; then
	print_help
	exit 1
fi

if [[ -z "${2:-}" ]]; then
	print_help
	exit 1
fi

url=$1
destfile=$2

# make curl write to a temp file, since we don't want to write to destfile if
# we get a 404 from GitHub
outfile=$(mktemp)

trap 'rm -f -- "$outfile"' EXIT

STATUSCODE=$(curl --retry 3 --compressed --silent --location --output $outfile --write-out "%{http_code}" $url)

if test $STATUSCODE -eq 404; then
	# If a tag exists without a release, then we'll get a 404 here. This could happen during a release, for example.
	# In this case, we don't error and don't write anything to destfile
	exit 0
elif test $STATUSCODE -ne 200; then
	echo "Got status code $STATUSCODE for '$url' - possibly broken or in-progress release / GitHub down / rate limit" > /dev/stderr
	exit 1
fi

cp $outfile $destfile
