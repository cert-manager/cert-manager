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

# This script checks if a given image exists in the upstream registry, and if it
# does, whether it contains all the expected architectures.

crane=${CRANE:-}

FULL_IMAGE=${1:-}

function print_usage() {
	echo "usage: $0 <full-image> [commands...]"
}

if [[ -z $FULL_IMAGE ]]; then
	print_usage
	echo "Missing full-image"
	exit 1
fi

if [[ -z $crane ]]; then
    echo "CRANE environment variable must be set to the path of the crane binary"
    exit 1
fi

shift 1

manifest=$(mktemp)
trap 'rm -f "$manifest"' EXIT SIGINT

manifest_error=$(mktemp)
trap 'rm -f "$manifest_error"' EXIT SIGINT

echo "+++ searching for $FULL_IMAGE in upstream registry"

set +o errexit
$crane manifest "$FULL_IMAGE" > "$manifest" 2> "$manifest_error"
exit_code=$?
set -o errexit

manifest_error_data=$(cat "$manifest_error")
if [[ $exit_code -eq 0 ]]; then
    echo "+++ upstream registry appears to contain $FULL_IMAGE, exiting"
	exit 0

elif [[ "$manifest_error_data" == *"MANIFEST_UNKNOWN"* ]]; then
    echo "+++ upstream registry does not contain $FULL_IMAGE, will build and push"
    # fall through to run the commands passed to this script

else
	echo "FATAL: upstream registry returned an unexpected error: $manifest_error_data, exiting"
	exit 1
fi
