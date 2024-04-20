#!/usr/bin/env bash

# Copyright 2023 The cert-manager Authors.
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

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

# This script takes the hash of its first argument and verifies it against the
# hex hash given in its second argument

function usage_and_exit() {
	echo "usage: $0 <path-to-target> <expected-hash>"
	echo "or: LEARN_FILE=<path-to-learn-file> $0 <path-to-target> <old-hash>"
	exit 1
}

HASH_TARGET=${1:-}
EXPECTED_HASH=${2:-}

if [[ -z $HASH_TARGET ]]; then
	usage_and_exit
fi

if [[ -z $EXPECTED_HASH ]]; then
	usage_and_exit
fi

SHASUM=$("${SCRIPT_DIR}/hash.sh" "$HASH_TARGET")

if [[ "$SHASUM" == "$EXPECTED_HASH" ]]; then
	exit 0
fi

# When running 'make learn-sha-tools', we don't want this script to fail.
# Instead we log what sha values are wrong, so the make.mk file can be updated.

if [ "${LEARN_FILE:-}" != "" ]; then
	echo "s/$EXPECTED_HASH/$SHASUM/g" >> "${LEARN_FILE:-}"
	exit 0
fi

echo "invalid checksum for \"$HASH_TARGET\": wanted \"$EXPECTED_HASH\" but got \"$SHASUM\""
exit 1
