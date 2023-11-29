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

# This script takes the hash of its first argument and verifies it against the
# hex hash given in its second argument

SHASUM=$(./hack/util/hash.sh "$1")

# When running 'make learn-sha-tools', we don't want this script to fail.
# Instead we log what sha values are wrong, so the make.mk file can be updated.
if [ "$SHASUM" != "$2" ] && [ "${LEARN_FILE:-}" != "" ]; then
	echo "s/$2/$SHASUM/g" >> "${LEARN_FILE:-}"
	exit 0
fi

if [ "$SHASUM" != "$2"  ]; then
	echo "invalid checksum for \"$1\": wanted \"$2\" but got \"$SHASUM\""
	exit 1
fi