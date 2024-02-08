#!/usr/bin/env bash

# +skip_license_check

# Copyright 2017 The Kubernetes Authors.
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

# This script will verify that the specified script files are valid, meaning:
# - they have "set -o errexit" turned on at some point
#
# Usage: verify-errexit.sh [ dir | file ... ]
# default args is the root of our source tree

# Should usually be called via make: `make verify-errexit`

set -o errexit
set -o nounset
set -o pipefail

echo "+++ validating all scripts set '-o errexit'" >&2

if [ "$*" != "" ]; then
  args="$*"
else
  args=$(ls "$(pwd)" | grep -v 'external/' | grep -v 'bin' | grep -v '_bin' )
fi

# Gather the list of files that appear to be shell scripts.
# Meaning they have some form of "#!...sh" as a line in them.
shFiles=$(grep -Rrl '^#!.*sh$' $args)

tmp=$(mktemp)
# Delete the temporary file as it should only exist if errors have occurred.
rm $tmp

for file in ${shFiles}; do
  grep "^set -o errexit" $file > /dev/null 2>&1 && continue
  grep "^set -[a-z]*e" $file > /dev/null 2>&1 && continue

  echo $file: appears to be missing \"set -o errexit\" | tee -a $tmp
done

rc="0"
if [ -e "$tmp" ]; then
  rc="1"
fi
rm -f $tmp
exit $rc
