#!/bin/bash

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

# This script will scan all md (markdown) files for bad references.
# It will look for strings of the form [...](...) and make sure that
# the (...) points to either a valid file in the source tree or, in the
# case of it being an http url, it'll make sure we don't get a 404.
#
# Usage: verify-links.sh [ dir | file ... ]
# default arg is root of our source tree

set -o errexit
set -o nounset
set -o pipefail

REPO_ROOT=$(dirname "${BASH_SOURCE}")/..

if [ "$*" != "" ]; then
  args="$*"
else
  args="${REPO_ROOT}"
fi

mdFiles=$(find "${args}" -name "*.md" | grep -v vendor | grep -v glide)

tmp=$(mktemp)

for file in ${mdFiles}; do
  # echo scanning $file
  dir=$(dirname $file)

  # Replace ) with )\n so that each possible href is on its own line.
  # Then only grab lines that have [..](..) in them - put results in tmp file.
  # If the file doesn't have any lines with [..](..) then skip this file
  sed "s/)/)\n/g" < $file | grep "\[.*\](.*)" > ${tmp}1 || continue

  # This sed will extract the href portion of the [..](..) - meaning
  # the stuff in the parens.
  sed "s/.*\(\[[^\[\]*\]([^()]*)\)/\1/" < ${tmp}1 > ${tmp}2  || continue

  # Extract all headings/anchors.
  # And strip off the leading #'s and leading/trailing blanks
  grep "^ *#" < $file | sed "s/ *#* *\(.*\) *$/\1/" > ${tmp}anchors

  # Now convert the header to what the anchor will look like.
  # - lower case stuff
  # - convert spaces to -'s
  # - remove punctuation marks (only accept 0-9, a-z
  cat ${tmp}anchors | \
    tr '[:upper:]' '[:lower:]' | \
	sed "s/ /-/g" | \
    sed "s/[^-a-zA-Z0-9]//g" > ${tmp}anchors1

  cat ${tmp}2 | while read line ; do
    # Strip off the leading and trailing parens
    ref=${line#*(}
	ref=${ref%)*}

	# An external href (ie. starts with http)
	if [ "${ref:0:4}" == "http" ]; then
	  if ! wget --timeout 10 -o /dev/null ${ref} > /dev/null 2>&1 ; then
	    echo $file: Can\'t load: url ${ref} | tee -a ${tmp}3
	  fi
	  continue
	fi

	# Local file href - skip for now.
	# TODO add support for checking these
	if [ "${ref:0:1}" == "#" ]; then
	  ref=${ref:1}
	  if ! grep "^$ref$" ${tmp}anchors1 > /dev/null 2>&1 ; then
	    echo $file: Can\'t find anchor \'\#${ref}\' | tee -a ${tmp}3
	  fi
	  continue
	fi

	# Remove everything after # (aka section of page)
	ref=${ref%#*}
	newPath=${dir}/${ref}

	# And finally make sure the file is there
	# debug line: echo ref: $ref "->" $newPath
	if ! ls "${newPath}" > /dev/null 2>&1 ; then
	  echo $file: Can\'t find: ${newPath} | tee -a ${tmp}3
	  failed=true
	fi
  done
done
rc=0
if [ -a ${tmp}3 ]; then
  rc=1
fi
rm -f ${tmp}*
exit $rc
