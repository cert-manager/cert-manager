#!/usr/bin/env bash

# Copyright 2020 The cert-manager Authors.
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

# shellcheck disable=SC2059

set -o nounset
set -o errexit
set -o pipefail

export SERVICE_IP_PREFIX="10.0.0"
export DNS_SERVER="${SERVICE_IP_PREFIX}.16"
export INGRESS_IP="${SERVICE_IP_PREFIX}.15"
export GATEWAY_IP="${SERVICE_IP_PREFIX}.14"

red=
green=
yel=
cyan=
bold=
gray=
end=
warn=
wait=
greencheck=
redcross=

should_color() {
	if [[ "${CI:-}" == "true" ]]; then
		return 1
	elif [[ "${NO_COLOR:-}" ]]; then
		return 1
	fi

	return 0
}

if should_color >/dev/null; then
  red="\033[0;31m"
  green="\033[0;32m"
  yel="\033[0;33m"
  cyan="\033[0;36m" # C = cyan
  bold="\033[0;37m" # B = white bold
  gray="\033[0;90m"
  end="\033[0m" # E is the "end" marker.
  warn="⚠️  "
  wait="⏳️  "
  greencheck="✅  "
  redcross="❌  "
fi

# Color stuff. Usage:
#    echo "Test in yellow!" | color "$yel"
# or if you just want some ANSI codes to be interpreted:
#    echo "${yel}Test in yellow!${end}" | color
color() {
  if printenv 1 >/dev/null; then
    # Let's prevent accidental interference from programs that also print
    # colors. Caveat: does only work on lines that end with \n. Lines that
    # do not end with \n are discarded.
    cmd='sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g"'
    col=${1}
  else
    cmd='cat'
    col=
  fi
  $cmd | while IFS= read -r line; do
    # We should be using "%s" "$line", but that would disable the
    # interpretation of color characters in $line.
    #
    # shellcheck disable=SC2059
    printf "${col}${line}${end}\n"
  done
}

# Shows the command before running it. Usage:
#
#     trace CMD ARGUMENTS...
#
# If you wish to trace a command that contains pipes, you can run:
#
#     trace bash -c "command | command | command"
trace() {
  # This mysterious awk expression makes sure to double-quote the arguments
  # that have special characters in them, such as spaces, curly braces (since
  # zsh interprets curly braces), interrogation marks, simple braces, and "*".
  for arg in "$@"; do echo "$arg"; done \
    | awk '{if (NR==1) printf "'"$yel"'%s '"$bold"'",$0; else if ($0 ~ / |\}|\{|\(|\)|\\|\*|\?/) printf "\"%s\" ",$0; else printf "%s ",$0} END {printf "\n"}'

  command "$@"
}
