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

set -o nounset
set -o errexit
set -o pipefail

export KIND_CLUSTER_NAME="${KIND_CLUSTER_NAME:-kind}"
export KIND_IMAGE_REPO="docker.io/kindest/node"
# Default Kubernetes version to use to 1.23
export K8S_VERSION=${K8S_VERSION:-1.23}
# Default OpenShift version to use to 3.11
export OPENSHIFT_VERSION=${OPENSHIFT_VERSION:-"3.11"}
export SERVICE_IP_PREFIX="${SERVICE_IP_PREFIX:-10.0.0}"
export IS_OPENSHIFT="${IS_OPENSHIFT:-"false"}"
export OPENSHIFT_VERSION="${OPENSHIFT_VERSION:-"3.11"}"
export SERVICE_IP_PREFIX="${SERVICE_IP_PREFIX:-10.0.0}"
export DNS_SERVER="${SERVICE_IP_PREFIX}.16"
export INGRESS_IP="${SERVICE_IP_PREFIX}.15"

export_logs() {
  echo "Exporting cluster logs to artifacts..."
  "${SCRIPT_ROOT}/cluster/export-logs.sh"
}

# registered_feature_gates_for returns the subset of supported of feature
# gates from the given enabled features. Usage:
#
#  registered_feature_gates_for "Feat1=true,Feat2=false,Feat3=false" Feat1 Feat3
#                               <----------------------------------> <--------->
#                                        given feature gates     supported feature gates
# This example prints:
#
#  Feat1=true,Feat3=false
registered_feature_gates_for() {
  given="${1//,/ }"
  shift
  supported=("$@")

  for val in $given; do
    if [[ "${supported[*]}" == *"${val%=*}"* ]]; then
      returned+=("$val")
    fi
  done

  # We can't use variable substitution to replace spaces with commas
  # because $returned is an array, and the substitution would only happen
  # on the individual elements, not on the whole space-separated array.
  echo "${returned[*]}" | tr ' ' ','
}

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
if ! printenv NO_COLOR >/dev/null; then
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

# Usage:
#  color "$yel"
# or
#  color
color() {
  # Let's prevent accidental interference from programs that also print colors.
  # Caveat: does only work on lines that end with \n. Lines that do not end with
  # \n are discarded.
  sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" | while IFS= read -r line; do
    printf "${1}%s${end}\n" "$line"
  done
}

# https://superuser.com/questions/184307/bash-create-anonymous-fifo
PIPE=$(mktemp -u)
mkfifo "$PIPE"
exec 3<>"$PIPE"
rm "$PIPE"
exec 3>/dev/stderr

# Shows the stdin, stdout and stderr of the given command. Usage:
#   trace CMD ARGUMENTS...
# If you wish to trace a command that contains pipes, you can run:
#   trace bash -c "command | command | command"
trace() {
  # This mysterious perl expression makes sure to double-quote the arguments
  # that have special characters in them, such as spaces, curly braces (since
  # zsh interprets curly braces), interogation marks, simple braces, and "*".
  LANG=C perl -e "print \"${yel}$1${end} \""', join(" ", map { $_ =~ / |}|{|\(|\)|\\|\*|\?/ ? "\"".$_."\"" : $_} @ARGV)' -- "${@:2}" >&3

  # (1) We only need to "show" stdin if stdin is attached to a tty.
  # (2) We only need to print stdout to stdout when stdout is attached to a
  #     pipe. It it is attached to a pseudo terminal, we don't need to print it
  #     again since we already print the stdout in gray.
  if ! [ -t 0 ] && ! [ -t 1 ]; then
    tee >(
      color "$red" <<<" <<EOF" >&3
      color "$gray" >&3
      color "$red" <<<"EOF" >&3
    ) | command "$@" 2> >(color "$gray" >&3) > >(tee >(color "$gray" >&3))

  elif ! [ -t 0 ] && [ -t 1 ]; then
    tee >(
      color "$red" <<<" <<EOF" >&3
      color "$gray" >&3
      color "$red" <<<"EOF" >&3
    ) | command "$@" 2> >(color "$gray" >&3) > >(color "$gray" >&3)
  elif [ -t 0 ] && ! [ -t 1 ]; then
    printf "\n" >&3
    command "$@" 2> >(color "$gray" >&3) > >(tee >(color "$gray" >&3))
  elif [ -t 0 ] && [ -t 1 ]; then
    printf "\n" >&3
    command "$@" 2> >(color "$gray" >&3) > >(color "$gray" >&3)
  fi
}
