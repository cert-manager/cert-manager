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

# shellcheck disable=SC2059

here=$(dirname "${BASH_SOURCE[0]}")
source "$here/config/lib.sh"
cd "$here/../"

set -e

source ./make/kind_images.sh

mode=kind
k8s_version=1.30
name=kind

help() {
  cat <<EOF
Creates or updates a kind cluster.

Usage:
    ${bold}$0 [--mode kind] [--name NAME] [--show-image] [--help]${end}

Flags:
  # TODO: do we need this flag? kind is the only mode possible at the moment.
  --mode MODE
      Can be either kind.
  --name NAME
      The name of the cluster. Only useful when using --mode kind.
  # TODO: do we need this flag? It's not used anywhere.
  --k8s-version VERSION
      The Kubernetes version to spin up with kind. It should be either a
      minor version e.g. 1.23 or a full version e.g. 1.23.3. You can also
      use K8S_VERSION to do the same.
  --show-image
      Show the image that will be used for the cluster and exit with 0. The
      image will be of the form docker.io/kindest/node:1.23@sha256:498...81ac.

Environment variables:
  ${green}K8S_VERSION${end}
        The Kubernetes version to use. Defaults to $k8s_version.
EOF
  exit
}

show_image=
while [ $# -ne 0 ]; do
  case "$1" in
  --*=*)
    echo "the flag $1 is invalid, please use '${1%=*} ${1#*=}'" >&2
    exit 1
    ;;
  -h | --help)
    help
    exit 0
    ;;
    # This block of code will create the variable associated the flags,
    # $mode, $name, and $k8s_version and then set them to the value provided.
    # E.g. "--name pinto" will create the variable named "name" set to the
    # value "pinto"--equivalent to name="pinto"
  --mode | --name | --k8s-version)
    if [ $# -lt 2 ]; then
      echo "$1 requires an argument" >&2
      exit 124
    fi
    var=$1
    var=${var/--/}
    var=${var//-/_}
    eval "$var=$2"
    shift
    ;;
  --show-image)
    show_image="yes"
    ;;
  --*)
    echo "error: unknown flag: $1" >&2
    exit 124
    ;;
  *)
    echo "no positional argument is expected" >&2
    exit 124
    ;;
  esac
  shift
done

kind_cluster_name=${name}

if printenv K8S_VERSION >/dev/null && [ -n "$K8S_VERSION" ]; then
  k8s_version="$K8S_VERSION"
fi

case "$k8s_version" in
1.25*) image=$KIND_IMAGE_K8S_125 ;;
1.26*) image=$KIND_IMAGE_K8S_126 ;;
1.27*) image=$KIND_IMAGE_K8S_127 ;;
1.28*) image=$KIND_IMAGE_K8S_128 ;;
1.29*) image=$KIND_IMAGE_K8S_129 ;;
1.30*) image=$KIND_IMAGE_K8S_130 ;;
v*) printf "${red}${redcross}Error${end}: Kubernetes version must be given without the leading 'v'\n" >&2 && exit 1 ;;
*) printf "${red}${redcross}Error${end}: unsupported Kubernetes version ${yel}${k8s_version}${end}\n" >&2 && exit 1 ;;
esac

if [ -n "$show_image" ]; then
  echo "$image"
  exit 0
fi

setup_kind() {
  # (1) Does the kind cluster already exist?
  if ! kind get clusters -q | grep -q "^$kind_cluster_name\$"; then
    trace kind create cluster --config "make/config/kind/cluster.yaml" \
      --image "$image" \
      --name "$kind_cluster_name"
  fi

  # (2) Does the kube config contain the context for this existing kind cluster?
  if ! kubectl config get-contexts -oname 2>/dev/null | grep -q "^kind-${kind_cluster_name}$"; then
    printf "${red}${redcross}Error${end}: the kind cluster ${yel}$kind_cluster_name${end} already exists, but your current kube config does not contain the context ${yel}kind-$kind_cluster_name${end}. Run:\n" >&2
    printf "    ${cyan}kind delete cluster --name $kind_cluster_name${end}\n" >&2
    printf "and then retry.\n"
    exit 1
  fi

  # (3) Is the existing kind cluster selected as the current context in the kube
  # config?
  if [ "$(kubectl config current-context 2>/dev/null)" != "kind-$kind_cluster_name" ]; then
    printf "${red}${redcross}Error${end}: the kind cluster ${yel}$kind_cluster_name${end} already exists, but is not selected as your current context. Run:\n" >&2
    printf "    ${cyan}kubectl config use-context kind-$kind_cluster_name${end}\n" >&2
    exit 1
  fi

  # (4) Is the current context responding?
  if ! kubectl --context "kind-$kind_cluster_name" get nodes >/dev/null 2>&1; then
    printf "${red}${redcross}Error${end}: the kind cluster $kind_cluster_name isn't responding. Please run:\n" >&2
    printf "    ${cyan}kind delete cluster --name $kind_cluster_name${end}\n" >&2
    printf "and then retry.\n"
    exit 1
  fi

  # (5) Does the current context have the correct Kubernetes version?
  existing_version=$(kubectl version -oyaml | yq e '.serverVersion | .major +"."+ .minor' -)
  if ! [[ "$k8s_version" =~ ${existing_version//./\.} ]]; then
    printf "${yel}${warn}Warning${end}: your current kind cluster runs Kubernetes %s, but %s is the expected version. Run:\n" "$existing_version" "$k8s_version" >&2
    printf "    ${cyan}kind delete cluster --name $kind_cluster_name${end}\n" >&2
    printf "and then retry.\n" >&2
  fi


  # (6) Has the Corefile been patched?
  corefile=$(kubectl get -ogo-template='{{.data.Corefile}}' -n=kube-system configmap/coredns)
  to_be_appended=$'example.com:53 {\n    forward . '$SERVICE_IP_PREFIX$'.16\n}\n'
  if ! grep -q --null-data -F "$(tr -d $'\n' <<<"$to_be_appended")" <(tr -d $'\n' <<<"$corefile"); then
    kubectl create configmap -oyaml coredns --dry-run=client --from-literal=Corefile="$(printf '%s\n%s' "$corefile" "$to_be_appended")" \
      | kubectl apply -n kube-system -f - >/dev/null
  fi
}

case "$mode" in
kind) setup_kind ;;
*)
  echo "error: unknown mode: $mode" >&2
  exit 124
  ;;
esac
