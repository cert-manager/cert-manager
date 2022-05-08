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

here=$(dirname "${BASH_SOURCE[0]}")
source "$here/config/lib.sh"
cd "$here/../"
set -e

mode=kind
k8s_version=1.23
kind_cluster_name=kind

help() {
  cat <<EOF
Creates or updates a kind cluster.

Usage:
    ${bold}$0 [--mode kind] [--name NAME] [--show-image] [--help]${end}

Flags:
  --mode MODE
      Can be either kind.
  --name NAME
      The name of the cluster. Only useful when using --mode kind.
  --k8s-version VERSION
      The Kubernetes version to spin up with kind. It should be either a
      minor version e.g. 1.23 or a full version e.g. 1.23.3. You can also
      use K8S_VERSION to do the same.
  --show-image
      Show the image that will be used for the cluster and exit with 0. The
      image will be of the form docker.io/kindest/node:1.23@sha256:498...81ac.
  --update-images
      Update the kind images to the latest version.

Environment variables:
  ${green}K8S_VERSION${end}
        The Kubernetes version to use. Defaults to $k8s_version.
EOF
  exit
}

# The below image digests can be refreshed with the command:
#  make/cluster.sh --update-images
images=$(
  cat <<EOF
docker.io/kindest/node:v1.18.20@sha256:e3dca5e16116d11363e31639640042a9b1bd2c90f85717a7fc66be34089a8169
docker.io/kindest/node:v1.19.16@sha256:81f552397c1e6c1f293f967ecb1344d8857613fb978f963c30e907c32f598467
docker.io/kindest/node:v1.20.15@sha256:393bb9096c6c4d723bb17bceb0896407d7db581532d11ea2839c80b28e5d8deb
docker.io/kindest/node:v1.21.10@sha256:84709f09756ba4f863769bdcabe5edafc2ada72d3c8c44d6515fc581b66b029c
docker.io/kindest/node:v1.22.7@sha256:1dfd72d193bf7da64765fd2f2898f78663b9ba366c2aa74be1fd7498a1873166
docker.io/kindest/node:v1.23.4@sha256:0e34f0d0fd448aa2f2819cfd74e99fe5793a6e4938b328f657c8e3f81ee0dfb9
eu.gcr.io/jetstack-build-infra-images/kind:v1.24.0@sha256:2f170bf60cfad9d961711f96c34349d789a56b5783c9a5dbc0a29cb5a25ec729

EOF
)

show_image=
update_images=
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
  --show-image | --update-images)
    var=$1
    var=${var/--/}
    var=${var//-/_}
    eval "$var=yes"
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

if printenv K8S_VERSION >/dev/null && [ -n "$K8S_VERSION" ]; then
  k8s_version="$K8S_VERSION"
fi

if [ -n "$update_images" ]; then
  for img in $images; do
    sha=$(crane digest "$(cut -d@ -f1 <<<"$img")")
    if [ "$(cut -d@ -f2 <<<"$img")" != "$sha" ]; then
      trace sed -i.bak "s|^$img$|$(cut -d@ -f1 <<<"$img")@$sha|" "$0"
    else
      printf "${green}${greencheck}Info${end}: $img already uses the latest digest\n" >&2
    fi
  done
  exit 0
fi

case "$k8s_version" in
1.18*) image=$(grep -F 1.18 <<<"$images") ;;
1.19*) image=$(grep -F 1.19 <<<"$images") ;;
1.20*) image=$(grep -F 1.20 <<<"$images") ;;
1.21*) image=$(grep -F 1.21 <<<"$images") ;;
1.22*) image=$(grep -F 1.22 <<<"$images") ;;
1.23*) image=$(grep -F 1.23 <<<"$images") ;;
1.24*) image=$(grep -F 1.24 <<<"$images") ;;
v*) printf "${red}${redcross}Error${end}: the Kubernetes version must be given without the leading 'v'\n" >&2 && exit 1 ;;
*) printf "${red}${redcross}Error${end}: unsupported Kubernetes version ${yel}${k8s_version}${end}\n" >&2 && exit 1 ;;
esac

if [ -n "$show_image" ]; then
  echo "$image"
  exit 0
fi

setup_kind() {
  # When running in our CI environment the Docker network's subnet choice will
  # cause issues with routing, which can manifest in errors such as this one:
  #
  #   dial tcp: lookup charts.jetstack.io on 10.8.240.10:53: read udp 10.8.0.2:54823->10.8.240.10:53: i/o timeout
  #
  # as seen in the build [1].  We create this custom network as a workaround
  # until we have a way to properly patch this.
  #
  # [1]: https://prow.build-infra.jetstack.net/view/gs/jetstack-logs/pr-logs/pull/cert-manager_approver-policy/36/pull-cert-manager-approver-policy-smoke/1447565895923666944#1:build-log.txt%3A222
  if printenv CI >/dev/null; then
    if ! docker network inspect kind >/dev/null 2>&1; then
      docker network create --driver=bridge --subnet=192.168.0.0/16 --gateway 192.168.0.1 kind
    fi

    # Wait for the network to be created so kind does not overwrite it.
    while ! docker network inspect kind >/dev/null; do
      sleep 100ms
    done
  fi

  # (1) Does the kind cluster already exist?
  if ! kind get clusters -q | grep -q "^$kind_cluster_name\$"; then
    trace kind create cluster --config make/config/kind/v1beta2.yaml \
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

  service_ip_prefix=$(set +o pipefail && kubectl cluster-info dump | grep -m1 ip-range | cut -d= -f2 | cut -d. -f1,2,3)

  # (6) Has the Corefile been patched?
  corefile=$(kubectl get -ogo-template='{{.data.Corefile}}' -n=kube-system configmap/coredns)
  to_be_appended=$'example.com:53 {\n    forward . '$service_ip_prefix$'.16\n}\n'
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
