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

set -ueo pipefail

here=$(dirname "${BASH_SOURCE[0]}")
source "$here/../../lib/lib.sh"
cd "$here/../../../"

feature_gates="${FEATURE_GATES:-ExperimentalCertificateSigningRequestControllers=true,ExperimentalGatewayAPISupport=true,AdditionalCertificateOutputFormats=true,ServerSideApply=true}"
service_ip_prefix=
namespace=cert-manager
release=cert-manager
chart_tgz=
controller=
acmesolver=
cainjector=
webhook=
ctl=

help() {
    cat <<EOF
Usage:
    $(basename "$0") [options] [--help]

Flags:
  --chart TGZ
        The path to a Helm chart tarball of cert-manager. For
        example, bin/cert-manager-v1.7.0.tgz. By default, builds
        and uses the Helm chart produced by the command
        'make bin/cert-manager.tgz'.

  --images IMG_CONTROLLER IMG_ACMESOLVER IMG_CAINJECTOR IMG_WEBHOOK IMG_CTL
        The 5 paths to the image tarballs, e.g. "controller.tar", for each image.
        All 5 paths have to be passed simultanously, and in this order.
        By default, it uses the images produced by the command
        "make -f make/Makefile all-containers".

  --service-ip-prefix PREFIX
        The first 3 bytes of the service IP range. For example, if the service
        IP range is 10.96.0.0/15, you should give the value "10.96.0".
        By default, PREFIX is extracted by running the command
        "kubectl cluster-info dump" and looking for the flag
        "--service-cluster-ip-range".

  --feature-gates FEATURE_GATES
        A comma-separated list of feature gates to enable. See the documentation
        for --feature-gates at https://cert-manager.io/docs/cli/controller/.
        Default value: $FEATURE_GATES
EOF
    exit
}

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
    --chart)
        if [ $# -lt 2 ]; then
            echo "$1 requires an argument" >&2
            exit 124
        fi
        chart_tgz="$2"
        shift
        ;;
    --images)
        if [ $# -lt 6 ]; then
            echo "$1 requires 5 arguments" >&2
            exit 124
        fi
        controller="$2"
        acmesolver="$3"
        cainjector="$4"
        webhook="$5"
        ctl="$6"
        shift 5
        ;;
    --service-ip-prefix)
        if [ $# -lt 2 ]; then
            echo "$1 requires an argument" >&2
            exit 124
        fi
        service_ip_prefix="$2"
        shift
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

# As Feature Gates are added/removed, these lists should be updated.
supported_controller=(AllAlpha AllBeta ValidateCAA ExperimentalCertificateSigningRequestControllers ExperimentalGatewayAPISupport AdditionalCertificateOutputFormats ServerSideApply)
supported_webhook=(AllAlpha AllBeta AdditionalCertificateOutputFormats)
supported_cainjector=(AllAlpha AllBeta)

actual_controller=$(registered_feature_gates_for "${feature_gates}" "${supported_controller[@]}")
actual_webhook=$(registered_feature_gates_for "${feature_gates}" "${supported_webhook[@]}")
actual_cainjector=$(registered_feature_gates_for "${feature_gates}" "${supported_cainjector[@]}")

if [ -z "$service_ip_prefix" ]; then
    # The command "kubectl cluster-info dump" returns 141 when the pipe is
    # broken, due to grep breaking the pipe on the first match.
    service_ip_prefix=$(set +o pipefail && kubectl cluster-info dump | grep -m1 service-cluster-ip-range | cut -d= -f2 | cut -d. -f1,2,3)
fi

if [ -z "$chart_tgz" ]; then
    chart_tgz=bin/cert-manager.tgz
    trace make -j"$(nproc)" -f make/Makefile bin/cert-manager.tgz
fi

if [ -z "$controller" ] || [ -z "$acmesolver" ] || [ -z "$cainjector" ] || [ -z "$webhook" ] || [ -z "$ctl" ]; then
    controller=bin/containers/cert-manager-controller-linux-amd64.tar
    acmesolver=bin/containers/cert-manager-acmesolver-linux-amd64.tar
    cainjector=bin/containers/cert-manager-cainjector-linux-amd64.tar
    webhook=bin/containers/cert-manager-webhook-linux-amd64.tar
    ctl=bin/containers/cert-manager-ctl-linux-amd64.tar
    trace make -j"$(nproc)" -f make/Makefile $controller $acmesolver $cainjector $webhook $ctl
fi

kind_cluster_name=$(kubectl get nodes -ojson | jq '.items[0].spec.providerID' -r | cut -d/ -f4)

if [ -z "$kind_cluster_name" ]; then
    color "" >&2 <<EOF
${yel}${warn}Error${end}: the current context is not a Kind cluster. Run the following command:
    ${cyan}make kind-cluster${end}
EOF
    exit 1
fi

trace xargs -L1 -P10 kind load image-archive --name "$kind_cluster_name" <<EOF
$controller
$acmesolver
$cainjector
$webhook
$ctl
EOF

# Helm's --set interprets commas, which means we want to escape commas for
# "--set featureGates".
trace helm upgrade \
    --install \
    --create-namespace \
    --wait \
    --namespace "$namespace" \
    --set image.repository="$(tar xfO "$controller" manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f1)" \
    --set cainjector.image.repository="$(tar xfO "$cainjector" manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f1)" \
    --set webhook.image.repository="$(tar xfO "$webhook" manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f1)" \
    --set startupapicheck.image.repository="$(tar xfO "$ctl" manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f1)" \
    --set cainjector.image.repository="$(tar xfO "$cainjector" manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f1)" \
    --set webhook.image.repository="$(tar xfO "$webhook" manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f1)" \
    --set startupapicheck.image.repository="$(tar xfO "$ctl" manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f1)" \
    --set image.tag="$(tar xfO "$controller" manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f2)" \
    --set cainjector.image.tag="$(tar xfO "$cainjector" manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f2)" \
    --set webhook.image.tag="$(tar xfO "$webhook" manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f2)" \
    --set startupapicheck.image.tag="$(tar xfO "$ctl" manifest.json | jq '.[0].RepoTags[0]' -r | cut -d: -f2)" \
    --set installCRDs=true \
    --set featureGates="${actual_controller//,/\\,}" \
    --set "webhook.extraArgs={--feature-gates=${actual_webhook//,/\\,}}" \
    --set "cainjector.extraArgs={--feature-gates=${actual_cainjector//,/\\,}}" \
    --set "extraArgs={--dns01-recursive-nameservers=${service_ip_prefix}.16:53,--dns01-recursive-nameservers-only=true}" \
    "$release" \
    "$chart_tgz" >/dev/null
