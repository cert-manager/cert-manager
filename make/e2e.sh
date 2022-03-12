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
cd "$here/.." || exit 1
set -e

flake_attempts=1
nodes=10
ginkgo_skip=
ginkgo_focus=
feature_gates=AdditionalCertificateOutputFormats=true,ExperimentalCertificateSigningRequestControllers=true,ExperimentalGatewayAPISupport=true
artifacts=
help() {
  cat <<EOF | color ""
Runs the end-to-end test suite against an already configured kind cluster.

Usage:
  ${bold}$(basename "$0") [--help] [args-for-ginkgo]${end}

Examples:
  ${bold}$(basename "$0") --ginkgo.skip='Venafi TPP|Venafi Cloud'${end}
  ${bold}$(basename "$0") --gingko.focus '.*a failing certificate that had a wrong dns name' --ginkgo.v --test.v -v=4${end}

Environment variables:
  ${green}GINKGO_FOCUS${end}
      If set, only run the test suite that matches the given regex. It is
      identical to running ${bold}--ginkgo.focus${end} on the command line.
      This environment variable is useful when running this script from make.
      For example:
          ${bold}make e2e GINKGO_SKIP='.*had a wrong dns name'${end}
  ${green}GINKGO_SKIP${end}
      If set, skip the test suite that matches the given regex. It is
      identical to running ${bold}--ginkgo.skip${end} on the command line.
  ${green}FLAKE_ATTEMPTS${end}
      The number of times to attempt to run each test case before giving up.
      The default is $flake_attempts.
  ${green}NODES${end}
      Ginkgo's parallelism. The default is $nodes.
  ${green}FEATURE_GATES${end}
      The feature gates that cert-manager is currently running with. Defaults
      to $feature_gates
  ${green}ARTIFACTS${end}
      The path to a directory where the JUnit XML files will be stored. By
      default, the JUnit XML files are not saved.

Details:
  Imagine you got the following failure:

    ${gray}1 |${end} ${red}• Failure [60.079 seconds]${end}
    ${gray}2 |${end} [Conformance] Certificates
    ${gray}3 |${end} ${gray}test/e2e/framework/framework.go:287${end}
    ${gray}4 |${end}   with an External Issuer
    ${gray}5 |${end}   ${gray}test/e2e/suite/conformance/certificates/tests.go:48${end}
    ${gray}6 |${end}     Creating a Gateway [It]
    ${gray}7 |${end}     ${gray}test/e2e/suite/conformance/certificates/suite.go:105${end}

  You need to "reconstruct" the name of the test case. The ending [It] must be
  removed. In the above example, the name of the test is:

    [Conformance] Certificates with an External Issuer Creating a Gateway
    ${gray}<------------------------> <---------------------> <---------------->${end}
    ${gray}         line 2                    line 4                line 6${end}

  To re-run this specific test case, you can use the following command:

    ${bold}$(basename "$0") --ginkgo.focus '\[Conformance\] Certificates with an External Issuer Creating a Gateway'${end}

  If you want, you can match the end of the test case name:

    ${bold}$(basename "$0") --ginkgo.focus '.*Creating a Gateway'${end}

  Note that if you use GINKGO_FOCUS or --ginkgo.focus, Ginkgo's parallelism will
  be turned off in order to see the logs streamed (instead of waiting until test
  ends before being able to see the logs).
EOF
  exit 0
}

if [ $# -gt 0 ]; then
  case "$1" in
  -h | --help)
    help
    ;;
  esac
fi

for v in FEATURE_GATES FLAKE_ATTEMPTS NODES GINKGO_FOCUS GINKGO_SKIP ARTIFACTS; do
  if printenv "$v" >/dev/null && [ -n "${!v}" ]; then
    eval "$(tr '[:upper:]' '[:lower:]' <<<"$v")"="${!v}"
  fi
done

# Skip Gateway tests for Kubernetes below v1.19.
k8s_version=$(kubectl version -oyaml | yq e '.serverVersion | .major +"."+ .minor' -)
case "$k8s_version" in
1.16* | 1.17* | 1.18*)
  printf "${yel}${warn}Warning${end}: Kubernetes version ${k8s_version}, skipping Gateway tests.\n" >&2

  if [[ -z "$ginkgo_skip" ]]; then
    ginkgo_skip="Gateway"
  else
    # duplicates are ok
    ginkgo_skip="${ginkgo_skip}|Gateway"
  fi
  ;;
esac

if [[ -n "$ginkgo_focus" ]]; then ginkgo_focus="--ginkgo.focus=${ginkgo_focus}"; fi
if [[ -n "$ginkgo_skip" ]]; then ginkgo_skip="--ginkgo.skip=${ginkgo_skip}"; fi

# Only enable junit output if ARTIFACTS is set.
extra_args=
if [[ -n "$artifacts" ]]; then
  mkdir -p "$artifacts"
  extra_args+=(--report-dir="$artifacts")
fi

# Ginkgo doesn't stream the logs when running in parallel (--nodes). Let's
# disable parallelism to force Ginkgo to stream the logs when
# --ginkgo.focus or GINKGO_FOCUS is set, since --ginkgo.focus and
# GINKGO_FOCUS are often used to debug a specific test.
if [[ "$*" =~ ginkgo.focus ]] || [[ -n "$ginkgo_focus" ]]; then
  nodes=1
  extra_args+=(--ginkgo.v --test.v)
fi

# The command "kubectl cluster-info dump" returns 141 since grep breaks the
# pipe as soon as it finds a match.
service_ip_prefix=$(set +o pipefail && kubectl cluster-info dump | grep -m1 ip-range | cut -d= -f2 | cut -d. -f1,2,3)
dns_server=${service_ip_prefix}.16
ingress_ip=${service_ip_prefix}.15

trace ginkgo \
  -nodes "$nodes" \
  -flakeAttempts "$flake_attempts" \
  -tags e2e_test \
  ./test/e2e/ \
  -- \
  --repo-root="$PWD" \
  --acme-dns-server="$dns_server" \
  --acme-ingress-ip="$ingress_ip" \
  --ingress-controller-domain=ingress-nginx.http01.example.com \
  --gateway-domain=gateway.http01.example.com \
  --feature-gates="$feature_gates" \
  $ginkgo_skip \
  $ginkgo_focus \
  "${extra_args[@]}" \
  "$@"
