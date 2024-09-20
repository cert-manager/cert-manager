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
cd "$here/.." || exit 1
set -e

_default_bindir=$(make print-bindir)

BINDIR=${BINDIR:-$_default_bindir}

# Why do we only run 20 tests concurrently? Because we have noticed that
# many tests start timing out when the Prow pod gets overloaded. We are
# using a n1-standard-8 VM (7900m vCPU and 24GB RAM), and the pod requests
# 3500m of vCPU and 12GB of RAM.
#
# The components that seem to overload are kyverno (which is in the hot
# path of kube-apiserver), etcd, the kube-apiserver. cert-manager then
# becomes sluggish due to slow calls to the apiserver.
#
# In the following table, the first column shows the various -nodes values
# tested when running ginkgo. The "test duration" is the time spent while
# running "ginkgo", and the column"timeouts" column shows the number of
# tests that failed with a time out (including the tests that are retried;
# tests that show in the "Flaky" column in the Prow UI are thus counted
# twice).
#
#
#  | nodes | ginkgo duration | timeouts | total duration |  startup time  | link  |
#  |-------|-----------------|----------|----------------|----------------|-------|
#  | 5     | 37m 49s         | 0        | 40m 21s        | 2m 32s   (hot) | [1][] |
#  | 10    | 27m 49s         | 0        | 34m 53s        | 7m 4s   (cold) | [2][] |
#  | 20    | 24m 16s         | 0        | 26m 46s        | 2m 30s   (hot) | [3][] |
#  | 20    | 24m 15s         | 1        | 30m 15s        | 6m 0s   (cold) | [4][] |
#  | 30    | 23m 42s         | 0        | 26m 35s        | 2m 53s   (hot) | [5][] |
#  | 40    | 26m 26s         | 26       | 29m 29s        | 3m 3s    (hot) | [6][] |
#  | 50    | interrupted (*) |          |                |          (hot) | [7][] |
#
# The startup time is calculated by subtracting the "started time" visible
# on the Prow UI with the first line that has a timestamp. This time
# depends on whether this Kubernetes node already has a cache or not.
#
# These results have no statistical significance since each line is the
# result of a single Prow job. But these results still show that 10 is a
# good number.
#
# (*) It seems like at 50 nodes the pod gets killed somehow.
#
#  [1]: https://prow.build-infra.jetstack.net/view/gs/jetstack-logs/pr-logs/pull/cert-manager_cert-manager/4968/pull-cert-manager-make-e2e-v1-23/1507028321639075840
#  [2]: https://prow.build-infra.jetstack.net/view/gs/jetstack-logs/pr-logs/pull/cert-manager_cert-manager/4968/pull-cert-manager-make-e2e-v1-23/1507002589567258624
#  [3]: https://prow.build-infra.jetstack.net/view/gs/jetstack-logs/pr-logs/pull/cert-manager_cert-manager/4968/pull-cert-manager-make-e2e-v1-23/1506994096810496000
#  [4]: https://prow.build-infra.jetstack.net/view/gs/jetstack-logs/pr-logs/pull/cert-manager_cert-manager/4968/pull-cert-manager-make-e2e-v1-23/1506974361645486080
#  [5]: https://prow.build-infra.jetstack.net/view/gs/jetstack-logs/pr-logs/pull/cert-manager_cert-manager/4968/pull-cert-manager-make-e2e-v1-23/1507011895024947200
#  [6]: https://prow.build-infra.jetstack.net/view/gs/jetstack-logs/pr-logs/pull/cert-manager_cert-manager/4968/pull-cert-manager-make-e2e-v1-23/1507019887451574272
#  [7]: https://prow.build-infra.jetstack.net/view/gs/jetstack-logs/pr-logs/pull/cert-manager_cert-manager/4968/pull-cert-manager-make-e2e-v1-23/1507040653668782080

nodes=40

flake_attempts=1

ginkgo_skip=
ginkgo_focus=

feature_gates=AdditionalCertificateOutputFormats=true,ExperimentalCertificateSigningRequestControllers=true,ExperimentalGatewayAPISupport=true,LiteralCertificateSubject=true,OtherNames=true

artifacts="./$BINDIR/artifacts"

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
      default, the JUnit XML files are saved to $artifacts

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
    eval "$(tr '[:upper:]' '[:lower:]' <<<"$v")=\"${!v}\""
  fi
done

ginkgo_args=("$@")

if [[ -n "$ginkgo_focus" ]]; then ginkgo_args+=(--ginkgo.focus="${ginkgo_focus}"); fi
if [[ -n "$ginkgo_skip" ]]; then ginkgo_args+=(--ginkgo.skip="${ginkgo_skip}"); fi


# Ginkgo doesn't stream the logs when running in parallel (--nodes). Let's
# disable parallelism to force Ginkgo to stream the logs when
# --ginkgo.focus or GINKGO_FOCUS is set, since --ginkgo.focus and
# GINKGO_FOCUS are often used to debug a specific test.
if [[ "${ginkgo_args[*]}" =~ ginkgo.focus ]]; then
  nodes=1
  ginkgo_args+=(--ginkgo.v --test.v)
fi

ginkgo_color=

if ! should_color; then
	ginkgo_color="--no-color"
fi

mkdir -p "$artifacts"

export CGO_ENABLED=0

trace ginkgo \
  --tags=e2e_test \
  --procs="$nodes" \
  --output-dir="$artifacts" \
  --junit-report="junit__01.xml" \
  --flake-attempts="$flake_attempts" \
  --timeout="1h" \
  $ginkgo_color \
  -v \
  --randomize-all \
  --trace \
  --poll-progress-after=60s \
  ./test/e2e/ \
  -- \
  --repo-root="$PWD" \
  --report-dir="$artifacts" \
  --acme-dns-server="${SERVICE_IP_PREFIX}.16" \
  --acme-ingress-ip="${SERVICE_IP_PREFIX}.15" \
  --acme-gateway-ip="${SERVICE_IP_PREFIX}.14" \
  --ingress-controller-domain=ingress-nginx.http01.example.com \
  --gateway-domain=gateway.http01.example.com \
  --feature-gates="$feature_gates" \
  "${ginkgo_args[@]}"
