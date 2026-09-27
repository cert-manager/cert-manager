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

set -o nounset
set -o errexit
set -o pipefail

SCRIPT_ROOT="$( cd "$( dirname "${BASH_SOURCE[0]}" )" > /dev/null && pwd )"
export REPO_ROOT="${SCRIPT_ROOT}/.."

usage_and_exit() {
	echo "usage: $0 <path-to-helm> <path-to-kind> <path-to-ytt> <path-to-kubectl> <path-to-cmctl> <host-architecture>" >&2
	exit 1
}

if [[ -z "${1:-}" || -z "${2:-}" || -z "${3:-}" ||-z "${4:-}" || -z "${5:-}" || -z "${6:-}" ]]; then
	usage_and_exit
fi

helm=$(realpath "$1")
kind=$(realpath "$2")
ytt=$(realpath "$3")
kubectl=$(realpath "$4")
cmctl=$(realpath "$5")

HOST_ARCH=$6

# Passed by make/test.mk, which already computes it; only used in log lines
GIT_COMMIT="${GIT_COMMIT:-unknown}"

HELM_URL="oci://quay.io/jetstack/charts/cert-manager"

manifest_url() {
	echo "https://github.com/cert-manager/cert-manager/releases/download/$1/cert-manager.yaml"
}

die() {
	echo "$1" >&2
	echo "Set INITIAL_RELEASE=vX.Y.Z, or UPGRADE_TEST_INITIAL_RELEASE=vX.Y.Z via make, to choose a starting version explicitly." >&2
	exit 1
}

# Resolve the release to upgrade from, unless the caller pinned one: the newest published one, which
# is not always the newest one tagged
if [[ -z "${INITIAL_RELEASE:-}" ]]; then
	# Prow presubmits run on a merge commit, which can reach tags the base branch cannot
	if ! nearest_tag=$(git -C "${REPO_ROOT}" describe --tags --match='v*' --abbrev=0 "${PULL_BASE_SHA:-HEAD}"); then
		die "Could not find a reachable v* git tag to derive the starting version from."
	fi

	# Unanchored, as the nearest tag is often a prerelease, e.g. v1.22.0-alpha.0
	if ! [[ "${nearest_tag}" =~ ^v([0-9]+)\.([0-9]+)\.[0-9]+ ]]; then
		die "Nearest reachable git tag is not a cert-manager release tag: ${nearest_tag}"
	fi

	# Only bare "1.x.y" tags match, as Helm's parser rejects "v1.x.y", and a constraint with no
	# prerelease part never matches a prerelease, so alpha and beta charts are skipped
	ceiling="${BASH_REMATCH[1]}.$(( BASH_REMATCH[2] + 1 )).0"

	INITIAL_RELEASE=$($helm show chart "${HELM_URL}" --version "<${ceiling}" | sed -n 's/^version: //p') \
		|| die "Could not resolve a published chart below ${ceiling} from ${HELM_URL}."

	# Guards against a prerelease slipping through the constraint, and against an empty result
	if ! [[ "${INITIAL_RELEASE}" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
		die "Resolved a prerelease or unexpected chart version below ${ceiling}: '${INITIAL_RELEASE}'"
	fi

	# The release process publishes the GitHub release before the chart, so a published chart implies
	# its static manifests exist. Checked anyway because nothing enforces that order, and failing here
	# beats failing ten minutes into the run. Retried so a transient error is not read as a missing
	# release, and time-bounded because curl honours a long Retry-After header
	status=$(curl --silent --head --location --retry 10 --retry-connrefused --retry-max-time 60 \
		--output /dev/null --write-out '%{http_code}' "$(manifest_url "${INITIAL_RELEASE}")") || status="000"
	if [[ "${status}" != "200" ]]; then
		die "${INITIAL_RELEASE} has a published chart but its static manifests returned ${status}, so the release is only half published."
	fi

	echo "+++ Resolved the newest published release below ${ceiling} -> ${INITIAL_RELEASE}"
	echo "+++ To reproduce this exact run: make test-upgrade UPGRADE_TEST_INITIAL_RELEASE=${INITIAL_RELEASE}"
fi

# Set up a fresh kind cluster

$kind delete clusters kind || :
make e2e-setup-kind

################################################
# VERIFY INSTALL, UPGRADE, UNINSTALL WITH HELM #
################################################

# Namespace we'll deploy into
NAMESPACE="${NAMESPACE:-cert-manager}"

# Release name to use with Helm
RELEASE_NAME="${RELEASE_NAME:-cert-manager}"

echo "+++ Testing upgrading from ${INITIAL_RELEASE} to commit ${GIT_COMMIT} with Helm"

# 1. INSTALL THE INITIAL RELEASE'S PUBLISHED HELM CHART

echo "+++ Installing cert-manager ${INITIAL_RELEASE} Helm chart into the cluster..."

# Upgrade or install latest published cert-manager Helm release
# We use the deprecated installCRDs=true value, to make the install work for older versions of cert-manager
$helm upgrade \
    --install \
    --wait \
    --namespace "${NAMESPACE}" \
    --set installCRDs=true \
    --create-namespace \
    --version "${INITIAL_RELEASE}" \
    "$RELEASE_NAME" \
    "$HELM_URL"

# Wait for the cert-manager api to be available
$cmctl check api --wait=2m -v=5

echo "+++ Creating some cert-manager resources.."

# Create a cert-manager issuer and cert
$kubectl apply -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml" --selector=test="first"

# Ensure cert becomes ready
$kubectl wait --for=condition=Ready cert/test1 --timeout=180s

# 2. BUILD AND UPGRADE TO HELM CHART FROM THE CURRENT MASTER

# e2e-setup-certmanager both builds and deploys the latest available chart based on the current checkout
make e2e-setup-certmanager

# Wait for the cert-manager api to be available
$cmctl check api --wait=2m -v=5

# Test that the existing cert-manager resources can still be retrieved
$kubectl get issuer/selfsigned-issuer cert/test1

echo "+++ Creating some more cert-manager resources.."

# Create another certificate
$kubectl apply -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml" --selector=test="second"

# Ensure cert becomes ready
$kubectl wait --for=condition=Ready cert/test2 --timeout=180s

# 3. UNINSTALL HELM RELEASE

echo "+++ Uninstalling the Helm release"

$kubectl delete -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml"

$helm uninstall \
    --namespace "${NAMESPACE}" \
    "$RELEASE_NAME"

$kubectl delete "namespace/${NAMESPACE}" --wait


############################################################
# VERIFY INSTALL, UPGRADE, UNINSTALL WITH STATIC MANIFESTS #
############################################################

# 1. INSTALL THE INITIAL RELEASE'S STATIC MANIFESTS

echo "+++ Testing cert-manager upgrade from ${INITIAL_RELEASE} to commit ${GIT_COMMIT} using static manifests"

echo "+++ Installing cert-manager ${INITIAL_RELEASE} using static manifests"

$kubectl apply \
	-f "$(manifest_url "${INITIAL_RELEASE}")" \
	--wait

$kubectl wait \
	--for=condition=available \
	--timeout=180s deployment/cert-manager-webhook \
	--namespace "${NAMESPACE}"

# Wait for the cert-manager api to be available
$cmctl check api --wait=2m -v=5

# Create a cert-manager issuer and cert
$kubectl apply -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml" --selector=test="first"

# Ensure cert becomes ready
$kubectl wait --for=condition=Ready cert/test1 --timeout=180s

# 2. VERIFY UPGRADE TO MASTER FROM THE INITIAL RELEASE

MANIFEST_LOCATION=${REPO_ROOT}/_bin/yaml/cert-manager.yaml

echo "+++ Installing cert-manager commit ${GIT_COMMIT} using static manifests"

# Build the static manifests
make release-manifests

RELEASE_VERSION=$(make --silent release-version)

# Overwrite image tags in the static manifests and deploy.
$ytt -f "${REPO_ROOT}/test/fixtures/upgrade/overlay/controller-ops.yaml" \
     -f "${REPO_ROOT}/test/fixtures/upgrade/overlay/cainjector-ops.yaml" \
     -f "${REPO_ROOT}/test/fixtures/upgrade/overlay/webhook-ops.yaml" \
     -f "${REPO_ROOT}/test/fixtures/upgrade/overlay/values.yaml" \
     -f $MANIFEST_LOCATION \
     --data-value app_version="${RELEASE_VERSION}" \
     --data-value arch="${HOST_ARCH}" \
     --ignore-unknown-comments | kubectl apply -f -

rollout_cmd="$kubectl rollout status deployment/cert-manager-webhook --namespace ${NAMESPACE}"
attempts=0

until $rollout_cmd; do
  $rollout_cmd
  ((attempts++))
  if [[ $attempts -gt  30 ]]; then
    echo "Upgrade failed to complete in 5 minutes"
    exit 1
  fi
  sleep 10
done

# Wait for the cert-manager api to be available
$cmctl check api --wait=2m -v=5

# Test that the existing cert-manager resources can still be retrieved
$kubectl get issuer/selfsigned-issuer cert/test1

echo "+++ Creating some cert-manager resources"

# Create another certificate
$kubectl apply -f "${REPO_ROOT}/test/fixtures/cert-manager-resources.yaml" --selector=test="second"

# Ensure cert becomes ready
$kubectl wait --for=condition=Ready cert/test2 --timeout=180s

# 3. UNINSTALL

echo "+++ Uninstalling cert-manager"

$kubectl delete -f $MANIFEST_LOCATION --wait

echo "+++ Upgrade test for $INITIAL_RELEASE complete"
