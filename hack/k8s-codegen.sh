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

set -o errexit
set -o nounset
set -o pipefail

go=$1

clientgen=$2
deepcopygen=$3
informergen=$4
listergen=$5
defaultergen=$6
conversiongen=$7
openapigen=$8

# If the envvar "VERIFY_ONLY" is set, we only check if everything's up to date
# and don't actually generate anything

VERIFY_FLAGS=""
VERB="Generating"

if [[ ${VERIFY_ONLY:-} ]]; then
	VERIFY_FLAGS="--verify-only"
	VERB="Verifying"
fi

export VERIFY_FLAGS
export VERB

echo "+++ ${VERB} code..." >&2

module_name="github.com/cert-manager/cert-manager"

# Generate deepcopy functions for all internal and external APIs
deepcopy_inputs=(
  internal/apis/certmanager/v1alpha2 \
  internal/apis/certmanager/v1alpha3 \
  internal/apis/certmanager/v1beta1 \
  pkg/apis/certmanager/v1 \
  internal/apis/certmanager \
  internal/apis/acme/v1alpha2 \
  internal/apis/acme/v1alpha3 \
  internal/apis/acme/v1beta1 \
  pkg/apis/acme/v1 \
  internal/apis/acme \
  pkg/apis/config/cainjector/v1alpha1 \
  internal/apis/config/cainjector \
  pkg/apis/config/webhook/v1alpha1 \
  internal/apis/config/webhook \
  pkg/apis/config/controller/v1alpha1 \
  internal/apis/config/controller \
  pkg/apis/meta/v1 \
  internal/apis/meta \
  pkg/acme/webhook/apis/acme/v1alpha1 \
)

client_subpackage="pkg/client"
client_package="${module_name}/${client_subpackage}"
# Generate clientsets, listers and informers for user-facing API types
client_inputs=(
  pkg/apis/certmanager/v1 \
  pkg/apis/acme/v1 \
)

# Generate defaulting functions to be used by the mutating webhook
defaulter_inputs=(
  internal/apis/certmanager/v1alpha2 \
  internal/apis/certmanager/v1alpha3 \
  internal/apis/certmanager/v1beta1 \
  internal/apis/certmanager/v1 \
  internal/apis/acme/v1alpha2 \
  internal/apis/acme/v1alpha3 \
  internal/apis/acme/v1beta1 \
  internal/apis/acme/v1 \
  internal/apis/config/cainjector/v1alpha1 \
  internal/apis/config/webhook/v1alpha1 \
  internal/apis/config/controller/v1alpha1 \
  internal/apis/meta/v1 \
)

# Generate conversion functions to be used by the conversion webhook
conversion_inputs=(
  internal/apis/certmanager/v1alpha2 \
  internal/apis/certmanager/v1alpha3 \
  internal/apis/certmanager/v1beta1 \
  internal/apis/certmanager/v1 \
  internal/apis/acme/v1alpha2 \
  internal/apis/acme/v1alpha3 \
  internal/apis/acme/v1beta1 \
  internal/apis/acme/v1 \
  internal/apis/config/cainjector/v1alpha1 \
  internal/apis/config/webhook/v1alpha1 \
  internal/apis/config/controller/v1alpha1 \
  internal/apis/meta/v1 \
)

# clean will delete files matching name in path.
clean() {
  if [[ ${VERIFY_ONLY:-} ]]; then
      # don't delete files if we're only verifying
      return 0
  fi

  path=$1
  name=$2
  if [[ ! -d "$path" ]]; then
    return 0
  fi
  find "$path" -name "$name" -delete
}

mkcp() {
  src="$1"
  dst="$2"
  mkdir -p "$(dirname "$dst")"
  cp "$src" "$dst"
}

# Export mkcp for use in sub-shells
export -f mkcp

gen-openapi-acme() {
  clean pkg/acme/webhook/openapi '*.go'
  echo "+++ ${VERB} ACME openapi..." >&2
  mkdir -p hack/openapi_reports
  "$openapigen" \
    ${VERIFY_FLAGS} \
    --go-header-file "hack/boilerplate-go.txt" \
    --report-filename "hack/openapi_reports/acme.txt" \
    --input-dirs "k8s.io/apimachinery/pkg/version" \
    --input-dirs "k8s.io/apimachinery/pkg/runtime" \
    --input-dirs "k8s.io/apimachinery/pkg/apis/meta/v1" \
    --input-dirs "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1" \
    --input-dirs "github.com/cert-manager/cert-manager/pkg/acme/webhook/apis/acme/v1alpha1" \
    --trim-path-prefix "github.com/cert-manager/cert-manager" \
    --output-package "github.com/cert-manager/cert-manager/pkg/acme/webhook/openapi" \
    --output-base ./ \
		-O zz_generated.openapi
}

gen-deepcopy() {
  clean pkg/apis 'zz_generated.deepcopy.go'
  clean pkg/acme/webhook/apis 'zz_generated.deepcopy.go'
  clean pkg/webhook/handlers/testdata/apis 'zz_generated.deepcopy.go'
  echo "+++ ${VERB} deepcopy methods..." >&2
  prefixed_inputs=( "${deepcopy_inputs[@]/#/$module_name/}" )
  joined=$( IFS=$','; echo "${prefixed_inputs[*]}" )
  "$deepcopygen" \
    ${VERIFY_FLAGS} \
    --go-header-file hack/boilerplate-go.txt \
    --input-dirs "$joined" \
    --output-file-base zz_generated.deepcopy \
    --trim-path-prefix="$module_name" \
    --bounding-dirs "${module_name}" \
    --output-base ./
}

gen-clientsets() {
  clean "${client_subpackage}"/clientset '*.go'
  echo "+++ ${VERB} clientset..." >&2
  prefixed_inputs=( "${client_inputs[@]/#/$module_name/}" )
  joined=$( IFS=$','; echo "${prefixed_inputs[*]}" )
  "$clientgen" \
    ${VERIFY_FLAGS} \
    --go-header-file hack/boilerplate-go.txt \
    --clientset-name versioned \
    --input-base "" \
    --input "$joined" \
    --trim-path-prefix="$module_name" \
    --output-package "${client_package}"/clientset \
    --output-base ./
}

gen-listers() {
  clean "${client_subpackage}/listers" '*.go'
  echo "+++ ${VERB} listers..." >&2
  prefixed_inputs=( "${client_inputs[@]/#/$module_name/}" )
  joined=$( IFS=$','; echo "${prefixed_inputs[*]}" )
  "$listergen" \
    ${VERIFY_FLAGS} \
    --go-header-file hack/boilerplate-go.txt \
    --input-dirs "$joined" \
    --trim-path-prefix="$module_name" \
    --output-package "${client_package}"/listers \
    --output-base ./
}

gen-informers() {
  clean "${client_subpackage}"/informers '*.go'
  echo "+++ ${VERB} informers..." >&2
  prefixed_inputs=( "${client_inputs[@]/#/$module_name/}" )
  joined=$( IFS=$','; echo "${prefixed_inputs[*]}" )
  "$informergen" \
    ${VERIFY_FLAGS} \
    --go-header-file hack/boilerplate-go.txt \
    --input-dirs "$joined" \
    --versioned-clientset-package "${client_package}"/clientset/versioned \
    --listers-package "${client_package}"/listers \
    --trim-path-prefix="$module_name" \
    --output-package "${client_package}"/informers \
    --output-base ./
}

gen-defaulters() {
  clean internal/apis 'zz_generated.defaults.go'
  clean pkg/webhook/handlers/testdata/apis 'zz_generated.defaults.go'
  echo "+++ ${VERB} defaulting functions..." >&2
  prefixed_inputs=( "${defaulter_inputs[@]/#/$module_name/}" )
  joined=$( IFS=$','; echo "${prefixed_inputs[*]}" )
  "$defaultergen" \
    ${VERIFY_FLAGS} \
    --go-header-file hack/boilerplate-go.txt \
    --input-dirs "$joined" \
    --trim-path-prefix="$module_name" \
    -O zz_generated.defaults \
    --output-base ./
}

gen-conversions() {
  clean internal/apis 'zz_generated.conversion.go'
  clean pkg/webhook/handlers/testdata/apis 'zz_generated.conversion.go'
  echo "+++ ${VERB} conversion functions..." >&2

  CONVERSION_EXTRA_PEER_PKGS=(
    github.com/cert-manager/cert-manager/internal/apis/meta \
    github.com/cert-manager/cert-manager/internal/apis/meta/v1 \
    github.com/cert-manager/cert-manager/pkg/apis/meta/v1
  )
  CONVERSION_PKGS=( "${conversion_inputs[@]/#/$module_name/}" )

  "$conversiongen" \
      ${VERIFY_FLAGS} \
      --go-header-file hack/boilerplate-go.txt \
      --extra-peer-dirs $( IFS=$','; echo "${CONVERSION_EXTRA_PEER_PKGS[*]}" ) \
      --extra-dirs $( IFS=$','; echo "${CONVERSION_PKGS[*]}" ) \
      --input-dirs $( IFS=$','; echo "${CONVERSION_PKGS[*]}" ) \
      --trim-path-prefix="$module_name" \
      -O zz_generated.conversion \
      --output-base ./
}

gen-openapi-acme
gen-deepcopy
gen-clientsets
gen-listers
gen-informers
gen-defaulters
gen-conversions
