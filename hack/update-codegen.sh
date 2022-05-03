#!/bin/bash
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

set -o errexit
set -o nounset
set -o pipefail

if [[ -n "${BUILD_WORKSPACE_DIRECTORY:-}" ]]; then # Running inside bazel
  echo "Updating generated clients..." >&2
elif ! command -v bazel &>/dev/null; then
  echo "Install bazel at https://bazel.build" >&2
  exit 1
else
  (
    set -o xtrace
    bazel run //hack:update-codegen
  )
  exit 0
fi

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
  pkg/apis/config/webhook/v1alpha1 \
  internal/apis/config/webhook \
  pkg/apis/meta/v1 \
  internal/apis/meta \
  pkg/webhook/handlers/testdata/apis/testgroup/v2 \
  pkg/webhook/handlers/testdata/apis/testgroup/v1 \
  pkg/webhook/handlers/testdata/apis/testgroup \
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
  internal/apis/config/webhook/v1alpha1 \
  internal/apis/meta/v1 \
  pkg/webhook/handlers/testdata/apis/testgroup/v2 \
  pkg/webhook/handlers/testdata/apis/testgroup/v1 \
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
  internal/apis/config/webhook/v1alpha1 \
  internal/apis/meta/v1 \
  pkg/webhook/handlers/testdata/apis/testgroup/v2 \
  pkg/webhook/handlers/testdata/apis/testgroup/v1 \
)

go_sdk=$PWD/external/go_sdk
go=$PWD/$1
clientgen=$PWD/$2
deepcopygen=$PWD/$3
informergen=$PWD/$4
listergen=$PWD/$5
defaultergen=$PWD/$6
conversiongen=$PWD/$7
applyconfigurationgen=$PWD/$8

shift 8

export GOROOT=$go_sdk

# clean will delete files matching name in path.
#
# When inside bazel test the files are read-only.
# Any attempts to write a file that already exists will fail.
# So resolve by deleting the files before generating them.
clean() {
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

gen-deepcopy() {
  clean pkg/apis 'zz_generated.deepcopy.go'
  clean pkg/acme/webhook/apis 'zz_generated.deepcopy.go'
  clean pkg/webhook/handlers/testdata/apis 'zz_generated.deepcopy.go'
  echo "Generating deepcopy methods..." >&2
  prefixed_inputs=( "${deepcopy_inputs[@]/#/$module_name/}" )
  joined=$( IFS=$','; echo "${prefixed_inputs[*]}" )
  "$deepcopygen" \
    --go-header-file hack/boilerplate/boilerplate.generatego.txt \
    --input-dirs "$joined" \
    --output-file-base zz_generated.deepcopy \
    --trim-path-prefix="$module_name" \
    --bounding-dirs "${module_name}" \
    --output-base ./
}

gen-applyconfigurations() {
    rm -rf "${client_subpackage}"/applyconfigurations
    echo "Generating applyconfigurations..." >&2
    prefixed_inputs=( "${client_inputs[@]/#/$module_name/}" )
    joined=$( IFS=$','; echo "${prefixed_inputs[*]}" )
    # It's necessary to have k8s.io/apimachinery/pkg/apis/meta/v1 to have
    # the proper method signature for `WithOwnerReferences` generated. If this
    # is not specified then the generated code cannot be compiled (wrong
    # import is used). This is the same as done in:
    # https://github.com/istio/client-go/pull/718/files#r770894721
    "$applyconfigurationgen" \
        --go-header-file hack/boilerplate/boilerplate.generatego.txt \
        --input-dirs "$joined",k8s.io/apimachinery/pkg/apis/meta/v1 \
        --trim-path-prefix="$module_name" \
        --output-package "${client_package}"/applyconfigurations \
        --output-base ./
    mv ./pkg/client/applyconfigurations/{cert-manager,certmanager}
    sed -i -e 's|github.com/cert-manager/cert-manager/pkg/client/applyconfigurations/cert-manager/|github.com/cert-manager/cert-manager/pkg/client/applyconfigurations/certmanager/|g' pkg/client/applyconfigurations/utils.go
}

gen-clientsets() {
  clean "${client_subpackage}"/clientset '*.go'
  echo "Generating clientset..." >&2
  prefixed_inputs=( "${client_inputs[@]/#/$module_name/}" )
  joined=$( IFS=$','; echo "${prefixed_inputs[*]}" )
  "$clientgen" \
    --go-header-file hack/boilerplate/boilerplate.generatego.txt \
    --clientset-name versioned \
    --input-base "" \
    --input "$joined" \
    --apply-configuration-package "${client_package}"/applyconfigurations \
    --trim-path-prefix="$module_name" \
    --output-package "${client_package}"/clientset \
    --output-base ./
}

gen-listers() {
  clean "${client_subpackage}/listers" '*.go'
  echo "Generating listers..." >&2
  prefixed_inputs=( "${client_inputs[@]/#/$module_name/}" )
  joined=$( IFS=$','; echo "${prefixed_inputs[*]}" )
  "$listergen" \
    --go-header-file hack/boilerplate/boilerplate.generatego.txt \
    --input-dirs "$joined" \
    --trim-path-prefix="$module_name" \
    --output-package "${client_package}"/listers \
    --output-base ./
}

gen-informers() {
  clean "${client_subpackage}"/informers '*.go'
  echo "Generating informers..." >&2
  prefixed_inputs=( "${client_inputs[@]/#/$module_name/}" )
  joined=$( IFS=$','; echo "${prefixed_inputs[*]}" )
  "$informergen" \
    --go-header-file hack/boilerplate/boilerplate.generatego.txt \
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
  echo "Generating defaulting functions..." >&2
  prefixed_inputs=( "${defaulter_inputs[@]/#/$module_name/}" )
  joined=$( IFS=$','; echo "${prefixed_inputs[*]}" )
  "$defaultergen" \
    --go-header-file hack/boilerplate/boilerplate.generatego.txt \
    --input-dirs "$joined" \
    --trim-path-prefix="$module_name" \
    -O zz_generated.defaults \
    --output-base ./
}

gen-conversions() {
  clean internal/apis 'zz_generated.conversion.go'
  clean pkg/webhook/handlers/testdata/apis 'zz_generated.conversion.go'
  echo "Generating conversion functions..." >&2

  CONVERSION_EXTRA_PEER_PKGS=(
    github.com/cert-manager/cert-manager/internal/apis/meta \
    github.com/cert-manager/cert-manager/internal/apis/meta/v1 \
    github.com/cert-manager/cert-manager/pkg/apis/meta/v1
  )
  CONVERSION_PKGS=( "${conversion_inputs[@]/#/$module_name/}" )

  "$conversiongen" \
      --go-header-file hack/boilerplate/boilerplate.generatego.txt \
      --extra-peer-dirs $( IFS=$','; echo "${CONVERSION_EXTRA_PEER_PKGS[*]}" ) \
      --extra-dirs $( IFS=$','; echo "${CONVERSION_PKGS[*]}" ) \
      --input-dirs $( IFS=$','; echo "${CONVERSION_PKGS[*]}" ) \
      --trim-path-prefix="$module_name" \
      -O zz_generated.conversion \
      --output-base ./
}

runfiles="$(pwd)"
cd "$BUILD_WORKSPACE_DIRECTORY"

gen-deepcopy
gen-applyconfigurations
gen-clientsets
gen-listers
gen-informers
gen-defaulters
gen-conversions

## Call update-bazel
cd "$runfiles"
"$@"
