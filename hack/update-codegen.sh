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

# Source runfiles.bash to to be able to use the rlocation function that is
# defined in the above linked script. This function finds runtime location of
# scripts thus allowing us to source other bash scripts when this script is run
# by Bazel.
# https://github.com/bazelbuild/bazel/blob/master/tools/bash/runfiles/runfiles.bash .

# The runfiles.bash is added as a dep of the update-codegen target that is
# used to run this script. Bazel places deps of sh_binary targets in runfiles
# https://docs.bazel.build/versions/main/be/shell.html#sh_binary_args and the
# following lines attempt to source this script from one of the known runfile
# location for runfiles for this target.

# set -e pipefail needs to happen after sourcing runfiles.bash, see
# https://github.com/bazelbuild/bazel/blob/master/tools/bash/runfiles/runfiles.bash#L21

# --- begin runfiles.bash initialization v2 ---
# Copy-pasted from the Bazel Bash runfiles library v2.
set -uo pipefail; f=bazel_tools/tools/bash/runfiles/runfiles.bash
source "${RUNFILES_DIR:-/dev/null}/$f" 2>/dev/null || \
  source "$(grep -sm1 "^$f " "${RUNFILES_MANIFEST_FILE:-/dev/null}" | cut -f2- -d' ')" 2>/dev/null || \
  source "$0.runfiles/$f" 2>/dev/null || \
  source "$(grep -sm1 "^$f " "$0.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null || \
  source "$(grep -sm1 "^$f " "$0.exe.runfiles_manifest" | cut -f2- -d' ')" 2>/dev/null || \
  { echo>&2 "ERROR: cannot find $f"; exit 1; }; f=; set -e
# --- end runfiles.bash initialization v2 ---


module_name="github.com/jetstack/cert-manager"

# Access to util functions
source "$(rlocation com_github_jetstack_cert_manager/hack/utils.sh)"

# Generate deepcopy functions for all internal and external APIs
deepcopy_inputs=(
  pkg/apis/certmanager/v1alpha2 \
  pkg/apis/certmanager/v1alpha3 \
  pkg/apis/certmanager/v1beta1 \
  pkg/apis/certmanager/v1 \
  internal/apis/certmanager \
  pkg/apis/acme/v1alpha2 \
  pkg/apis/acme/v1alpha3 \
  pkg/apis/acme/v1beta1 \
  pkg/apis/acme/v1 \
  internal/apis/acme \
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
  pkg/apis/certmanager/v1alpha2 \
  pkg/apis/certmanager/v1alpha3 \
  pkg/apis/certmanager/v1beta1 \
  pkg/apis/certmanager/v1 \
  pkg/apis/acme/v1alpha2 \
  pkg/apis/acme/v1alpha3 \
  pkg/apis/acme/v1beta1 \
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

shift 7

fake_gopath=""
fake_repopath=""
ensure-in-gopath() {
  export GOROOT=$go_sdk

  fake_gopath=$(mktemp -d -t codegen.gopath.XXXX)

  fake_repopath=$fake_gopath/src/github.com/jetstack/cert-manager
  mkdir -p "$fake_repopath"
  cp -R "$BUILD_WORKSPACE_DIRECTORY/." "$fake_repopath"

  export GOPATH=$fake_gopath
  cd "$fake_repopath"
  echo "Created fake GOPATH to run code generators in"
}

cleanup_gopath() {
  export GO111MODULE=off
  "$go" clean --modcache
  rm -rf "$fake_gopath" || true
}
trap cleanup_gopath EXIT

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

copyfiles() {
  # Don't copy data if the workspace directory is already within the GOPATH
  if [ "${BUILD_WORKSPACE_DIRECTORY:0:${#GOPATH}}" = "$GOPATH" ]; then
    return 0
  fi

  path=$1
  name=$2
  if [[ ! -d "$path" ]]; then
    return 0
  fi
  (
    cd "$GOPATH/src/$module_name/$path"

    find "." -name "$name" -exec bash -c "mkcp {} \"$BUILD_WORKSPACE_DIRECTORY/$path/{}\"" \;
  )
}

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
    --bounding-dirs "${module_name}"
  for dir in "${deepcopy_inputs[@]}"; do
    copyfiles "$dir" "zz_generated.deepcopy.go"
  done
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
    --output-package "${client_package}"/clientset
  copyfiles "${client_subpackage}/clientset" "*.go"
}

gen-listers() {
  clean "${client_subpackage}/listers" '*.go'
  echo "Generating listers..." >&2
  prefixed_inputs=( "${client_inputs[@]/#/$module_name/}" )
  joined=$( IFS=$','; echo "${prefixed_inputs[*]}" )
  "$listergen" \
    --go-header-file hack/boilerplate/boilerplate.generatego.txt \
    --input-dirs "$joined" \
    --output-package "${client_package}"/listers
  copyfiles "${client_subpackage}/listers" "*.go"
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
    --output-package "${client_package}"/informers
  copyfiles "${client_subpackage}/informers" "*.go"
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
    -O zz_generated.defaults
  for dir in "${defaulter_inputs[@]}"; do
    copyfiles "$dir" "zz_generated.defaults.go"
  done
}

# TODO: fix the workarounds in this function, files that start with "// +build
# !ignore_autogenerated" and "//go:build !ignore_autogenerated" are ignored by the
# conversion-gen tool, causing an incorrect 'zz_generated.conversion.go' to be
# generated. This bug should get resolved in
# https://github.com/kubernetes/kubernetes/issues/101567
gen-conversions() {
  clean internal/apis 'zz_generated.conversion.go'
  clean pkg/webhook/handlers/testdata/apis 'zz_generated.conversion.go'
  echo "Generating conversion functions..." >&2

  # meta api
  "$conversiongen" --go-header-file hack/boilerplate/boilerplate.generatego.txt \
    --input-dirs github.com/jetstack/cert-manager/internal/apis/meta/v1 \
    -O zz_generated.conversion
  
  # Workaround (see: https://github.com/kubernetes/kubernetes/issues/101567).
  remove_go_autogen_tags "internal/apis/meta/v1/zz_generated.conversion.go"

  # acme and certmanager apis
  for v in v1alpha2 v1alpha3 v1beta1 v1
  do
    "$conversiongen" --go-header-file hack/boilerplate/boilerplate.generatego.txt \
      --input-dirs "github.com/jetstack/cert-manager/internal/apis/acme/$v" \
      -O zz_generated.conversion \
      --extra-dirs github.com/jetstack/cert-manager/internal/apis/meta/v1
    
    # Workaround (see: https://github.com/kubernetes/kubernetes/issues/101567)
    remove_go_autogen_tags "internal/apis/acme/$v/zz_generated.conversion.go"

    "$conversiongen" --go-header-file hack/boilerplate/boilerplate.generatego.txt \
      --input-dirs "github.com/jetstack/cert-manager/internal/apis/certmanager/$v" \
      -O zz_generated.conversion \
      --extra-dirs "github.com/jetstack/cert-manager/internal/apis/meta/v1,github.com/jetstack/cert-manager/internal/apis/acme/$v"

    # Workaround (see: https://github.com/kubernetes/kubernetes/issues/101567)
    remove_go_autogen_tags "internal/apis/certmanager/$v/zz_generated.conversion.go"
  done

  # test apis
  "$conversiongen" --go-header-file hack/boilerplate/boilerplate.generatego.txt \
    --input-dirs github.com/jetstack/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/v2,github.com/jetstack/cert-manager/pkg/webhook/handlers/testdata/apis/testgroup/v1 \
    -O zz_generated.conversion
  
  # copy into source folder
  for dir in "${conversion_inputs[@]}"; do
    # Workaround (see: https://github.com/kubernetes/kubernetes/issues/101567)
    replace_go_autogen_tags "$dir/zz_generated.conversion.go"
    copyfiles "$dir" "zz_generated.conversion.go"
  done
}

runfiles="$(pwd)"
export GO111MODULE=off
ensure-in-gopath
old=${GOCACHE:-}
export GOCACHE=$(mktemp -d -t codegen.gocache.XXXX)
export GO111MODULE=on
export GOSUMDB=sum.golang.org
"$go_sdk/bin/go" mod vendor
export GO111MODULE=off
export GOCACHE=$old

gen-deepcopy
gen-clientsets
gen-listers
gen-informers
gen-defaulters
gen-conversions

## Call update-bazel
export GO111MODULE=on
cd "$runfiles"
"$@"
