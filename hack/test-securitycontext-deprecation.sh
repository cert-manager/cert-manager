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

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
TMPFILES=$TEST_TMPDIR/files

info() {
  echo "info: $1"
}

error() {
  echo "error: $1"
}

check_pattern_present() {
  message=$1
  file=$2
  pattern=$3
  set +o errexit
  grep "$pattern" "$file" >& /dev/null
  status=$?
  set -o errexit
  if [[ $status -ne 0 ]]; then
    info "generated output: ${file}"
    cat "$file"
    error "${message} - expected pattern ${pattern} is absent"
    exit 1
  fi
}

check_pattern_absent() {
  message=$1
  file=$2
  pattern=$3
  set +o errexit
  grep "$pattern" "$file" >& /dev/null
  status=$?
  set -o errexit
  if [[ $status -eq 0 ]]; then
    info "generated output: ${file}"
    cat "$file"
    error "${message} - unexpected pattern ${pattern} is present"
    exit 1
  fi
}

#
# generate_template
#
generate_template() {
  values=$1
  generated="$TMPFILES/generated.yaml"
  helm template --dry-run --values $values --name-template=jetstack --namespace=cert-manager ${SCRIPT_DIR}/../deploy/charts/cert-manager > $generated
  echo $generated
}

#
# test_use_case_1
#
test_use_case_1() {
  values="$TMPFILES/values.yaml"
  cat <<EOF > $values
---
EOF
  generated="$(generate_template $values)"
  check_pattern_absent "use case 1" $generated "      securityContext:"
  check_pattern_absent "use case 1" $generated "        enabled:"
  check_pattern_absent "use case 1" $generated "        fsGroup:"
  check_pattern_absent "use case 1" $generated "        runAsUser:"
}

#
# test_use_case_2
#
test_use_case_2() {
  values="$TMPFILES/values.yaml"
  cat <<EOF > $values
securityContext:
  enabled: true
EOF
  generated="$(generate_template $values)"
  check_pattern_present "use case 2" $generated "      securityContext:"
  check_pattern_present "use case 2" $generated "        fsGroup: 1001"
  check_pattern_present "use case 2" $generated "        runAsUser: 1001"
  check_pattern_absent  "use case 2" $generated "        enabled:"
}

#
# test_use_case_3
#
test_use_case_3() {
  values="$TMPFILES/values.yaml"
  cat <<EOF > $values
securityContext:
  enabled: true
  fsGroup: 1111
  runAsUser: 2222
EOF
  generated="$(generate_template $values)"
  check_pattern_present "use case 3" $generated "      securityContext:"
  check_pattern_present "use case 3" $generated "        fsGroup: 1111"
  check_pattern_present "use case 3" $generated "        runAsUser: 2222"
  check_pattern_absent  "use case 3" $generated "        enabled:"
}

#
# test_use_case_4
#
test_use_case_4() {
  values="$TMPFILES/values.yaml"
  cat <<EOF > $values
securityContext: {}
EOF
  generated="$(generate_template $values)"
  check_pattern_absent "use case 4" $generated "      securityContext:"
  check_pattern_absent "use case 4" $generated "        fsGroup:"
  check_pattern_absent "use case 4" $generated "        runAsUser:"
  check_pattern_absent "use case 4" $generated "        enabled:"
}

#
# test_use_case_5
#
test_use_case_5() {
  values="$TMPFILES/values.yaml"
  cat <<EOF > $values
securityContext:
  fsGroup: 1111
  runAsUser: 2222
  runAsNonRoot: true
EOF
  generated="$(generate_template $values)"
  check_pattern_present "use case 5" $generated "      securityContext:"
  check_pattern_present "use case 5" $generated "        fsGroup: 1111"
  check_pattern_present "use case 5" $generated "        runAsUser: 2222"
  check_pattern_present "use case 5" $generated "        runAsNonRoot: true"
  check_pattern_absent  "use case 5" $generated "        enabled:"
}

#
# test_use_case_6
#
test_use_case_6() {
  values="$TMPFILES/values.yaml"
  cat <<EOF > $values
securityContext:
  enabled: false
  fsGroup: 1111
  runAsUser: 2222
EOF
  generated="$(generate_template $values)"
  check_pattern_absent "use case 6" $generated "      securityContext:"
  check_pattern_absent "use case 6" $generated "        enabled:"
  check_pattern_absent "use case 6" $generated "        fsGroup:"
  check_pattern_absent "use case 6" $generated "        runAsUser:"
}

#
# test_use_case_7
#
test_use_case_7() {
  values="$TMPFILES/values.yaml"
  cat <<EOF > $values
securityContext:
  enabled: false
EOF
  generated="$(generate_template $values)"
  check_pattern_absent "use case 7" $generated "      securityContext:"
  check_pattern_absent "use case 7" $generated "        enabled:"
  check_pattern_absent "use case 7" $generated "        fsGroup:"
  check_pattern_absent "use case 7" $generated "        runAsUser:"
}

#
# test_use_case_8
#
test_use_case_8() {
  values="$TMPFILES/values.yaml"
  cat <<EOF > $values
securityContext:
  fsGroup: 1111
  runAsUser: 2222
EOF
  generated="$(generate_template $values)"
  check_pattern_present "use case 8" $generated "      securityContext:"
  check_pattern_absent  "use case 8" $generated "        enabled:"
  check_pattern_present "use case 8" $generated "        fsGroup: 1111"
  check_pattern_present "use case 8" $generated "        runAsUser: 2222"
}

#
# unit_test
#
unit_test() {
  values="$TMPFILES/values.yaml"
  cat <<EOF > $values
---
EOF
  generated="$(generate_template $values)"
  echo "following should fail"
  check_pattern_present "unit test" $generated "foo"
  echo "following should succeed"
  check_pattern_absent "unit test" $generated "foo"
  echo "following should succeed"
  check_pattern_present "unit test" $generated "kind"
  echo "following should fail"
  check_pattern_absent "unit test" $generated "kind"
}

info "testing securityContext.enabled deprecation in chart parameters"

mkdir -p "$TMPFILES"

#unit_test
test_use_case_1
test_use_case_2
test_use_case_3
test_use_case_4
test_use_case_5
test_use_case_6
test_use_case_7
test_use_case_8

info "Tests successful"
