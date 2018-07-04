#!/usr/bin/env bash

## This script has been taken from https://github.com/kubernetes-helm/chart-testing
## It has the same dependencies as described in that repo, and should ideally be run
## within the docker image published by that same repository in order to make sure
## the correct dependencies are included.
##
## Run from within the root of the repository with:
##
## docker run --rm -v "$(pwd):/workdir" --workdir /workdir \
##    gcr.io/kubernetes-charts-ci/chart-testing:v1.0.2 \
##    /workdir/test/chart_test.sh \
##    --no-install \
##    --config test/.testenv

# Copyright 2018 The Helm Authors. All rights reserved.
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

readonly REPO_ROOT=$(git rev-parse --show-toplevel)
readonly SCRIPT_DIR=$(dirname "$(readlink -f "$0")")

show_help() {
cat << EOF
Usage: $(basename "$0") <options>
    Lint, install, and test Helm charts.
    -h, --help        Display help
    --verbose         Display verbose output
    --no-lint         Skip chart linting
    --no-install      Skip chart installation
    --config          Path to the config file (optional)
    --                End of all options
EOF
}

main() {
    local no_lint=
    local no_install=
    local config=
    local verbose=

    while :; do
        case "${1:-}" in
            -h|--help)
                show_help
                exit
                ;;
            --verbose)
                verbose=true
                ;;
            --no-install)
                no_install=true
                ;;
            --no-lint)
                no_lint=true
                ;;
            --config)
                if [ -n "$2" ]; then
                    config="$2"
                    shift
                else
                    echo "ERROR: '--config' cannot be empty." >&2
                    exit 1
                fi
                ;;
            -?*)
                echo "WARN: Unknown option (ignored): $1" >&2
                ;;
            *)
                break
                ;;
        esac

        shift
    done

    if [[ -n "$config" ]]; then
        if [[ -f "$config" ]]; then
            # shellcheck disable=SC1090
            source "$config"
        else
            echo "ERROR: Specified config file does not exist: $config" >&2
            exit 1
        fi
    fi

    # shellcheck source=lib/chartlib.sh
    source "$SCRIPT_DIR/lib/chartlib.sh"

    [[ -n "$verbose" ]] && set -o xtrace

    pushd "$REPO_ROOT" > /dev/null

    local exit_code=0

    read -ra changed_dirs <<< "$(chartlib::detect_changed_directories)"

    if [[ -n "${changed_dirs[*]}" ]]; then
        echo "Charts to be installed and tested: ${changed_dirs[*]}"

        chartlib::init_helm

        local summary=()

        for chart_dir in "${changed_dirs[@]}"; do
            echo ''
            echo '--------------------------------------------------------------------------------'
            echo " Processing chart '$chart_dir'..."
            echo '--------------------------------------------------------------------------------'
            echo ''

            local error=

            if [[ -z "$no_lint" ]]; then
                if ! chartlib::validate_chart "$chart_dir"; then
                    error=true
                fi
                if ! chartlib::lint_chart_with_all_configs "$chart_dir"; then
                    error=true
                fi
            fi

            if [[ -z "$no_install" && -z "$error" ]]; then
                if ! chartlib::install_chart_with_all_configs "$chart_dir"; then
                    error=true
                fi
            fi

            if [[ -z "$error" ]]; then
                summary+=(" ✔︎ $chart_dir")
            else
                summary+=(" ✖︎ $chart_dir")
                exit_code=1
            fi
        done
    else
        summary+=('No chart changes detected.')
    fi

    echo '--------------------------------------------------------------------------------'
    for line in "${summary[@]}"; do
        echo "$line"
    done
    echo '--------------------------------------------------------------------------------'

    popd > /dev/null

    exit "$exit_code"
}

main "$@"