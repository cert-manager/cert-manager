#!/usr/bin/env bash

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
shopt -s nullglob


readonly REMOTE="${REMOTE:-origin}"
readonly TARGET_BRANCH="${TARGET_BRANCH:-master}"
readonly TIMEOUT="${TIMEOUT:-300}"
readonly LINT_CONF="${LINT_CONF:-/testing/etc/lintconf.yaml}"
readonly CHART_YAML_SCHEMA="${CHART_YAML_SCHEMA:-/testing/etc/chart_schema.yaml}"
readonly VALIDATE_MAINTAINERS="${VALIDATE_MAINTAINERS:-true}"

# Special handling for arrays
[[ -z "${CHART_DIRS[*]}" ]] && CHART_DIRS=(charts); readonly CHART_DIRS
[[ -z "${EXCLUDED_CHARTS[*]}" ]] && EXCLUDED_CHARTS=(); readonly EXCLUDED_CHARTS
[[ -z "${CHART_REPOS[*]}" ]] && CHART_REPOS=(); readonly CHART_REPOS

echo
echo '--------------------------------------------------------------------------------'
echo ' Environment:'
echo " REMOTE=$REMOTE"
echo " TARGET_BRANCH=$TARGET_BRANCH"
echo " CHART_DIRS=${CHART_DIRS[*]}"
echo " EXCLUDED_CHARTS=${EXCLUDED_CHARTS[*]}"
echo " CHART_REPOS=${CHART_REPOS[*]}"
echo " TIMEOUT=$TIMEOUT"
echo " LINT_CONF=$LINT_CONF"
echo " CHART_YAML_SCHEMA=$CHART_YAML_SCHEMA"
echo " VALIDATE_MAINTAINERS=$VALIDATE_MAINTAINERS"
echo '--------------------------------------------------------------------------------'
echo


# Detects chart directories that have changes against the
# target branch ("$REMOTE/$TARGET_BRANCH").
chartlib::detect_changed_directories() {
    local merge_base
    merge_base="$(git merge-base "$REMOTE/$TARGET_BRANCH" HEAD)"

    local changed_dirs=()
    local dir

    while read -r dir; do
        local excluded=
        for excluded_dir in "${EXCLUDED_CHARTS[@]}"; do
            if [[ "$dir" == "$excluded_dir" ]]; then
                excluded=true
                break
            fi
        done
        if [[ -z "$excluded" && -d "$dir" ]]; then
            changed_dirs=("${changed_dirs[@]}" "$dir")
        fi

    ## @munnerz: because the cert-manager repository stores charts in the contrib/
    ## subdirectory, we must modify the below line from $1/$2 to be $1/$2/$3.
    ## In future, we should PR upstream so we no longer hardcode the depth of
    ## directories required for this script.
    done < <(git diff --find-renames --name-only "$merge_base" "${CHART_DIRS[@]}" | awk -F/ '{ print $1"/"$2"/"$3 }' | uniq)

    echo "${changed_dirs[@]}"
}

# Initializes the Helm client and add configured repos.
chartlib::init_helm() {
    echo 'Initializing Helm client...'

    helm init --client-only

    for repo in "${CHART_REPOS[@]}"; do
        local name="${repo%=*}"
        local url="${repo#*=}"

        helm repo add "$name" "$url"
    done
}

# Checks a chart for a version bump comparing the version from Chart.yaml
# with that from the target branch.
# Args:
#   $1 The chart directory
chartlib::check_for_version_bump() {
    local chart_dir="${1?Chart directory is required}"

    echo "Checking chart '$chart_dir' for a version bump..."

    # Check if chart exists on taget branch
    if ! git cat-file -e "$REMOTE/$TARGET_BRANCH:$chart_dir/Chart.yaml" > /dev/null 2>&1; then
        echo "Unable to find chart on master. New chart detected."
        return 0
    fi

    # Compare version of chart under test with that on the target branch

    local old_version
    old_version=$(yq -r .version <(git show "$REMOTE/$TARGET_BRANCH:$chart_dir/Chart.yaml"))
    echo "Chart version on" "$REMOTE/$TARGET_BRANCH" ":" "$old_version"

    local new_version
    new_version=$(yq -r .version "$chart_dir/Chart.yaml")
    echo "New chart version: " "$new_version"

    # Pre-releases may not be API compatible. So, when tools compare versions
    # they often skip pre-releases. vert can force looking at pre-releases by
    # adding a dash on the end followed by pre-release. -0 on the end will force
    # looking for all valid pre-releases since a pre-release cannot start with a 0.
    # For example, 1.2.3-0 will include looking for pre-releases.
    if [[ $old_version == *-* ]]; then  # Found the - to denote it has a pre-release
        if vert ">$old_version" "$new_version"; then
            echo "Chart version ok. Version bumped."
            return 0
        fi
    else
        # No pre-release was found so we increment the patch version and attach a
        # -0 to enable pre-releases being found.
        local old_version_array
        read -ra old_version_array <<< "${old_version//./ }" # Turn the version into an array

        (( old_version_array[2] += 1 )) # Increment the patch release
        if vert ">${old_version_array[0]}.${old_version_array[1]}.${old_version_array[2]}-0" "$new_version"; then
            echo "Chart version ok. Version bumped."
            return 0
        fi
    fi

    chartlib::error "Chart version not ok. Needs a version bump."
    return 1
}

# Validates the Chart.yaml against a YAML schema.
# Args:
#   $1 The chart directory
chartlib::validate_chart_yaml() {
    local chart_dir="${1?Chart directory is required}"

    echo "Validating Chart.yaml"
    yamale --schema "$CHART_YAML_SCHEMA" "$chart_dir/Chart.yaml"
}

# Validates maintainer names in Chart.yaml to be valid Github users.
# Args:
#   $1 The chart directory
chartlib::validate_maintainers() {
    local chart_dir="${1?Chart directory is required}"

    echo "Validating maintainers"

    # We require maintainers for non-deprecated charts
    local deprecated
    deprecated=$(yq -r '.deprecated // empty' "$chart_dir/Chart.yaml")

    local maintainers
    maintainers=$(yq -r '.maintainers // empty' "$chart_dir/Chart.yaml")

    if [[ -n "$deprecated" ]]; then
        if [[ -n "$maintainers" ]]; then
            chartlib::error "Deprecated charts must not have any maintainers in 'Chart.yaml'."
            return 1
        else
            return 0
        fi
    else
        if [[ -z "$maintainers" ]]; then
            echo "No maintainers found in 'Chart.yaml'."
        fi
    fi

    while read -r name; do
        echo "Verifying maintainer '$name'..."
        if [[ $(curl --silent --output /dev/null --write-out "%{http_code}" --fail --head "https://github.com/$name") -ne 200 ]]; then
            chartlib::error "'$name' is not a valid GitHub account. Please use a valid Github account to help us communicate with maintainers in PRs/issues."
            return 1
        fi
    done < <(yq -r '.maintainers[].name' "$chart_dir/Chart.yaml")
}

# Lints a YAML file.
# Args:
#   $1 The YAML file to lint
chartlib::lint_yaml_file() {
    local file="${1?Specify YAML file for linting}"

    echo "Linting '$file'..."

    if [[ -f "$file" ]]; then
        yamllint --config-file "$LINT_CONF" "$file"
    else
        chartlib::error "File '$file' does not exist."
        return 1
    fi
}

# Validates a chart:
#   - Checks for a version bump
#   - Lints Chart.yaml and values.yaml
#   - Validates Chart.yaml against schema
#   - Validates maintainers
# Args:
#   $1 The chart directory
chartlib::validate_chart() {
    local chart_dir="${1?Chart directory is required}"
    local error=

    echo "Validating chart '$chart_dir'..."

    chartlib::check_for_version_bump "$chart_dir" || error=true
    chartlib::lint_yaml_file "$chart_dir/Chart.yaml" || error=true
    chartlib::lint_yaml_file "$chart_dir/values.yaml" || error=true
    chartlib::validate_chart_yaml "$chart_dir" || error=true

    if [[ "$VALIDATE_MAINTAINERS" == true ]]; then
        chartlib::validate_maintainers "$chart_dir" || error=true
    fi

    if [[ -n "$error" ]]; then
        chartlib::error 'Chart validation failed.'
        return 1
    fi
}

# Lints a chart.
# Args:
#   $1 The chart directory
#   $2 A custom values file for the chart installation (optional)
chartlib::lint_chart_with_single_config() {
    local chart_dir="${1?Chart directory is required}"
    local values_file="${2:-}"

    echo "Building dependencies for chart '$chart_dir'..."
    helm dependency build "$chart_dir"

    if [[ -n "$values_file" ]]; then
        echo "Using custom values file '$values_file'..."

        echo "Linting chart '$chart_dir'..."
        helm lint "$chart_dir" --values "$values_file"
    else
        echo "Chart does not provide test values. Using defaults..."

        echo "Linting chart '$chart_dir'..."
        helm lint "$chart_dir"
    fi
}

# Installs and tests a chart. The release and the namespace are
# automatically deleted afterwards.
# Args:
#   $1 The chart directory
#   $2 The release name for the chart to be installed
#   $3 The namespace to install the chart in
#   $4 A custom values file for the chart installation (optional)
chartlib::install_chart_with_single_config() {
    local chart_dir="${1?Chart directory is required}"
    local release="${2?Release is required}"
    local namespace="${3?Namespace is required}"
    local values_file="${4:-}"

    # Capture subshell output
    exec 3>&1

    if ! (
        set -o errexit

        # Run in subshell so we can use a trap within the function.
        trap 'chartlib::print_pod_details_and_logs "$namespace" || true; chartlib::delete_release "$release" || true; chartlib::delete_namespace "$namespace" || true' EXIT

        echo "Building dependencies for chart '$chart_dir'..."
        helm dependency build "$chart_dir"

        echo "Installing chart '$chart_dir' into namespace '$namespace'..."

        if [[ -n "$values_file" ]]; then
            echo "Using custom values file '$values_file'..."
            helm install "$chart_dir" --name "$release" --namespace "$namespace" --wait --timeout "$TIMEOUT" --values "$values_file"
        else
            echo "Chart does not provide test values. Using defaults..."
            helm install "$chart_dir" --name "$release" --namespace "$namespace" --wait --timeout "$TIMEOUT"
        fi

        # For deployments --wait may not be sufficient because it looks at 'maxUnavailable' which is 0 by default.
        for deployment in $(kubectl get deployment --namespace "$namespace" --output jsonpath='{.items[*].metadata.name}'); do
            kubectl rollout status "deployment/$deployment" --namespace "$namespace"
        done

        echo "Testing chart '$chart_dir' in namespace '$namespace'..."
        helm test "$release" --cleanup --timeout "$TIMEOUT"

    ) >&3; then

        chartlib::error "Chart installation failed: $chart_dir"
        return 1
    fi
}

# Lints a chart for all custom values files matching '*.values.yaml'
# in the 'ci' subdirectory.
# Args:
#   $1 The chart directory
chartlib::lint_chart_with_all_configs() {
    local chart_dir="${1?Chart directory is required}"

    local has_test_values=
    for values_file in "$chart_dir"/ci/*-values.yaml; do
        has_test_values=true
        chartlib::lint_chart_with_single_config "$chart_dir" "$values_file"
    done

    if [[ -z "$has_test_values" ]]; then
        chartlib::lint_chart_with_single_config "$chart_dir"
    fi
}

# Installs a chart for all custom values files matching '*.values.yaml'
# in the 'ci' subdirectory. If no custom values files are found, the chart
# is installed with defaults. If $BUILD_ID is set, it is used as
# name for the namespace to install the chart in. Otherwise, the chart
# name is taken as the namespace name. Namespace and release are suffixed with
# an index. Releases and namespaces are automatically deleted afterwards.
# Args:
#   $1 The chart directory
chartlib::install_chart_with_all_configs() {
    local chart_dir="${1?Chart directory is required}"
    local index=0

    local release
    release=$(yq -r .name < "$chart_dir/Chart.yaml")

    local random_suffix
    random_suffix=$(tr -dc a-z0-9 < /dev/urandom | fold -w 16 | head -n 1)

    local namespace="${BUILD_ID:-"$release"}-$random_suffix"
    local release="$release-$random_suffix"

    local has_test_values=
    for values_file in "$chart_dir"/ci/*-values.yaml; do
        has_test_values=true
        chartlib::install_chart_with_single_config "$chart_dir" "$release-$index" "$namespace-$index" "$values_file"
        ((index += 1))
    done

    if [[ -z "$has_test_values" ]]; then
        chartlib::install_chart_with_single_config "$chart_dir" "$release" "$namespace"
    fi
}

# Prints log for all pods in the specified namespace.
# Args:
#   $1 The namespace
chartlib::print_pod_details_and_logs() {
    local namespace="${1?Namespace is required}"

    kubectl get pods --show-all --no-headers --namespace "$namespace" | awk '{ print $1 }' | while read -r pod; do
        if [[ -n "$pod" ]]; then
            printf '\n================================================================================\n'
            printf ' Details from pod %s\n' "$pod"
            printf '================================================================================\n'

            printf '\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n'
            printf ' Description of pod %s\n' "$pod"
            printf '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n'

            kubectl describe pod --namespace "$namespace" "$pod" || true

            printf '\n~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n'
            printf ' End of description for pod %s\n' "$pod"
            printf '~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~\n'

            local init_containers
            init_containers=$(kubectl get pods --show-all --output jsonpath="{.spec.initContainers[*].name}" --namespace "$namespace" "$pod")
            for container in $init_containers; do
                printf -- '\n--------------------------------------------------------------------------------\n'
                printf ' Logs of init container %s in pod %s\n' "$container" "$pod"
                printf -- '--------------------------------------------------------------------------------\n\n'

                kubectl logs --namespace "$namespace" --container "$container" "$pod" || true

                printf -- '\n--------------------------------------------------------------------------------\n'
                printf ' End of logs of init container %s in pod %s\n' "$container" "$pod"
                printf -- '--------------------------------------------------------------------------------\n'
            done

            local containers
            containers=$(kubectl get pods --show-all --output jsonpath="{.spec.containers[*].name}" --namespace "$namespace" "$pod")
            for container in $containers; do
                printf '\n--------------------------------------------------------------------------------\n'
                printf -- ' Logs of container %s in pod %s\n' "$container" "$pod"
                printf -- '--------------------------------------------------------------------------------\n\n'

                kubectl logs --namespace "$namespace" --container "$container" "$pod" || true

                printf -- '\n--------------------------------------------------------------------------------\n'
                printf ' End of logs of container %s in pod %s\n' "$container" "$pod"
                printf -- '--------------------------------------------------------------------------------\n'
            done

            printf '\n================================================================================\n'
            printf ' End of details for pod %s\n' "$pod"
            printf '================================================================================\n\n'
        fi
    done
}

# Deletes a release.
# Args:
#   $1 The name of the release to delete
chartlib::delete_release() {
    local release="${1?Release is required}"

    echo "Deleting release '$release'..."
    helm delete --purge "$release" --timeout "$TIMEOUT"
}

# Deletes a namespace.
# Args:
#   $1 The namespace to delete
chartlib::delete_namespace() {
    local namespace="${1?Namespace is required}"

    echo "Deleting namespace '$namespace'..."
    kubectl delete namespace "$namespace"

    echo -n "Waiting for namespace '$namespace' to terminate..."

    local max_retries=30
    local retry=0
    local sleep_time_sec=3
    while ((retry < max_retries)); do
        sleep "$sleep_time_sec"
        ((retry++))

        if ! kubectl get namespace "$namespace" &> /dev/null; then
            echo
            echo "Namespace '$namespace' terminated."
            return 0
        fi

        echo -n '.'
    done

    echo

    chartlib::error "Namespace '$namespace' not terminated after $((max_retries * sleep_time_sec)) s."

    echo "Force-deleting pods..."
    kubectl delete pods --namespace "$namespace" --all --force --grace-period 0 || true

    sleep 3

    if ! kubectl get namespace "$namespace" &> /dev/null; then
        echo "Force-deleting namespace '$namespace'..."
        kubectl delete namespace "$namespace" --ignore-not-found --force --grace-period 0 || true
    fi
}

# Logs an error.
# Args:
#   $1 The error message
chartlib::error() {
    printf '\e[31mERROR: %s\n\e[39m' "$1" >&2
}