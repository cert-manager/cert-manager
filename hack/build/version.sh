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

# Changes made from the original source file, copyright Kubernetes authors:

# Copyright 2014 The Kubernetes Authors.
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

# Grovels through git to set a set of env variables.
#    GIT_COMMIT - The git commit id corresponding to this source code.
#    GIT_TREE_STATE - "clean" indicates no changes since the git commit id
#      dirty" indicates source code changes after the git commit id
#      archive" indicates the tree was produced by 'git archive'
#    GIT_VERSION - "vX.Y" used to indicate the last release version.
#    GIT_MAJOR - The major part of the version
#    GIT_MINOR - The minor component of the version
version::get_version() {
  local git=(git --work-tree "${REPO_ROOT}")

  GIT_COMMIT=$("${git[@]}" rev-parse "HEAD^{commit}" 2>/dev/null)

  # Check if the tree is dirty.  default to dirty
  if git_status=$("${git[@]}" status --porcelain 2>/dev/null) && [[ -z ${git_status} ]]; then
    GIT_TREE_STATE="clean"
  else
    GIT_TREE_STATE="dirty"
  fi

  # Use git describe to find the version based on tags.
  GIT_VERSION=$("${git[@]}" describe --tags --match='v*' --abbrev=14 "${GIT_COMMIT}^{commit}" 2>/dev/null)

  GIT_IS_TAGGED_RELEASE=$("${git[@]}" git describe --exact-match HEAD >/dev/null 2>&1 && echo "true" || echo "false")
  
  # This translates the "git describe" to an actual semver.org
  # compatible semantic version that looks something like this:
  #   v1.1.0-alpha.0.6+84c76d1142ea4d
  #
  # TODO: We continue calling this "git version" because so many
  # downstream consumers are expecting it there.
  #
  # These regexes are painful enough in sed...
  # We don't want to do them in pure shell, so disable SC2001
  # shellcheck disable=SC2001
  DASHES_IN_VERSION=$(echo "${GIT_VERSION}" | sed "s/[^-]//g")
  if [[ "${DASHES_IN_VERSION}" == "---" ]] ; then
    # shellcheck disable=SC2001
    # We have distance to subversion (v1.1.0-subversion-1-gCommitHash)
    GIT_VERSION=$(echo "${GIT_VERSION}" | sed "s/-\([0-9]\{1,\}\)-g\([0-9a-f]\{14\}\)$/.\1\+\2/")
  elif [[ "${DASHES_IN_VERSION}" == "--" ]] ; then
    # shellcheck disable=SC2001
    # We have distance to base tag (v1.1.0-1-gCommitHash)
    GIT_VERSION=$(echo "${GIT_VERSION}" | sed "s/-g\([0-9a-f]\{14\}\)$/+\1/")
  fi
  if [[ "${GIT_TREE_STATE}" == "dirty" ]]; then
    # git describe --dirty only considers changes to existing files, but
    # that is problematic since new untracked .go files affect the build,
    # so use our idea of "dirty" from git status instead.
    GIT_VERSION+="-dirty"
  fi

  # Try to match the "git describe" output to a regex to try to extract
  # the "major", "minor" and "patch" versions and whether this is the exact tagged
  # version or whether the tree is between two tagged versions.
  # Cert-manager release tag always has all three of major, minor and patch versions.
  if [[ "${GIT_VERSION}" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)(-([0-9A-Za-z.-]+))?(\+([0-9A-Za-z.-]+))?$ ]]; then
    GIT_MAJOR=${BASH_REMATCH[1]}
    GIT_MINOR=${BASH_REMATCH[2]}
    GIT_PATCH=${BASH_REMATCH[3]}
    IMAGE_NAME_SHORT="v${GIT_MAJOR}.${GIT_MINOR}.${GIT_PATCH}"
    
    GIT_SUBVERSION=${BASH_REMATCH[5]}
    GIT_IS_PRERELEASE="false"
    if [[ -n "$GIT_SUBVERSION" ]]; then
      IMAGE_NAME_SHORT+="-${GIT_SUBVERSION}"
      GIT_IS_PRERELEASE="true"
    fi
    
    IMAGE_NAME_LONG="$IMAGE_NAME_SHORT"
    if [[ -n "${BASH_REMATCH[7]}" ]]; then
      IMAGE_NAME_LONG+="-${BASH_REMATCH[7]}"
    fi
  else
    # If GIT_VERSION is not a valid Semantic Version, then refuse to build.
    echo "GIT_VERSION should be a valid Semantic Version. Current value: ${GIT_VERSION}"
    echo "Please see more details here: https://semver.org"
    exit 1
  fi
}

# This function can be used to find the version of last published release that
# is not alpha or beta release (i.e in upgrade test script)
# If the latest published release is v1.2.3 it will set KUBE_LAST_VERSION to
# v1.2.3.
# If the last published releases are v1.2.3 and v1.3.0-alpha.0 it will set
# KUBE_LAST_VERSION to v1.2.3
version::last_published_release() {
  version::list_published_releases

  local latest

  latest=$(
    echo "$RELEASE_LIST" | \
    grep -v 'alpha\|beta' | \
    tail -n1
  )

  if [[ "${latest}" =~ ^v([0-9]+)\.([0-9]+)\.([0-9]+)([-].*)?([+].*)?$ ]]; then
    major=${BASH_REMATCH[1]}
    minor=${BASH_REMATCH[2]}
    patch=${BASH_REMATCH[3]}
    LAST_RELEASE="v${major}.${minor}.${patch}"
  else
    echo "Latest found Git tag that is not alpha or beta tag is not a valid semver tag: ${latest}"
    echo "Please see more details here: https://semver.org"
    exit 1
  fi
}

version::list_published_releases() {
  local list

  # Lists all remote tags on the upstream, which gives tags in format:
  # "<commit> ref/tags/<tag>". Strips commit + tag prefix, filters out tags for v1+,
  # and manually removes v1.2.0-alpha.1, since that version's manifest contains
  # duplicate CRD resources (2 CRDs with the same name) which in turn can cause problems
  # with the versionchecker test.
  list=$(
    git ls-remote --tags --refs "${REPO_URL}" | \
		awk '{print $2;}' | \
		sed 's/refs\/tags\///' | \
		sed -n '/v1.0.0/,$p' | \
		grep -v "v1.2.0-alpha.1"
  )

  RELEASE_LIST=$list
}


help() {
  cat <<EOF
Usage:
    $0 version <root-of-repo>
    $0 last-published-release <git-repo-url>
    $0 list-published-releases <git-repo-url>
EOF
  exit
}

if [ $# -eq 2 ]; then
  case "$1" in
    version)
      REPO_ROOT=$2
      version::get_version

      results=(
        "GIT_COMMIT=$GIT_COMMIT"
        "GIT_TREE_STATE=$GIT_TREE_STATE"
        "GIT_VERSION=$GIT_VERSION"
        "GIT_MAJOR=$GIT_MAJOR"
        "GIT_MINOR=$GIT_MINOR"
        "GIT_PATCH=$GIT_PATCH"
        "GIT_SUBVERSION=$GIT_SUBVERSION"
        "IMAGE_NAME_SHORT=$IMAGE_NAME_SHORT"
        "IMAGE_NAME_LONG=$IMAGE_NAME_LONG"
        "GIT_IS_PRERELEASE=$GIT_IS_PRERELEASE"
        "GIT_IS_TAGGED_RELEASE=$GIT_IS_TAGGED_RELEASE"
      )

      echo "${results[@]}"

      exit 0
      ;;
    last-published-release)
      REPO_URL=$2
      version::last_published_release
      echo "$LAST_RELEASE"
      exit 0
      ;;
    list-published-releases)
      REPO_URL=$2
      version::list_published_releases
      echo "$RELEASE_LIST"
      exit 0
      ;;
  esac
fi

help
exit 124
