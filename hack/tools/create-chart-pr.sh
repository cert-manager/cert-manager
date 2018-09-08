#!/bin/bash

# Copyright 2018 The Jetstack cert-manager contributors.
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

# Set FORCE to create a pull request against the target repo even if the previous
# sync version cannot be detected.
FORCE=${FORCE:-}
COMMIT_SUBJ_SHA_LEN=${COMMIT_SUBJ_SHA_LEN:-8}

# Hide output of pushd and popd
pushd() { builtin pushd "$@" > /dev/null; }
popd() { builtin popd "$@" > /dev/null; }

function check() {
    local varname="${1}"
    local msg="${2:-${varname} must be set}"
    local var=`eval eval "echo \$${varname}"`
    echo "${var}"
    if [ -z "${var}" ]; then
        echo "${msg}"
        exit 1
    fi
}

[ ${GITHUB_USER?export GITHUB_USER=<your-user> to publish pull requests as} ] && echo "Using GITHUB_USER: ${GITHUB_USER}"

# Ensure github hub is installed
if ! which hub > /dev/null; then
  echo "Can't find 'hub' tool in PATH, please install from https://github.com/github/hub"
  exit 1
fi

# Target repo parameters
TARGET_REPO=${TARGET_REPO:-"$HOME/go/src/github.com/kubernetes/charts"}
TARGET_REPO_REMOTE=${TARGET_REPO_REMOTE:-upstream}
TARGET_REPO_REF=${TARGET_REPO_REF:-master}
TARGET_REPO_PATH="${TARGET_REPO_PATH:-stable/cert-manager}"

# Source repo parameters
SOURCE_REPO=${SOURCE_REPO:-"$HOME/go/src/github.com/jetstack/cert-manager"}
SOURCE_REPO_REMOTE=${SOURCE_REPO_REMOTE:-upstream}
SOURCE_REPO_PATH=${SOURCE_REPO_PATH:-contrib/charts/cert-manager}

# Fork parameters
FORK_REPO_REMOTE=${FORK_REPO_REMOTE:-origin}

[ ${TARGET_REPO?not set} ] && echo "Using target repo: ${TARGET_REPO}"
[ ${TARGET_REPO_REMOTE?not set} ] && echo "Using target repo remote: ${TARGET_REPO_REMOTE}"
[ ${TARGET_REPO_REF?not set} ] && echo "Using target repo ref: ${TARGET_REPO_REF}"
[ ${TARGET_REPO_PATH?not set} ] && echo "Using target repo path: ${TARGET_REPO_PATH}"

[ ${SOURCE_REPO?not set} ] && echo "Using source repo: ${SOURCE_REPO}"
[ ${SOURCE_REPO_REMOTE?not set} ] && echo "Using source repo remote: ${SOURCE_REPO_REMOTE}"
[ ${SOURCE_REPO_REF?not set} ] && echo "Using source repo ref: ${SOURCE_REPO_REF}"
[ ${SOURCE_REPO_PATH?not set} ] && echo "Using source repo path: ${SOURCE_REPO_PATH}"

[ ${FORK_REPO_REMOTE?not set} ] && echo "Using fork repo remote: ${FORK_REPO_REMOTE}"

# Exit early if either repo has a dirty tree
if git_status=$(pushd "${TARGET_REPO}" && git status --porcelain --untracked=no 2>/dev/null && popd) && [[ -n "${git_status}" ]]; then
  echo "!!! Target repo has dirty tree. Clean up and try again."
  exit 1
fi
if git_status=$(pushd "${SOURCE_REPO}" && git status --porcelain --untracked=no 2>/dev/null && popd) && [[ -n "${git_status}" ]]; then
  echo "!!! Source repo has dirty tree. Clean up and try again."
  exit 1
fi

# Update remotes
echo "+++ Updating remotes..."
pushd "${TARGET_REPO}"
git remote update "${TARGET_REPO_REMOTE}" "${FORK_REPO_REMOTE}"
popd
pushd "${SOURCE_REPO}"
git remote update "${SOURCE_REPO_REMOTE}"
popd

if [ -z "${TARGET_REPO_OWNER:-}" ]; then
    pushd "${TARGET_REPO}"
    remoteurl=$(git remote get-url ${TARGET_REPO_REMOTE})
    echo $(dirname ${remoteurl})
    TARGET_REPO_OWNER=$(sed -n 's/.*[:/]\(.*\)/\1/p' <<< $(dirname ${remoteurl}))
    TARGET_REPO_NAME=$(sed -n 's/\(.*\)\.git/\1/p' <<< $(basename ${remoteurl}) )
    popd
fi
if [ -z "${FORK_REPO_OWNER:-}" ]; then
    pushd "${TARGET_REPO}"
    remoteurl=$(git remote get-url ${FORK_REPO_REMOTE})
    FORK_REPO_OWNER=$(sed -n 's/.*[:/]\(.*\)/\1/p' <<< $(dirname ${remoteurl}))
    FORK_REPO_NAME=$(sed -n 's/\(.*\)\.git/\1/p' <<< $(basename ${remoteurl}) )
    popd
fi

#[ -z "${TARGET_REPO_OWNER:-}" ] || ( echo "TARGET_REPO_OWNER could not be autodetected from git remote URL" && exit 1 )
[ ${TARGET_REPO_OWNER?not set} ] && echo "Using target repo owner: ${TARGET_REPO_OWNER}"
[ ${TARGET_REPO_NAME?not set} ] && echo "Using target repo name: ${TARGET_REPO_NAME}"
[ ${FORK_REPO_OWNER?not set} ] && echo "Using fork repo owner: ${FORK_REPO_OWNER}"
[ ${FORK_REPO_NAME?not set} ] && echo "Using fork repo name: ${FORK_REPO_NAME}"

PATCH_BRANCH="automated-sync-${SOURCE_REPO_REF}-${TARGET_REPO_REF}"
PATCH_BRANCH_UNIQ="${PATCH_BRANCH}-$(date +%s)"

pushd "${SOURCE_REPO}" && SOURCE_STARTING_BRANCH=$(git symbolic-ref --short HEAD) && popd
pushd "${TARGET_REPO}" && TARGET_STARTING_BRANCH=$(git symbolic-ref --short HEAD) && popd

function cleanup {
    echo "+++ Switching source repo back to '${SOURCE_STARTING_BRANCH}'"

    pushd "${SOURCE_REPO}"
    git checkout "${SOURCE_STARTING_BRANCH}" || echo "+++ Failed to switch source repo back to starting branch"
    popd

    echo "+++ Cleaning up target repo and switching back to '${TARGET_STARTING_BRANCH}'"
    pushd "${TARGET_REPO}"
    git checkout "${TARGET_REPO_PATH}" || echo "+++ Failed to clean up tracked files in the target repo"
    git clean -fd "${TARGET_REPO_PATH}" || echo "+++ Failed to clean up untracked files in the target repo"
    git checkout "${TARGET_STARTING_BRANCH}" || echo "+++ Failed to switch target repo back to starting branch"
    git branch -D "${PATCH_BRANCH_UNIQ}" || echo "+++ Failed to delete temporary patch branch"
    popd
}
trap cleanup EXIT

function gitcheckout() {
    repo="${1}"
    remote="${2}"
    ref="${3}"
    prettystr=$(basename ${repo})"@${remote}/${ref}"
    pushd "${repo}"
    echo "+++ Checking out ${prettystr}"
    errwrap git reset --hard "${remote}"/"${ref}"
    popd
}

GITHUB_PR_API_BASE="https://api.github.com/repos/jetstack/cert-manager/pulls"

function errwrap() {
    tmp="$(mktemp)"
    code=0
    "$@" > "${tmp}" 2>&1 || code=$?
    [ "${code}" -eq 0 ] || ( echo "+++ Error executing '$@'" && cat "${tmp}" )
    rm -rf "${tmp}"
    return ${code}
}

gitcheckout "${SOURCE_REPO}" "${SOURCE_REPO_REMOTE}" "${SOURCE_REPO_REF}"
gitcheckout "${TARGET_REPO}" "${TARGET_REPO_REMOTE}" "${TARGET_REPO_REF}"

echo "+++ Checking for most recent sync commit hash in target repo"
pushd "${TARGET_REPO}"
# Get the most recent commit subject in the target repo
target_subj=$(git --no-pager log -m --first-parent --pretty=format:"%s" -1 "${TARGET_REPO_PATH}")
# Extract the commit ref
target_latest_ref=$(sed -n 's/cert-manager: fast-forward to upstream \([a-z0-9]*\) (\#[0-9]*)/\1/p' <<< ${target_subj})
if [ ! ${#target_latest_ref} -eq ${COMMIT_SUBJ_SHA_LEN} ]; then
    echo "+++ Could not detect last sync commit ref in target repo"
    if [ -z "${FORCE}" ]; then
        echo "+++ FORCE flag is not set. Exiting..."
        exit 1
    fi
    echo "+++ !! Forcing sync of chart due to FORCE flag being set..."
    target_latest_ref="40beda22b6bef07d0ea423d89f06b9fb2d264de2"
    echo "+++ !! Setting previous sync sha to '${target_latest_ref}'"
    sleep 3
fi
echo "+++ Latest sync was of commit '${target_latest_ref}'"
popd

pushd "${SOURCE_REPO}"
echo "+++ Checking latest commit ref in cert-manager repository"
source_latest_ref=$(git --no-pager log --first-parent --pretty=format:"%H" -1 "${SOURCE_REPO_PATH}")
echo "+++ Latest commit on chart at cert-manager@${SOURCE_REPO_REF} is ${source_latest_ref}"

if [[ "${target_latest_ref}" == "${source_latest_ref}" ]]; then
    echo "+++ Detected commit refs match. Target repository is already up to date."
    exit 0
fi

echo "+++ Fetching previous sync point reference sha from upstream repo"
# we checkout the old ref and then checkout the SOURCE_REF
# to ensure the git log command below doesn't fail
errwrap git checkout "${target_latest_ref}"
errwrap git checkout "${source_latest_ref}"

echo "+++ Building commit message for sync"

commitMessage=""
printf -v commitMessage "cert-manager: fast-forward to upstream ${source_latest_ref:0:COMMIT_SUBJ_SHA_LEN}"'\n'

# Attempt to parse the commit messages between the latest reference in the target repo
# and the latest reference at SOURCE_REF.
# This will only work for mungegithub/prow merged PRs.
while read line;
do
    sha=$(echo "${line}" | awk '{print $1}')
    pr_no_hash=$(echo "${line}" | awk '{print $5}')
    pr_no=""
    [[ "${pr_no_hash}" =~ \#([0-9]+) ]] && pr_no=${BASH_REMATCH[1]}
    if [ -z "${pr_no}" ]; then
        echo "+++ Could not detect pull request number from commit subject '${line}'"
        commitMessage+=$'\n'"* ${line:0:COMMIT_SUBJ_SHA_LEN} ${line:41}"
        continue
    fi
    echo "+++ Detected PR number ${pr_no} for commit ${sha}"
    title=$(curl -s "${GITHUB_PR_API_BASE}/${pr_no}" | jq -r '.title')
    # TODO: make 'jetstack/cert-manager' dynamic based on remote URLs
    commitMessage+=$'\n'"* ${title} (jetstack/cert-manager#${pr_no})"
done < <(git --no-pager log -m --first-parent --merges --pretty=oneline ${target_latest_ref}..${source_latest_ref} -- "${SOURCE_REPO_PATH}")
echo git --no-pager log -m --first-parent --merges --pretty=oneline ${target_latest_ref}..${source_latest_ref} -- "${SOURCE_REPO_PATH}"
echo "+++ Built commit message:"
echo
echo -e "$commitMessage" | sed 's/^/    /'
echo

echo "+++ Copying files from source repo to target"
errwrap cp -R ${SOURCE_REPO_PATH}/* "${TARGET_REPO}/${TARGET_REPO_PATH}/"
echo "+++ Copied files"
popd

pushd "${TARGET_REPO}"

echo "+++ Creating patch branch '${PATCH_BRANCH_UNIQ}'"
errwrap git checkout -b "${PATCH_BRANCH_UNIQ}"

if [ -z "$(git ls-files -m)" ]; then
    echo "+++ No file changes detected"
    exit 0
fi

echo "+++ Detected changed files - committing changes"
errwrap git add -A "${TARGET_REPO_PATH}"
errwrap git commit -m "${commitMessage}"

echo
echo "+++ I'm about to do the following to push to GitHub (and I'm assuming ${FORK_REPO_OWNER} is your personal fork):"
echo
echo "  git push -f ${FORK_REPO_REMOTE} ${PATCH_BRANCH_UNIQ}:${PATCH_BRANCH}"
echo
read -p "+++ Proceed (anything but 'y' aborts the push)? [y/n] " -r
if ! [[ "${REPLY}" =~ ^[yY]$ ]]; then
  echo "Aborting." >&2
  exit 1
fi

git push "${FORK_REPO_REMOTE}" -u -f "${PATCH_BRANCH_UNIQ}:${PATCH_BRANCH}"

pr_body=$(mktemp)
printf "%s" "${commitMessage}" > "${pr_body}"
hub pull-request -F "${pr_body}" -h "${FORK_REPO_OWNER}/${FORK_REPO_NAME}:${PATCH_BRANCH}" -b "${TARGET_REPO_OWNER}/${TARGET_REPO_NAME}:${TARGET_REPO_REF}"

popd
