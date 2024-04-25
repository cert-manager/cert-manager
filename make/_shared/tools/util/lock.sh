#!/usr/bin/env bash

# Copyright 2023 The cert-manager Authors.
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

# This script is used to lock a file while it is being downloaded. It prevents
# multiple processes from downloading the same file at the same time or from reading
# a half-downloaded file.
# We need this solution because we have recursive $(MAKE) calls in our makefile
# which each will try to download a set of tools. To prevent them from all downloading
# the same files, we re-use the same downloads folder for all $(MAKE) invocations and
# use this script to deduplicate the download processes.

finalfile="$1"
lockfile="$finalfile.lock"
# Timeout in seconds.
timeout=60

# On OSX, flock is not installed, we just skip locking in that case,
# this means that running verify in parallel without downloading all
# tools first will not work.
flock_installed=$(command -v flock >/dev/null && echo "yes" || echo "no")

if [[ "$flock_installed" == "yes" ]]; then
  mkdir -p "$(dirname "$lockfile")"
  touch "$lockfile"
  exec {FD}<>"$lockfile"

  # wait for the file to be unlocked
  if ! flock -x -w $timeout $FD; then
    echo "Failed to obtain a lock for $lockfile within $timeout seconds"
    exit 1
  fi
fi

# now that we have the lock, check if file is already there
if [[ -e "$finalfile" ]]; then
  exit 0
fi

# use a temporary file to prevent Make from thinking the file is ready
# while in reality is is only a partial download
# shellcheck disable=SC2034
outfile="$finalfile.tmp"

finish() {
  rv=$?
  if [[ $rv -eq 0 ]]; then
    mv "$outfile" "$finalfile"
    echo "[info]: downloaded $finalfile"
  else
    rm -rf "$outfile" || true
    rm -rf "$finalfile" || true
  fi
  rm -rf "$lockfile" || true
}
trap finish EXIT SIGINT
