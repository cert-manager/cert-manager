#!/usr/bin/env bash

set -o nounset
set -o errexit
set -o pipefail
set -o xtrace

scriptdir="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Use short form arguments here to support BSD/macOS. `-d` instructs
# it to make a directory, `-t` provides a prefix to use for the directory name.
tmp="$(mktemp -d /tmp/cert-manager-third-party-update.sh.XXXXXXXX)"

go mod vendor -o $tmp
rm -rf ${scriptdir}/forked/acme
mv ${tmp}/golang.org/x/crypto/acme ${scriptdir}/forked/
mv ${tmp}/golang.org/x/crypto/{LICENSE,PATENTS} ${scriptdir}/forked/acme/
pushd $scriptdir/forked
patch -p3 < patches/acme-profiles.patch
