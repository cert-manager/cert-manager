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

## This file is copied and modified from https://github.com/kubernetes/kubernetes/blob/a06d16565cc5c129241f306d04a12fd94585d956/build/platforms.bzl

load("@bazel_skylib//lib:new_sets.bzl", "sets")
load("@bazel_skylib//lib:types.bzl", "types")

SERVER_PLATFORMS = {
    "linux": [
        "amd64",
        "arm64",
        "arm",
        "ppc64le",
        "s390x",
    ],
}

CLIENT_PLATFORMS = {
    "linux": [
        "amd64",
        "arm64",
        "arm",
        "ppc64le",
        "s390x",
    ],
    "darwin": [
        "amd64",
        "arm64",
    ],
    "windows": [
        "amd64",
    ],
}

TEST_PLATFORMS = {
    "linux": [
        "amd64",
        "arm64",
    ],
    "darwin": [
        "amd64",
        "arm64",
    ],
}

# Helper which produces the ALL_PLATFORMS dictionary, currently composed of
# just the SERVER and TEST platforms
def _all_platforms():
    all_platforms = {}
    for platforms in [SERVER_PLATFORMS, TEST_PLATFORMS, CLIENT_PLATFORMS]:
        for os, archs in platforms.items():
            all_platforms[os] = sets.union(
                all_platforms.setdefault(os, sets.make()),
                sets.make(archs),
            )
    for os, archs in all_platforms.items():
        all_platforms[os] = sets.to_list(archs)
    return all_platforms

ALL_PLATFORMS = _all_platforms()

def go_platform_constraint(os, arch):
    return "@io_bazel_rules_go//go/platform:%s_%s" % (os, arch)

# Helper to for_platforms which updates the select() dictionary.
# d is the dictionary being updated.
# value is the value to set for each item of platforms, which should
# be a single platform category dictionary (e.g. SERVER_PLATFORMS).
# only_os selects one of the OSes in platforms.
def _update_dict_for_platform_category(d, value, platforms, only_os = None):
    if not value:
        return
    for os, arches in platforms.items():
        if only_os and os != only_os:
            continue
        for arch in arches:
            constraint = go_platform_constraint(os, arch)
            fmt_args = {"OS": os, "ARCH": arch}
            if types.is_list(value):
                # Format all items in the list, and hope there are no duplicates
                d.setdefault(constraint, []).extend(
                    [v.format(**fmt_args) for v in value],
                )
            else:
                # Don't overwrite existing value
                if constraint in d:
                    fail("duplicate entry for constraint %s", constraint)
                if types.is_dict(value):
                    # Format dictionary values only
                    d[constraint] = {
                        dict_key: dict_value.format(**fmt_args)
                        for dict_key, dict_value in value.items()
                    }
                else:
                    # Hopefully this is just a string
                    d[constraint] = value.format(**fmt_args)

## NOTE: We (cert-manager) do not currently build for multiple platforms, so
## most of this functionality is not utilised. It is kept in case we do end out
## publishing binaries for different 'platform categories' in future.
#
# for_platforms returns a dictionary to be used with select().
# select() is used for configurable attributes (most attributes, notably
# excluding output filenames), and takes a dictionary mapping a condition
# to a value for that attribute.
# select() is described in more detail in the Bazel documentation:
# https://docs.bazel.build/versions/master/be/functions.html#select
#
# One notable condition is the target platform (os and arch).
# Kubernetes binaries generally target particular platform categories,
# such as client binaries like kubectl, or node binaries like kubelet.
# Additionally, some build artifacts need specific configurations such as
# the appropriate arch-specific base image.
#
# This macro produces a dictionary where each of the platform categories
# (client, node, server, test, all) is enumerated and filled in
# with the provided arguments as the values.
#
# For example, a filegroup might want to include one binary for all client
# platforms and another binary for server platforms. The client and server
# platform lists have some shared items but also some disjoint items.
# The client binary can be provided in for_client and the server binary provided
# in for_server; this macro will then return a select() dictionary that
# includes the appropriate binaries based on the configured platform.
#
# Another example selecting the appropriate base image for a docker container.
# One can use select(for_platforms(for_server="base-image-{ARCH}//image"))
# to have the appropriate arch-specific image selected.
#
# The for_platform arguments can be lists, dictionaries, or strings, but
# they should all be the same type for a given call.
# The tokens {OS} and {ARCH} will be substituted with the corresponding values,
# but if a dictionary is provided, only the dictionary values will be formatted.
#
# If default is provided, a default condition will be added with the provided
# value.
# only_os can be used to select a single OS from a platform category that lists
# multiple OSes. For example, it doesn't make sense to build debs or RPMs for
# anything besides Linux, so you might supply only_os="linux" for those rules.
#
# For a complete example, consult something like the release-tars target in
# build/release-tars/BUILD.
def for_platforms(
        for_server = None,
        for_test = None,
        for_client = None,
        for_all = None,
        default = None,
        only_os = None):
    d = {}
    if default != None:
        d["//conditions:default"] = default
    _update_dict_for_platform_category(d, for_server, SERVER_PLATFORMS, only_os)
    _update_dict_for_platform_category(d, for_test, TEST_PLATFORMS, only_os)
    _update_dict_for_platform_category(d, for_client, CLIENT_PLATFORMS, only_os)
    _update_dict_for_platform_category(d, for_all, ALL_PLATFORMS, only_os)
    return d
