# Copyright 2021 The cert-manager Authors.
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

# File contents copied from https://github.com/pixie-io/pixie/blob/main/workspace.bzl

# Common functions and imports used by the WORKSPACE file.

def _parse_bazel_version(bazel_version):
    # Remove commit from version.
    version = bazel_version.split(" ", 1)[0]

    # Split into (release, date) parts and only return the release
    # as a tuple of integers.
    parts = version.split("-", 1)

    # Turn "release" into a tuple of strings
    version_tuple = ()
    for number in parts[0].split("."):
        version_tuple += (str(number),)
    return version_tuple

# Check that a minimum version of bazel is being used.
def check_min_bazel_version(bazel_version):
    if "bazel_version" in dir(native) and native.bazel_version:
        # native is a built-in Bazel module https://docs.bazel.build/versions/main/skylark/lib/native.html#modules.native
        # native.bazel_version is only available in WORKSPACE, so this def can only ever be used in WORKSPACE
        current_bazel_version = _parse_bazel_version(native.bazel_version)
        minimum_bazel_version = _parse_bazel_version(bazel_version)
        if minimum_bazel_version > current_bazel_version:
            fail("\nCurrent Bazel version is {}, expected at least {}\n".format(
                native.bazel_version,
                bazel_version,
            ))
