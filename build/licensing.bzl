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

def licensed_file(
    name,
    src,
    # Default to use the 'bazel' boilerplate file.
    # This uses '#' as a way to denote a comment.
    # This will likely need changing depending on the type of the file being
    # generated.
    license_boilerplate = "//hack/boilerplate:boilerplate.bzl.timestamped.txt",
    **kwargs,
):
    native.genrule(
        name = "%s.genrule" % name,
        srcs = [src, license_boilerplate],
        outs = [name],
        cmd = " ".join([
            "cat",
            "$(location %s)" % license_boilerplate,
            "$(location %s)" % src,
            "> $@",
        ]),
        **kwargs,
    )
