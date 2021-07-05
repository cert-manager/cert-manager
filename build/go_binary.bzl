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

load(":version.bzl", "version_x_defs")
load("@io_bazel_rules_go//go:def.bzl", real_go_binary = "go_binary")

def go_binary(name, **kwargs):
    real_go_binary(
        name = name,
        x_defs = version_x_defs(),
        # reduce the go binary size with this simple trick
        # (https://blog.filippo.io/shrink-your-go-binaries-with-this-one-weird-trick/)
        # it strips the DWARF tables needed for debuggers, not the annotations
        # needed for stack traces, so our panics are still readable!
        gc_linkopts = ["-w"],
        **kwargs,
    )
