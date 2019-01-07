# Copyright 2019 The Jetstack cert-manager contributors.
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

load("@io_bazel_rules_docker//container:image.bzl", "container_image")
load("@io_bazel_rules_docker//go:image.bzl", "go_image")

## stamped_image is a macro for creating :app and :image targets
def stamped_image(
    name, # use "image"
    base = None,
    user = "1000",
    stamp = True,  # stamp by default, but allow overrides
    **kwargs):
  go_image(
      name = "%s.app" % name,
      base = base,
      embed = [":go_default_library"],
      goarch = "amd64",
      goos = "linux",
      pure = "on",
  )

  container_image(
      name = name,
      base = ":%s.app" % name,
      user = user,
      stamp = stamp,
      **kwargs)
