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
load("@io_bazel_rules_docker//container:bundle.bzl", "container_bundle")
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

def multiarch_image(
    name,
    component,
    goarch = ["amd64", "arm64", "arm"],
    goos = ["linux"],
    user = "1000",
    stamp = True,
    **kwargs):

  for arch in goarch:
    for os in goos:
      go_image(
          name = "%s.app_%s-%s" % (name, os, arch),
          base = "@static_base//image",
          embed = [":go_default_library"],
          goarch = arch,
          goos = os,
          pure = "on",
      )

      container_image(
          name = "%s.%s-%s" % (name, os, arch),
          base = "%s.app_%s-%s" % (name, os, arch),
          user = user,
          stamp = stamp,
          **kwargs)

      suffix = ""
      if arch != "amd64":
        suffix = "-%s" % arch

      container_bundle(
          name = "%s.%s-%s.export" % (name, os, arch),
          images = {
              ("{STABLE_DOCKER_REPO}/cert-manager-%s%s:{STABLE_APP_VERSION}" % (component, suffix)): ":%s.%s-%s" % (name, os, arch),
              ("{STABLE_DOCKER_REPO}/cert-manager-%s%s:{STABLE_APP_GIT_COMMIT}" % (component, suffix)): ":%s.%s-%s" % (name, os, arch),
          },
      )

  container_image(
      name = name,
      base = "%s.%s-%s" % (name, goos[0], goarch[0]),
      **kwargs)

def multiarch_bundle(
    name,
    images,
    os = ["linux"],
    arch = ["amd64", "arm64", "arm"],
    **kwargs):

    all_images = {}
    for a in arch:
      for o in os:
        oa_images = {}
        for (k, v) in images.items():
          image_name = k.replace("{arch}", a)
          image_name = image_name.replace("{os}", o)

          oa_images[image_name] = "%s.%s-%s" % (v, o, a)

        container_bundle(
            name = "%s.%s-%s" % (name, o, a),
            images = oa_images,
            **kwargs)

        all_images.update(oa_images)

    container_bundle(
        name = name,
        images = all_images,
        **kwargs)
