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

load("@io_bazel_rules_docker//container:container.bzl", "container_pull")

def define_base_images():
    ## Use 'static' distroless image for all builds
    container_pull(
        name = "static_base",
        registry = "gcr.io",
        repository = "distroless/static",
        digest = "sha256:cd0679a54d2abaf3644829f5e290ad8a10688847475f570fddb9963318cf9390",
    )

