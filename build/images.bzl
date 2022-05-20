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
    # Use 'static' distroless image for all builds by default.
    # To get the latest-amd64 digest for gcr.io/distroless/static, assuming
    # that $GOPATH/bin is in your $PATH, run:
    # go install github.com/google/go-containerregistry/cmd/crane@latest && crane digest gcr.io/distroless/static:latest-amd64
    container_pull(
        name = "static_base",
        registry = "gcr.io",
        repository = "distroless/static",
        digest = "sha256:f4e4259820649c75fef543614974adc1dfe1c937d5c663a81b3edca5da472442"
    )
    # Use 'dynamic' distroless image for modified cert-manager deployments that
    # are dynamically linked. (This is not the default and you probably don't
    # need this.)
    # To get the latest-amd64 digest for gcr.io/distroless/base,
    # assuming that $GOPATH/bin is in your $PATH, run:
    # go install github.com/google/go-containerregistry/cmd/crane@latest && crane digest gcr.io/distroless/base:latest-amd64
    container_pull(
        name = "dynamic_base",
        registry = "gcr.io",
        repository = "distroless/base",
        digest = "sha256:34e96e21516698913035a62ef1ce484d91184de8a44209a33c7e134547e20dee"
    )
