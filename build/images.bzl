# Copyright 2020 The Jetstack cert-manager contributors.
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

UBI_BASE_IMAGES = {
    # Pinned to release https://access.redhat.com/containers/#/registry.access.redhat.com/ubi8-minimal/images/8.1-407
    # Ensure you update _all_ image digests when upgrading the UBI base image.
    "amd64": {
        "digest": "sha256:39df7365f1343e9a49132f96edd852ddb80e4dcdec03ef8fe1779acb5418d37e",
    },
    "arm64": {
        "digest": "sha256:2166f0122117868485b429170d0848b2da566c20a61e517d44d059c360e2ed2b",
        "variant": "v8",
    },
    "ppc64le": {
        "digest": "sha256:e55721eb97b2517542b695c3ad36e9534fb8f7a8641d06b2ad87e802e36dd8d2",
    },
    "s390x": {
        "digest": "sha256:d41676554f34c417c82a016c94790179fb4116063547b757ec7a65a52235c9c8",
    },
}

OPERATOR_BASE_IMAGES = {
    "amd64": {
        "digest": "sha256:72083dc69195fd2182ea789bdd6a88cf37ce6491f3437c17de8e0af886988c19",
    },
    "ppc64le": {
        "digest": "sha256:14b54dfe73e98bcef55838951cda12b9fcac01bea9ffc61767489c8fa3e8cd41",
    },
    "s390x": {
        "digest": "sha256:c9198b5d498d579ecada93fd9023eb363532fd165b79fc10dc57645389773076",
    },
}

def define_base_images():
    ## Use 'static' distroless image for all builds
    container_pull(
        name = "static_base",
        registry = "gcr.io",
        repository = "distroless/static",
        digest = "sha256:cd0679a54d2abaf3644829f5e290ad8a10688847475f570fddb9963318cf9390",
    )

    [container_pull(
        name = "com_redhat_access_registry_ubi8_ubi_minimal-%s" % arch,
        registry = "registry.access.redhat.com",
        repository = "ubi8/ubi-minimal",
        architecture = arch,
        digest = meta["digest"],
        cpu_variant = meta.get("variant", None),
    ) for arch, meta in UBI_BASE_IMAGES.items()]

    [container_pull(
        name = "io_quay_operator_framework_helm_operator-%s" % arch,
        registry = "quay.io",
        repository = "operator-framework/helm-operator",
        architecture = arch,
        digest = meta["digest"],
        cpu_variant = meta.get("variant", None),
    ) for arch, meta in OPERATOR_BASE_IMAGES.items()]
