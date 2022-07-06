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
load("@bazel_gazelle//:deps.bzl", "go_repository")

# Defines Bazel WORKSPACE targets that are used during e2e tests
def install():
    ## Fetch pebble for use during e2e tests
    ## You can change the version of Pebble used for tests by changing the 'commit'
    ## field in this rule
    go_repository(
        name = "org_letsencrypt_pebble",
        commit = "abe2768b4c05f15dcde7626b484a7fdf1165a73a",
        remote = "https://github.com/letsencrypt/pebble",
        vcs = "git",
        importpath = "github.com/letsencrypt/pebble",
        build_external = "vendored",
        build_naming_convention = "go_default_library",
        # Expose the generated go_default_library as 'public' visibility
        patch_cmds = ["sed -i -e 's/private/public/g' 'cmd/pebble/BUILD.bazel'"],
    )

    ## Fetch nginx-ingress for use during e2e tests
    ## You can change the version of nginx-ingress used for tests by changing the
    ## 'tag' and 'digest' fields in these rules.
    ## The digest here is the digest of a platform-specific image, so it will not
    ## match the manifest list digest in ingress-nginx release notes- you will
    ## have to find the value by other means.
    container_pull(
        name = "io_kubernetes_ingress-nginx",
        registry = "k8s.gcr.io",
        repository = "ingress-nginx/controller",
        tag = "v1.1.0",
        digest = "sha256:7464dc90abfaa084204176bcc0728f182b0611849395787143f6854dc6c38c85"
    )

    container_pull(
        name = "io_kyverno",
        registry = "ghcr.io",
        repository = "kyverno/kyverno",
        tag = "v1.7.1",
        digest = "sha256:9c73f1841ebc61b6a23c935154521cb12289a38de3422f56aa87a7d7ff9b39fe",
    )

    container_pull(
        name = "io_kyverno_pre",
        registry = "ghcr.io",
        repository = "kyverno/kyvernopre",
        tag = "v1.7.1",
        digest = "sha256:185d2eebc60cc693056d9359f0434b7eca4152b06f21f58c6289815257c41af8",
    )

    ## Fetch vault for use during e2e tests
    ## You can change the version of vault used for tests by changing the 'tag'
    ## field in this rule
    container_pull(
        name = "com_hashicorp_vault",
        registry = "index.docker.io",
        repository = "library/vault",
        tag = "1.2.3",
        digest = "sha256:b1c86c9e173f15bb4a926e4144a63f7779531c30554ac7aee9b2a408b22b2c01",
    )

    ## Fetch bind for use during e2e tests
    container_pull(
        name = "io_docker_index_sameersbn_bind",
        registry = "index.docker.io",
        repository = "sameersbn/bind",
        tag = "9.11.3-20190706",
        digest = "sha256:b8e84f9a9fe0c05c3a963606c3d0170622be9c5e8800431ffcaadb0c79a3ff75",
    )

    ## Fetch sample-external-issuer for use during e2e tests
    container_pull(
        name = "io_ghcr_wallrj_sample-external-issuer_controller",
        registry = "ghcr.io",
        repository = "wallrj/sample-external-issuer/controller",
        tag = "v0.0.0-30-gf333b9e",
        digest = "sha256:609a12fca03554a186e516ef065b4152f02596fba697e3cc45f3593654c87a86",
    )
