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
    ## 'tag' field in this rule
    container_pull(
        name = "io_kubernetes_ingress-nginx",
        registry = "k8s.gcr.io",
        repository = "ingress-nginx/controller",
        tag = "v0.41.2",
        digest = "sha256:e11b7d264cac4cfc7566b78bb150c94168ea4612a4e9769ca549eb03469db906",
    )

    ## Fetch vault for use during e2e tests
    ## You can change the version of vault used for tests by changing the 'tag'
    ## field in this rule
    container_pull(
        name = "com_hashicorp_vault",
        registry = "index.docker.io",
        repository = "library/vault",
        tag = "1.7.1",
        digest = "sha256:7d07d64480897215cca86ce51750c888fae4d703529708517ecdd5fabba6cbb3"
    )

    ## Fetch bind for use during e2e tests
    container_pull(
        name = "io_docker_index_sameersbn_bind",
        registry = "index.docker.io",
        repository = "sameersbn/bind",
        tag = "9.11.3-20190706",
        digest = "sha256:b8e84f9a9fe0c05c3a963606c3d0170622be9c5e8800431ffcaadb0c79a3ff75"
    )

    ## Fetch sample-external-issuer for use during e2e tests
    container_pull(
        name = "io_ghcr_wallrj_sample-external-issuer_controller",
        registry = "ghcr.io",
        repository = "wallrj/sample-external-issuer/controller",
        tag = "v0.0.0-30-gf333b9e",
        digest = "sha256:609a12fca03554a186e516ef065b4152f02596fba697e3cc45f3593654c87a86"
    )
