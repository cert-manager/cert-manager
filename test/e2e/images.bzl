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

load("@io_bazel_rules_docker//container:container.bzl", "container_pull")
load("@bazel_gazelle//:deps.bzl", "go_repository")

# Defines Bazel WORKSPACE targets that are used during e2e tests
def install():
    container_pull(
        name = "io_gcr_helm_tiller",
        registry = "gcr.io",
        repository = "kubernetes-helm/tiller",
        tag = "v2.15.1",
        digest = "sha256:39bb81aa9299390ef1d9e472531da24e98234db46664e431001a5fd6d0611114",
    )

    ## Fetch pebble for use during e2e tests
    ## You can change the version of Pebble used for tests by changing the 'commit'
    ## field in this rule
    go_repository(
        name = "org_letsencrypt_pebble",
        commit = "2787c898960ca6326da21ab48b76b080f89a8fec",
        remote = "https://github.com/munnerz/pebble",
        vcs = "git",
        importpath = "github.com/letsencrypt/pebble",
        build_external = "vendored",
        # Expose the generated go_default_library as 'public' visibility
        patch_cmds = ["sed -i -e 's/private/public/g' 'cmd/pebble/BUILD.bazel'"],
    )


    ## Fetch nginx-ingress for use during e2e tests
    ## You can change the version of nginx-ingress used for tests by changing the
    ## 'tag' field in this rule
    container_pull(
        name = "io_kubernetes_ingress-nginx",
        registry = "quay.io",
        repository = "kubernetes-ingress-controller/nginx-ingress-controller",
        tag = "0.26.1",
        # For some reason, the suggested sha256 returns an error when fetched from
        # quay.io by digest.
        # digest = "sha256:f7f08fdbbeddaf3179829c662da360a3feac1ecf8c4b1305949fffd8c8f59879",
    )

    container_pull(
        name = "io_gcr_k8s_defaultbackend",
        registry = "k8s.gcr.io",
        repository = "defaultbackend-amd64",
        tag = "1.5",
        digest = "sha256:4dc5e07c8ca4e23bddb3153737d7b8c556e5fb2f29c4558b7cd6e6df99c512c7",
    )

    ## Fetch vault for use during e2e tests
    ## You can change the version of vault used for tests by changing the 'tag'
    ## field in this rule
    container_pull(
        name = "com_hashicorp_vault",
        registry = "index.docker.io",
        repository = "library/vault",
        tag = "1.2.3",
        digest = "sha256:b1c86c9e173f15bb4a926e4144a63f7779531c30554ac7aee9b2a408b22b2c01"
    )
