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
        tag = "v2.14.2",
        digest = "sha256:be79aff05025bd736f027eaf4a1b2716ac1e09b88e0e9493c962642519f19d9c",
    )

    ## Fetch pebble for use during e2e tests
    ## You can change the version of Pebble used for tests by changing the 'commit'
    ## field in this rule
    go_repository(
        name = "org_letsencrypt_pebble",
        commit = "2e69bb16af048c491720f23cb284fce685e65fec",
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
        tag = "0.23.0",
        # For some reason, the suggested sha256 returns an error when fetched from
        # quay.io by digest.
        # digest = "sha256:f7f08fdbbeddaf3179829c662da360a3feac1ecf8c4b1305949fffd8c8f59879",
    )

    container_pull(
        name = "io_gcr_k8s_defaultbackend",
        registry = "k8s.gcr.io",
        repository = "defaultbackend",
        tag = "1.4",
        digest = "sha256:865b0c35e6da393b8e80b7e3799f777572399a4cff047eb02a81fa6e7a48ed4b",
    )

    ## Fetch vault for use during e2e tests
    ## You can change the version of vault used for tests by changing the 'tag'
    ## field in this rule
    container_pull(
        name = "com_hashicorp_vault",
        registry = "index.docker.io",
        repository = "library/vault",
        tag = "0.9.3",
        digest = "sha256:27a564c725f4f6fa72a618add6b0c3294431ed6b5e912ee042822b35b91064c3",
    )
