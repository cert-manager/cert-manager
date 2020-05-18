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

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file", "http_archive")
load("@io_bazel_rules_docker//container:container.bzl", "container_pull")
load("@bazel_gazelle//:deps.bzl", "go_repository")

def install():
    install_misc()
    install_integration_test_dependencies()
    install_bazel_tools()
    install_staticcheck()
    install_helm()
    install_kubectl()
    install_kind()

    # Install golang.org/x/build as kubernetes/repo-infra requires it for the
    # build-tar bazel target.
    go_repository(
        name = "org_golang_x_build",
        build_file_generation = "on",
        build_file_proto_mode = "disable",
        importpath = "golang.org/x/build",
        sum = "h1:hXVePvSFG7tPGX4Pwk1d10ePFfoTCc0QmISfpKOHsS8=",
        version = "v0.0.0-20190927031335-2835ba2e683f",
    )

def install_staticcheck():
    http_archive(
        name = "co_honnef_go_tools_staticcheck_linux",
        sha256 = "09d2c2002236296de2c757df111fe3ae858b89f9e183f645ad01f8135c83c519",
        urls = ["https://github.com/dominikh/go-tools/releases/download/2020.1.4/staticcheck_linux_amd64.tar.gz"],
        build_file_content = """
filegroup(
    name = "file",
    srcs = [
        "staticcheck/staticcheck",
    ],
    visibility = ["//visibility:public"],
)
""",
    )

    http_archive(
        name = "co_honnef_go_tools_staticcheck_osx",
        sha256 = "5706d101426c025e8f165309e0cb2932e54809eb035ff23ebe19df0f810699d8",
        urls = ["https://github.com/dominikh/go-tools/releases/download/2020.1.4/staticcheck_darwin_amd64.tar.gz"],
        build_file_content = """
filegroup(
    name = "file",
    srcs = [
        "staticcheck/staticcheck",
    ],
    visibility = ["//visibility:public"],
)
""",
    )

def install_misc():
    http_file(
        name = "jq_linux",
        executable = 1,
        sha256 = "c6b3a7d7d3e7b70c6f51b706a3b90bd01833846c54d32ca32f0027f00226ff6d",
        urls = ["https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64"],
    )

    http_file(
        name = "jq_osx",
        executable = 1,
        sha256 = "386e92c982a56fe4851468d7a931dfca29560cee306a0e66c6a1bd4065d3dac5",
        urls = ["https://github.com/stedolan/jq/releases/download/jq-1.5/jq-osx-amd64"],
    )

# Install dependencies used by the controller-runtime integration test framework
def install_integration_test_dependencies():
    http_file(
        name = "kube-apiserver_darwin_amd64",
        executable = 1,
        sha256 = "a874d479f183f9e4c19a5c69b44955fabd2e250b467d2d9f0641ae91a82ddbea",
        urls = ["https://storage.googleapis.com/cert-manager-testing-assets/kube-apiserver-1.17.3_darwin_amd64"],
    )

    http_file(
        name = "kube-apiserver_linux_amd64",
        executable = 1,
        sha256 = "b4505b838b27b170531afbdef5e7bfaacf83da665f21b0e3269d1775b0defb7a",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.17.3/bin/linux/amd64/kube-apiserver"],
    )

    http_archive(
        name = "com_coreos_etcd_darwin_amd64",
        sha256 = "c8f36adf4f8fb7e974f9bafe6e390a03bc33e6e465719db71d7ed3c6447ce85a",
        urls = ["https://github.com/etcd-io/etcd/releases/download/v3.3.12/etcd-v3.3.12-darwin-amd64.zip"],
        build_file_content = """
filegroup(
    name = "file",
    srcs = [
        "etcd-v3.3.12-darwin-amd64/etcd",
    ],
    visibility = ["//visibility:public"],
)
""",
    )

    http_archive(
        name = "com_coreos_etcd_linux_amd64",
        sha256 = "dc5d82df095dae0a2970e4d870b6929590689dd707ae3d33e7b86da0f7f211b6",
        urls = ["https://github.com/etcd-io/etcd/releases/download/v3.3.12/etcd-v3.3.12-linux-amd64.tar.gz"],
        build_file_content = """
filegroup(
    name = "file",
    srcs = [
        "etcd-v3.3.12-linux-amd64/etcd",
    ],
    visibility = ["//visibility:public"],
)
""",
    )

# Install additional tools for Bazel management
def install_bazel_tools():
    ## Install buildozer, for mass-editing BUILD files
    http_file(
        name = "buildozer_darwin",
        executable = 1,
        sha256 = "f2bcb59b96b1899bc27d5791f17a218f9ce76261f5dcdfdbd7ad678cf545803f",
        urls = ["https://github.com/bazelbuild/buildtools/releases/download/0.22.0/buildozer.osx"],
    )

    http_file(
        name = "buildozer_linux",
        executable = 1,
        sha256 = "7750fe5bfb1247e8a858f3c87f63a5fb554ee43cb10efc1ce46c2387f1720064",
        urls = ["https://github.com/bazelbuild/buildtools/releases/download/0.22.0/buildozer"],
    )

# Install Helm targets
def install_helm():
    ## Fetch helm & tiller for use in template generation and testing
    ## You can bump the version of Helm & Tiller used during e2e tests by tweaking
    ## the version numbers in these rules.
    http_archive(
        name = "helm_darwin",
        sha256 = "05c7748da0ea8d5f85576491cd3c615f94063f20986fd82a0f5658ddc286cdb1",
        urls = ["https://get.helm.sh/helm-v3.0.2-darwin-amd64.tar.gz"],
        build_file_content =
            """
filegroup(
    name = "file",
    srcs = [
        "darwin-amd64/helm",
    ],
    visibility = ["//visibility:public"],
)
""",
    )

    http_archive(
        name = "helm_linux",
        sha256 = "c6b7aa7e4ffc66e8abb4be328f71d48c643cb8f398d95c74d075cfb348710e1d",
        urls = ["https://get.helm.sh/helm-v3.0.2-linux-amd64.tar.gz"],
        build_file_content =
            """
filegroup(
    name = "file",
    srcs = [
        "linux-amd64/helm",
    ],
    visibility = ["//visibility:public"],
)
""",
    )

# Define rules for different kubectl versions
def install_kubectl():
    http_file(
        name = "kubectl_1_18_darwin",
        executable = 1,
        sha256 = "5eda86058a3db112821761b32afce3fdd2f6963ab580b1780a638ac323864eba",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.18.0/bin/darwin/amd64/kubectl"],
    )

    http_file(
        name = "kubectl_1_18_linux",
        executable = 1,
        sha256 = "bb16739fcad964c197752200ff89d89aad7b118cb1de5725dc53fe924c40e3f7",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.18.0/bin/linux/amd64/kubectl"],
    )

## Fetch kind images used during e2e tests
def install_kind():
    # install kind binary
    http_file(
        name = "kind_darwin",
        executable = 1,
        sha256 = "11b8a7fda7c9d6230f0f28ffe57831a7227c0655dfb8d38e838e8f03db6612de",
        urls = ["https://github.com/kubernetes-sigs/kind/releases/download/v0.7.0/kind-darwin-amd64"],
    )

    http_file(
        name = "kind_linux",
        executable = 1,
        sha256 = "0e07d5a9d5b8bf410a1ad8a7c8c9c2ea2a4b19eda50f1c629f1afadb7c80fae7",
        urls = ["https://github.com/kubernetes-sigs/kind/releases/download/v0.7.0/kind-linux-amd64"],
    )
