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
    install_helm()
    install_kubectl()
    install_kind()

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

    # Load the controller-tools repository in order to build the crd generator tool
    go_repository(
        name = "io_kubernetes_sigs_controller-tools",
        commit = "538db3af1387ce55d50b93e500a49925a5768c82",
        importpath = "sigs.k8s.io/controller-tools",
    )

# Install dependencies used by the controller-runtime integration test framework
def install_integration_test_dependencies():
    http_file(
        name = "kube-apiserver_1_14_darwin",
        executable = 1,
        sha256 = "8a7a21a5683386998ebd3a4fe9af346626ebdaf84a59094a2b2188e59e13b6d6",
        urls = ["https://storage.googleapis.com/cert-manager-testing-assets/kube-apiserver-1.14.1_darwin_amd64"],
    )

    http_file(
        name = "kube-apiserver_1_14_linux",
        executable = 1,
        sha256 = "1ce67dda7b125dc1adadc10ab93fe339f6ce40211ae4f1552d6de177e36a430d",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.14.1/bin/linux/amd64/kube-apiserver"],
    )

    http_archive(
        name = "etcd_v3_3_darwin",
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
        name = "etcd_v3_3_linux",
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
        sha256 = "9469da75bb357bc325c985dead224480bbacc7aa8aecff74089dff97e64655d0",
        urls = ["https://get.helm.sh/helm-v2.14.2-darwin-amd64.tar.gz"],
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
        sha256 = "9f50e69cf5cfa7268b28686728ad0227507a169e52bf59c99ada872ddd9679f0",
        urls = ["https://get.helm.sh/helm-v2.14.2-linux-amd64.tar.gz"],
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
        name = "kubectl_1_11_darwin",
        executable = 1,
        sha256 = "cf1feeac2fdedfb069131e7d62735b99b49ec43bf0d7565a30379c35056906c4",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.11.3/bin/darwin/amd64/kubectl"],
    )

    http_file(
        name = "kubectl_1_11_linux",
        executable = 1,
        sha256 = "0d4c70484e90d4310f03f997b4432e0a97a7f5b5be5c31d281f3d05919f8b46c",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.11.3/bin/linux/amd64/kubectl"],
    )

    http_file(
        name = "kubectl_1_12_darwin",
        executable = 1,
        sha256 = "ccddf5b78cd24d5782f4fbe436eee974ca3d901a2d850c24693efa8824737979",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.12.3/bin/darwin/amd64/kubectl"],
    )

    http_file(
        name = "kubectl_1_12_linux",
        executable = 1,
        sha256 = "a93cd2ffd146bbffb6ea651b71b57fe377ba1f158c7c0eb16c14aa93394cd576",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.12.3/bin/linux/amd64/kubectl"],
    )

    http_file(
        name = "kubectl_1_13_darwin",
        executable = 1,
        sha256 = "e656a8ac9272d04febf2ed29b2e8866bfdb73f55e098026384268851d7aeba74",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.13.2/bin/darwin/amd64/kubectl"],
    )

    http_file(
        name = "kubectl_1_13_linux",
        executable = 1,
        sha256 = "2c7ab398559c7f4f91102c4a65184e0a5a3a137060c3179e9361d9c20b467181",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.13.2/bin/linux/amd64/kubectl"],
    )

    http_file(
        name = "kubectl_1_14_darwin",
        executable = 1,
        sha256 = "b4f6d583014f3dc9f3912d68b5aaa20a25394ecc43b42b2df3d37ef7c4a6f819",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.14.3/bin/darwin/amd64/kubectl"],
    )

    http_file(
        name = "kubectl_1_14_linux",
        executable = 1,
        sha256 = "ebc8c2fadede148c2db1b974f0f7f93f39f19c8278619893fd530e20e9bec98f",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.14.3/bin/linux/amd64/kubectl"],
    )

    http_file(
        name = "kubectl_1_15_darwin",
        executable = 1,
        sha256 = "63f1ace419edffa1f5ebb64a6c63597afd48f8d94a61d4fb44e820139adbbe54",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.15.0/bin/darwin/amd64/kubectl"],
    )

    http_file(
        name = "kubectl_1_15_linux",
        executable = 1,
        sha256 = "ecec7fe4ffa03018ff00f14e228442af5c2284e57771e4916b977c20ba4e5b39",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.15.0/bin/linux/amd64/kubectl"],
    )

    http_file(
        name = "kubectl_1_16_darwin",
        executable = 1,
        sha256 = "ab04b4e950fb7a8fa24da1d646af6d2fd7c1c7f09254af3783c920d258a94b1a",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.16.0-alpha.1/bin/darwin/amd64/kubectl"],
    )

    http_file(
        name = "kubectl_1_16_linux",
        executable = 1,
        sha256 = "05942f4d57305dedeb76102a8d7ba0476914a1cd373e51d503923e6c96c4dc45",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.16.0-alpha.1/bin/linux/amd64/kubectl"],
    )

## Fetch kind images used during e2e tests
def install_kind():
    # install kind binary
    http_file(
        name = "kind_darwin",
        executable = 1,
        sha256 = "023f1886207132dcfc62139a86f09488a79210732b00c9ec6431d6f6b7e9d2d3",
        urls = ["https://github.com/kubernetes-sigs/kind/releases/download/v0.4.0/kind-darwin-amd64"],
    )

    http_file(
        name = "kind_linux",
        executable = 1,
        sha256 = "a97f7d6d97bc0e261ea85433ca564269f117baf0fae051f16b296d2d7541f8dd",
        urls = ["https://github.com/kubernetes-sigs/kind/releases/download/v0.4.0/kind-linux-amd64"],
    )

    container_pull(
        name = "kind-1.11",
        registry = "index.docker.io",
        repository = "kindest/node",
        tag = "v1.11.10",
        digest = "sha256:176845d919899daef63d0dbd1cf62f79902c38b8d2a86e5fa041e491ab795d33",
    )

    container_pull(
        name = "kind-1.12",
        registry = "index.docker.io",
        repository = "kindest/node",
        tag = "v1.12.9",
        digest = "sha256:bcb79eb3cd6550c1ba9584ce57c832dcd6e442913678d2785307a7ad9addc029",
    )

    container_pull(
        name = "kind-1.13",
        registry = "index.docker.io",
        repository = "kindest/node",
        tag = "v1.13.7",
        digest = "sha256:f3f1cfc2318d1eb88d91253a9c5fa45f6e9121b6b1e65aea6c7ef59f1549aaaf",
    )    

    container_pull(
        name = "kind-1.14",
        registry = "index.docker.io",
        repository = "kindest/node",
        tag = "v1.14.3",
        digest = "sha256:583166c121482848cd6509fbac525dd62d503c52a84ff45c338ee7e8b5cfe114",
    )

    container_pull(
        name = "kind-1.15",
        registry = "index.docker.io",
        repository = "kindest/node",
        tag = "v1.15.0",
        digest = "sha256:b4d092fd2b507843dd096fe6c85d06a27a0cbd740a0b32a880fe61aba24bb478",
    )

    container_pull(
        name = "kind-1.16",
        registry = "eu.gcr.io",
        repository = "jetstack-build-infra-images/kind-node",
        tag = "1.16.0-alpha.1",
        digest = "sha256:b9775b688fda2e6434cda1b9016baf876f381a8325961f59b9ae238166259885",
    )
