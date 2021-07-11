# Copyright 2021 The cert-manager Authors.
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
load("@bazel_gazelle//:deps.bzl", "go_repository")

def install():
    install_misc()
    install_integration_test_dependencies()
    install_bazel_tools()
    install_staticcheck()
    install_helm()
    install_kubectl()
    install_oc3()
    install_kind()
    install_ytt()

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
        sha256 = "1ffaa079089ce8209f0c89a5d8726d06b8632eb2682e57016ff07f7e29e912dc",
        urls = ["https://github.com/dominikh/go-tools/releases/download/2021.1/staticcheck_linux_amd64.tar.gz"],
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
        sha256 = "03b100561e3bc14db0b3b4004b102a00cb0197938d23cc40193f269f7b246d2d",
        urls = ["https://github.com/dominikh/go-tools/releases/download/2021.1/staticcheck_darwin_amd64.tar.gz"],
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
        sha256 = "af986793a515d500ab2d35f8d2aecd656e764504b789b66d7e1a0b727a124c44",
        urls = ["https://github.com/stedolan/jq/releases/download/jq-1.6/jq-linux64"],
    )

    http_file(
        name = "jq_osx",
        executable = 1,
        sha256 = "5c0a0a3ea600f302ee458b30317425dd9632d1ad8882259fcaf4e9b868b2b1ef",
        urls = ["https://github.com/stedolan/jq/releases/download/jq-1.6/jq-osx-amd64"],
    )

# Install dependencies used by the controller-runtime integration test framework
# Use these links to check for new versions:
# https://console.developers.google.com/storage/kubebuilder-tools/
def install_integration_test_dependencies():
    http_archive(
        name = "kubebuilder-tools_linux_amd64",
        sha256 = "5bee54dcae3bab7689505b438432de9ebfe880ea684aa54c6b81d6bc0d8df86a",
        urls = ["https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-1.21.2-linux-amd64.tar.gz"],
        build_file_content = """
filegroup(
    name = "kube-apiserver",
    srcs = [
        "kubebuilder/bin/kube-apiserver",
    ],
    visibility = ["//visibility:public"],
)
filegroup(
    name = "etcd",
    srcs = [
        "kubebuilder/bin/etcd",
    ],
    visibility = ["//visibility:public"],
)
""",
    )
    
    http_archive(
        name = "kubebuilder-tools_darwin_amd64",
        sha256 = "add3f62be843b0c0f4be17d9159ebea738da18e2f0edce62d945b3ffdd683800",
        urls = ["https://storage.googleapis.com/kubebuilder-tools/kubebuilder-tools-1.21.2-darwin-amd64.tar.gz"],
        build_file_content = """
filegroup(
    name = "kube-apiserver",
    srcs = [
        "kubebuilder/bin/kube-apiserver",
    ],
    visibility = ["//visibility:public"],
)
filegroup(
    name = "etcd",
    srcs = [
        "kubebuilder/bin/etcd",
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
        sha256 = "972944bbd15a20d1527695ba805ca7e7f98c3381c8f521359791e0016f079713",
        urls = ["https://github.com/bazelbuild/buildtools/releases/download/4.0.1/buildozer-darwin-amd64"],
    )

    http_file(
        name = "buildozer_linux",
        executable = 1,
        sha256 = "082aea1df38fe30ce41d955a2cbf309cae8ec386507e0c10cc16f0d9a93e151f",
        urls = ["https://github.com/bazelbuild/buildtools/releases/download/4.0.1/buildozer-linux-amd64"],
    )

# Install Helm targets
def install_helm():
    ## Fetch helm & tiller for use in template generation and testing
    ## You can bump the version of Helm & Tiller used during e2e tests by tweaking
    ## the version numbers in these rules.
    http_archive(
        name = "helm_darwin",
        sha256 = "81a94d2877326012b99ac0737517501e5ed69bb4987884e7f2d0887ad27895a9",
        urls = ["https://get.helm.sh/helm-v3.6.2-darwin-amd64.tar.gz"],
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
        sha256 = "f3a4be96b8a3b61b14eec1a35072e1d6e695352e7a08751775abf77861a0bf54",
        urls = ["https://get.helm.sh/helm-v3.6.2-linux-amd64.tar.gz"],
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
        name = "kubectl_1_21_darwin",
        executable = 1,
        sha256 = "4a6c072223d5944b98601fc9f4cfdc5652ff0919ca91210b7eed5c83f2422fa1",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.21.2/bin/darwin/amd64/kubectl"],
    )

    http_file(
        name = "kubectl_1_21_linux",
        executable = 1,
        sha256 = "55b982527d76934c2f119e70bf0d69831d3af4985f72bb87cd4924b1c7d528da",
        urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.21.2/bin/linux/amd64/kubectl"],
    )


# Define rules for different oc versions
def install_oc3():
    http_archive(
        name = "oc_3_11_linux",
        sha256 = "4b0f07428ba854174c58d2e38287e5402964c9a9355f6c359d1242efd0990da3",
        urls = ["https://github.com/openshift/origin/releases/download/v3.11.0/openshift-origin-client-tools-v3.11.0-0cbc58b-linux-64bit.tar.gz"],
        build_file_content =
         """
filegroup(
     name = "file",
     srcs = [
        "openshift-origin-client-tools-v3.11.0-0cbc58b-linux-64bit/oc",
     ],
     visibility = ["//visibility:public"],
)
    """,
    )
## Fetch kind images used during e2e tests
def install_kind():
    # install kind binary
    http_file(
        name = "kind_darwin",
        executable = 1,
        sha256 = "432bef555a70e9360b44661c759658265b9eaaf7f75f1beec4c4d1e6bbf97ce3",
        urls = ["https://github.com/kubernetes-sigs/kind/releases/download/v0.11.1/kind-darwin-amd64"],
    )

    http_file(
        name = "kind_linux",
        executable = 1,
        sha256 = "949f81b3c30ca03a3d4effdecda04f100fa3edc07a28b19400f72ede7c5f0491",
        urls = ["https://github.com/kubernetes-sigs/kind/releases/download/v0.11.1/kind-linux-amd64"],
    )


# ytt is a yaml interpolator from the Carvel toolchain https://carvel.dev/.
def install_ytt():
    http_file(
        name = "ytt_darwin",
        executable = 1,
        sha256 = "a874395924e670f2c89160efeffc35b94a9bcf4e515e49935cb1ceb22be7f08a",
        urls = ["https://github.com/vmware-tanzu/carvel-ytt/releases/download/v0.34.0/ytt-darwin-amd64"],
    )

    http_file(
        name = "ytt_linux",
        executable = 1,
        sha256 = "49741ac5540fc64da8566f3d1c9538f4f0fec22c62b8ba83e5e3d8efb91ee170",
        urls = ["https://github.com/vmware-tanzu/carvel-ytt/releases/download/v0.34.0/ytt-linux-amd64"],
    )
