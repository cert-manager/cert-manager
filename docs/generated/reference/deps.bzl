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

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")
load("@bazel_gazelle//:deps.bzl", "go_repository")

# Install brodocs and related dependencies
def install():
    install_brodocs()
    install_reference_docs_deps()

def install_brodocs():
    ## Brodocs and associated dependencies
    new_git_repository(
        name = "brodocs",
        remote = "https://github.com/munnerz/brodocs.git",
        # We use this specific revision as it contains changes that allow us to
        # specify custom paths when building documentation.
        commit = "28714834053271ebb5a6a5fe22af29f98fc0b6d0",
        shallow_since = "1556994488 +0100",
        build_file_content = """
exports_files(["brodoc.js"])

filegroup(
    name = "all-srcs",
    srcs = glob(["**/*"]),
    visibility = ["//visibility:public"],
)

filegroup(
    name = "static",
    srcs = [
        "stylesheet.css",
        "scroll.js",
        "actions.js",
        "tabvisibility.js",
    ],
    visibility = ["//visibility:public"],
)
""",
    )

    # Install the nodejs "bootstrap" package
    # This provides the basic tools for running and packaging nodejs programs in Bazel
    http_archive(
        name = "build_bazel_rules_nodejs",
        sha256 = "395b7568f20822c13fc5abc65b1eced637446389181fda3a108fdd6ff2cac1e9",
        urls = ["https://github.com/bazelbuild/rules_nodejs/releases/download/0.29.2/rules_nodejs-0.29.2.tar.gz"],
    )

def install_reference_docs_deps():
    # Load kubernetes-incubator/reference-docs, to be used as part of the docs
    # generation pipeline.
    # This involves quite a few dependencies, hence the long list of go_repository
    # rules.
    # We include them here instead of in Gopkg.{toml,lock} to save extra sources in
    # the repository.
    # These were all taken from the HEAD of each repositories 'master' branch.
    go_repository(
        name = "io_kubernetes_incubator_reference_docs",
        # Points to HEAD of the 'kubebuilder' branch
        commit = "1959039a016c77efe6786b19f3f55f7b3042604f",
        importpath = "github.com/kubernetes-incubator/reference-docs",
    )

    go_repository(
        name = "in_gopkg_yaml_v2",
        commit = "5420a8b6744d3b0345ab293f6fcba19c978f1183",
        remote = "https://github.com/go-yaml/yaml",
        vcs = "git",
        importpath = "gopkg.in/yaml.v2",
    )

    go_repository(
        name = "com_github_go_openapi_spec",
        commit = "f1468acb3b29cdd5c5f6fa29435d2d2d6e6c9ff1",
        importpath = "github.com/go-openapi/spec",
    )

    go_repository(
        name = "com_github_go_openapi_loads",
        commit = "fd899182a268dcf25de088722375311d9dee2662",
        importpath = "github.com/go-openapi/loads",
    )

    go_repository(
        name = "com_github_go_openapi_swag",
        commit = "dd0dad036e67ae93c27dc64337b3f76296f3a5f0",
        importpath = "github.com/go-openapi/swag",
    )

    go_repository(
        name = "com_github_go_openapi_analysis",
        commit = "b006789cd277d4fa4d16767046d694a256c6a218",
        importpath = "github.com/go-openapi/analysis",
    )

    go_repository(
        name = "com_github_go_openapi_jsonreference",
        commit = "1c6a3fa339f2743b7b0fd2b842fc455eca2fa9eb",
        importpath = "github.com/go-openapi/jsonreference",
    )

    go_repository(
        name = "com_github_go_openapi_jsonpointer",
        commit = "52eb3d4b47c6a51ce2693c8e614a15a07c1af435",
        importpath = "github.com/go-openapi/jsonpointer",
    )

    go_repository(
        name = "com_github_go_openapi_strfmt",
        commit = "776114108ccc228238641096ea5be3d24842d4ea",
        importpath = "github.com/go-openapi/strfmt",
    )

    go_repository(
        name = "com_github_go_openapi_errors",
        commit = "87bb653288778f8b0d922c5c3fb8b3f00a47ff28",
        importpath = "github.com/go-openapi/errors",
    )

    go_repository(
        name = "com_github_mailru_easyjson",
        commit = "60711f1a8329503b04e1c88535f419d0bb440bff",
        importpath = "github.com/mailru/easyjson",
    )

    go_repository(
        name = "com_github_puerkitobio_purell",
        commit = "975f53781597ed779763b7b65566e74c4004d8de",
        importpath = "github.com/PuerkitoBio/purell",
    )

    go_repository(
        name = "com_github_puerkitobio_urlesc",
        commit = "de5bf2ad457846296e2031421a34e2568e304e35",
        importpath = "github.com/PuerkitoBio/urlesc",
    )

    go_repository(
        name = "com_github_globalsign_mgo",
        commit = "1ca0a4f7cbcbe61c005d1bd43fdd8bb8b71df6bc",
        importpath = "github.com/globalsign/mgo",
    )

    go_repository(
        name = "com_github_mitchellh_mapstructure",
        commit = "fa473d140ef3c6adf42d6b391fe76707f1f243c8",
        importpath = "github.com/mitchellh/mapstructure",
    )

    go_repository(
        name = "com_github_asaskevich_govalidator",
        commit = "f9ffefc3facfbe0caee3fea233cbb6e8208f4541",
        importpath = "github.com/asaskevich/govalidator",
    )
