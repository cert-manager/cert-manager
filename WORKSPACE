# gazelle:repository_macro hack/build/repos.bzl%go_repositories
workspace(name = "com_github_jetstack_cert_manager")

load("//:workspace.bzl", "check_min_bazel_version")

# rules_go v0.28.0 requires Bazel v4.0.0 as minimum
# https://github.com/bazelbuild/rules_go/releases/tag/v0.28.0
check_min_bazel_version("4.0.0")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")

http_archive(
    name = "com_google_protobuf",
    sha256 = "14e8042b5da37652c92ef6a2759e7d2979d295f60afd7767825e3de68c856c54",
    strip_prefix = "protobuf-3.18.0",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.18.0.tar.gz"],
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

## Load rules_go and dependencies
http_archive(
    name = "io_bazel_rules_go",
    sha256 = "8e968b5fcea1d2d64071872b12737bbb5514524ee5f0a4f54f5920266c261acb",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.28.0/rules_go-v0.28.0.zip",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.28.0/rules_go-v0.28.0.zip",
    ],
)

load("@io_bazel_rules_go//go:deps.bzl", "go_register_toolchains", "go_rules_dependencies")

go_rules_dependencies()

go_register_toolchains(
    nogo = "@//hack/build:nogo_vet",
    version = "1.17.1",
)

## Load gazelle and dependencies
http_archive(
    name = "bazel_gazelle",
    sha256 = "62ca106be173579c0a167deb23358fdfe71ffa1e4cfdddf5582af26520f1c66f",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/bazel-gazelle/releases/download/v0.23.0/bazel-gazelle-v0.23.0.tar.gz",
        "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.23.0/bazel-gazelle-v0.23.0.tar.gz",
    ],
)

load("//hack/build:repos.bzl", "go_repositories")

go_repositories()

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")

gazelle_dependencies()

## Load kubernetes repo-infra for tools like kazel
http_archive(
    name = "io_k8s_repo_infra",
    sha256 = "c1da51ca6d34b1ec767125c7a7ca5d7d890c9e5772210ae43fd2aba88a6dda41",
    strip_prefix = "repo-infra-0.1.10",
    urls = [
        "https://github.com/kubernetes/repo-infra/archive/v0.1.10.tar.gz",
    ],
)

## Load rules_docker and dependencies, for working with docker images
http_archive(
    name = "io_bazel_rules_docker",
    sha256 = "5d31ad261b9582515ff52126bf53b954526547a3e26f6c25a9d64c48a31e45ac",
    strip_prefix = "rules_docker-0.18.0",
    urls = ["https://github.com/bazelbuild/rules_docker/releases/download/v0.18.0/rules_docker-v0.18.0.tar.gz"],
)

load(
    "@io_bazel_rules_docker//repositories:repositories.bzl",
    container_repositories = "repositories",
)

container_repositories()

load(
    "@io_bazel_rules_docker//go:image.bzl",
    _go_image_repos = "repositories",
)

_go_image_repos()

# Load and define targets defined in //hack/bin
load("//hack/bin:deps.bzl", install_hack_bin = "install")

install_hack_bin()

# Load and define targets defined in //test/e2e
load("//test/e2e:images.bzl", install_e2e_images = "install")

install_e2e_images()

# Install build image targets
load("//build:images.bzl", "define_base_images")

define_base_images()

# Buildbuddy RBE
http_archive(
    name = "io_buildbuddy_buildbuddy_toolchain",
    sha256 = "a2a5cccec251211e2221b1587af2ce43c36d32a42f5d881737db3b546a536510",
    strip_prefix = "buildbuddy-toolchain-829c8a574f706de5c96c54ca310f139f4acda7dd",
    urls = ["https://github.com/buildbuddy-io/buildbuddy-toolchain/archive/829c8a574f706de5c96c54ca310f139f4acda7dd.tar.gz"],
)

load("@io_buildbuddy_buildbuddy_toolchain//:deps.bzl", "buildbuddy_deps")

buildbuddy_deps()

load("@io_buildbuddy_buildbuddy_toolchain//:rules.bzl", "buildbuddy")

buildbuddy(name = "buildbuddy_toolchain")