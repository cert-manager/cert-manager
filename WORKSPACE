# gazelle:repository_macro hack/build/repos.bzl%go_repositories
workspace(name = "com_github_jetstack_cert_manager")

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

http_archive(
    name = "com_google_protobuf",
    sha256 = "2ee9dcec820352671eb83e081295ba43f7a4157181dad549024d7070d079cf65",
    strip_prefix = "protobuf-3.9.0",
    urls = ["https://github.com/protocolbuffers/protobuf/archive/v3.9.0.tar.gz"],
)

load("@com_google_protobuf//:protobuf_deps.bzl", "protobuf_deps")

protobuf_deps()

## Load rules_go and dependencies
http_archive(
    name = "io_bazel_rules_go",
    urls = [
        "https://mirror.bazel.build/github.com/bazelbuild/rules_go/releases/download/v0.22.2/rules_go-v0.22.2.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/v0.22.2/rules_go-v0.22.2.tar.gz",
    ],
    sha256 = "142dd33e38b563605f0d20e89d9ef9eda0fc3cb539a14be1bdb1350de2eda659",
)

load("@io_bazel_rules_go//go:deps.bzl", "go_rules_dependencies", "go_register_toolchains")

go_rules_dependencies()

go_register_toolchains(
    go_version = "1.14.1",
    nogo = "@//hack/build:nogo_vet",
)

## Load gazelle and dependencies
http_archive(
    name = "bazel_gazelle",
    url = "https://github.com/bazelbuild/bazel-gazelle/releases/download/v0.19.1/bazel-gazelle-v0.19.1.tar.gz",
    sha256 = "86c6d481b3f7aedc1d60c1c211c6f76da282ae197c3b3160f54bd3a8f847896f",
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")

gazelle_dependencies()

## Load kubernetes repo-infra for tools like kazel
http_archive(
    name = "io_k8s_repo_infra",
    strip_prefix = "repo-infra-0.0.2",
    sha256 = "774e160ba1a2a66a736fdc39636dca799a09df015ac5e770a46ec43487ec5708",
    urls = [
        "https://github.com/kubernetes/repo-infra/archive/v0.0.2.tar.gz",
    ],
)

## Load rules_docker and dependencies, for working with docker images
git_repository(
    name = "io_bazel_rules_docker",
    remote = "https://github.com/bazelbuild/rules_docker.git",
    commit = "80ea3aae060077e5fe0cdef1a5c570d4b7622100",
    shallow_since = "1561646721 -0700",
)

load(
    "@io_bazel_rules_docker//repositories:repositories.bzl",
    container_repositories = "repositories",
)

container_repositories()

load(
    "@io_bazel_rules_docker//container:container.bzl",
    "container_pull",
)
load(
    "@io_bazel_rules_docker//go:image.bzl",
    _go_image_repos = "repositories",
)

_go_image_repos()

## Use 'static' distroless image for all builds
container_pull(
    name = "static_base",
    registry = "gcr.io",
    repository = "distroless/static",
    digest = "sha256:cd0679a54d2abaf3644829f5e290ad8a10688847475f570fddb9963318cf9390",
)

# Load and define targets defined in //hack/bin
load(
    "//hack/bin:deps.bzl",
    install_hack_bin = "install",
)

install_hack_bin()

# Load and define targets defined in //hack/bin
load(
    "//test/e2e:images.bzl",
    install_e2e_images = "install",
)

install_e2e_images()

load("//hack/build:repos.bzl", "go_repositories")

go_repositories()
