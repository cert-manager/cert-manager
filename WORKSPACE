load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
http_archive(
    name = "io_bazel_rules_go",
    urls = ["https://github.com/bazelbuild/rules_go/releases/download/0.14.0/rules_go-0.14.0.tar.gz"],
    sha256 = "5756a4ad75b3703eb68249d50e23f5d64eaf1593e886b9aa931aa6e938c4e301",
)
#http_archive(
#    name = "bazel_gazelle",
#    url = "https://github.com/bazelbuild/bazel-gazelle/releases/download/0.10.0/bazel-gazelle-0.10.0.tar.gz",
#    sha256 = "6228d9618ab9536892aa69082c063207c91e777e51bd3c5544c9c060cafe1bd8",
#)
git_repository(
    name = "bazel_gazelle",
    remote = "https://github.com/bazelbuild/bazel-gazelle.git",
    commit = "f4ae892927eeabd060c59693c38e82303f41558d",
)
git_repository(
    name = "io_kubernetes_build",
    commit = "4ce715fbe67d8fbed05ec2bb47a148e754100a4b",
    remote = "https://github.com/kubernetes/repo-infra.git",
)
load(
    "@io_bazel_rules_go//go:def.bzl",
    "go_rules_dependencies",
    "go_register_toolchains",
)
go_rules_dependencies()
go_register_toolchains()
load(
    "@bazel_gazelle//:deps.bzl",
    "gazelle_dependencies",
)
gazelle_dependencies()

git_repository(
    name = "io_bazel_rules_docker",
    remote = "https://github.com/bazelbuild/rules_docker.git",
    tag = "v0.4.0",
)
load(
    "@io_bazel_rules_docker//container:container.bzl",
    "container_pull",
    container_repositories = "repositories",
)

# This is NOT needed when going through the language lang_image
# "repositories" function(s).
container_repositories()

load(
    "@io_bazel_rules_docker//go:image.bzl",
    _go_image_repos = "repositories",
)
_go_image_repos()

container_pull(
    name = "alpine",
    registry = "index.docker.io",
    repository = "library/alpine",
    tag = "3.5",
)
