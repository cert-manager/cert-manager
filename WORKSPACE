load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")

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

new_git_repository(
    name = "brodocs",
    remote = "https://github.com/munnerz/brodocs.git",
    commit = "94937a75f3fd680df04a2cfb06ea7299aad156e9",
    build_file_content = """
filegroup(
    name = "all-srcs",
    srcs = glob(["**/*"]),
    visibility = ["//visibility:public"],
)
""",
)

# Setup npm for brodocs doc generation
git_repository(
    name = "build_bazel_rules_nodejs",
    remote = "https://github.com/bazelbuild/rules_nodejs.git",
    tag = "0.11.5", # check for the latest tag when you install
)

load("@build_bazel_rules_nodejs//:package.bzl", "rules_nodejs_dependencies")
rules_nodejs_dependencies()

load("@build_bazel_rules_nodejs//:defs.bzl", "node_repositories")

node_repositories(package_json = ["@brodocs//:package.json"])

load("@build_bazel_rules_nodejs//:defs.bzl", "npm_install")

npm_install(
    name = "brodocs_modules",
    package_json = "@brodocs//:package.json",
    package_lock_json = "//hack/brodocs:package-lock.json",
)

# Install Helm for use in template generation and testing
new_http_archive(
    name = "helm_darwin",
    sha256 = "7c4e6bfbc211d6b984ffb4fa490ce9ac112cc4b9b8d859ece27045b8514c1ed1",
    urls = ["https://storage.googleapis.com/kubernetes-helm/helm-v2.10.0-darwin-amd64.tar.gz"],
    build_file = "hack/bazel/BUILD.helm-darwin",
)

new_http_archive(
    name = "helm_linux",
    sha256 = "0fa2ed4983b1e4a3f90f776d08b88b0c73fd83f305b5b634175cb15e61342ffe",
    urls = ["https://storage.googleapis.com/kubernetes-helm/helm-v2.10.0-linux-amd64.tar.gz"],
    build_file = "hack/bazel/BUILD.helm-linux",
)
