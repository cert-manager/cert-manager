load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")

http_archive(
    name = "io_bazel_rules_go",
    urls = ["https://github.com/bazelbuild/rules_go/releases/download/0.15.0/rules_go-0.15.0.tar.gz"],
    sha256 = "56d946edecb9879aed8dff411eb7a901f687e242da4fa95c81ca08938dd23bb4",
)
http_archive(
   name = "bazel_gazelle",
   url = "https://github.com/bazelbuild/bazel-gazelle/releases/download/0.14.0/bazel-gazelle-0.14.0.tar.gz",
   sha256 = "c0a5739d12c6d05b6c1ad56f2200cb0b57c5a70e03ebd2f7b87ce88cabf09c7b",
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
    tag = "v0.5.0",
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

# Install buildozer
http_file(
    name = "buildozer_darwin",
    executable = 1,
    sha256 = "294357ff92e7bb36c62f964ecb90e935312671f5a41a7a9f2d77d8d0d4bd217d",
    urls = ["https://github.com/bazelbuild/buildtools/releases/download/0.15.0/buildozer.osx"],
)

http_file(
    name = "buildozer_linux",
    executable = 1,
    sha256 = "be07a37307759c68696c989058b3446390dd6e8aa6fdca6f44f04ae3c37212c5",
    urls = ["https://github.com/bazelbuild/buildtools/releases/download/0.15.0/buildozer"],
)
