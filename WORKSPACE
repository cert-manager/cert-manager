workspace(
    # How this workspace would be referenced with absolute labels from another workspace
    name = "cert_manager",
)

load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")

## Load rules_go and dependencies
http_archive(
    name = "io_bazel_rules_go",
    urls = [
        "https://storage.googleapis.com/bazel-mirror/github.com/bazelbuild/rules_go/releases/download/0.19.1/rules_go-0.19.1.tar.gz",
        "https://github.com/bazelbuild/rules_go/releases/download/0.19.1/rules_go-0.19.1.tar.gz",
    ],
    sha256 = "8df59f11fb697743cbb3f26cfb8750395f30471e9eabde0d174c3aebc7a1cd39",
)

load("@io_bazel_rules_go//go:deps.bzl", "go_rules_dependencies", "go_register_toolchains")

go_rules_dependencies()

go_register_toolchains(
    go_version = "1.12.7",
)

## Load gazelle and dependencies
http_archive(
    name = "bazel_gazelle",
    url = "https://github.com/bazelbuild/bazel-gazelle/releases/download/0.18.1/bazel-gazelle-0.18.1.tar.gz",
    sha256 = "be9296bfd64882e3c08e3283c58fcb461fa6dd3c171764fcc4cf322f60615a9b",
)

load("@bazel_gazelle//:deps.bzl", "gazelle_dependencies")

gazelle_dependencies()

## Load kubernetes repo-infra for tools like kazel
git_repository(
    name = "io_kubernetes_build",
    commit = "1b2ddaf3fb8775a5d0f4e28085cf846f915977a8",
    remote = "https://github.com/kubernetes/repo-infra.git",
    shallow_since = "1562041369 -0700",
)

## Load rules_docker and depdencies, for working with docker images
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
load("//hack/bin:deps.bzl", install_hack_bin = "install")

install_hack_bin()

# Load and define targets defined in //hack/bin
load("//test/e2e:images.bzl", install_e2e_images = "install")

install_e2e_images()

# Load and define targets used for reference doc generation
load("//docs/generated/reference:deps.bzl", install_docs_dependencies = "install")

install_docs_dependencies()

# The npm_install rule runs yarn anytime the package.json or package-lock.json file changes.
# It also extracts any Bazel rules distributed in an npm package.
load("@build_bazel_rules_nodejs//:defs.bzl", "npm_install")

npm_install(
    # Name this npm so that Bazel Label references look like @brodocs_modules//package
    name = "brodocs_modules",
    package_json = "@brodocs//:package.json",
    package_lock_json = "//docs/generated/reference/generate/bin:package-lock.json",
)

# Install any Bazel rules which were extracted earlier by the npm_install rule.
load("@brodocs_modules//:install_bazel_dependencies.bzl", "install_bazel_dependencies")

install_bazel_dependencies()
