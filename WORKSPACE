load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")

## Load rules_go and dependencies
http_archive(
    name = "io_bazel_rules_go",
    urls = ["https://github.com/bazelbuild/rules_go/releases/download/0.16.2/rules_go-0.16.2.tar.gz"],
    sha256 = "f87fa87475ea107b3c69196f39c82b7bbf58fe27c62a338684c20ca17d1d8613",
)

load(
    "@io_bazel_rules_go//go:def.bzl",
    "go_rules_dependencies",
    "go_register_toolchains",
)

go_rules_dependencies()

go_register_toolchains(
    go_version = "1.11.2",
)

## Load gazelle and dependencies
http_archive(
    name = "bazel_gazelle",
    url = "https://github.com/bazelbuild/bazel-gazelle/releases/download/0.15.0/bazel-gazelle-0.15.0.tar.gz",
    sha256 = "6e875ab4b6bf64a38c352887760f21203ab054676d9c1b274963907e0768740d",
)

load(
    "@bazel_gazelle//:deps.bzl",
    "gazelle_dependencies",
    "go_repository",
)

gazelle_dependencies()

## Load kubernetes repo-infra for tools like kazel
git_repository(
    name = "io_kubernetes_build",
    commit = "84d52408a061e87d45aebf5a0867246bdf66d180",
    remote = "https://github.com/kubernetes/repo-infra.git",
)

## Load rules_docker and depdencies, for working with docker images
git_repository(
    name = "io_bazel_rules_docker",
    remote = "https://github.com/bazelbuild/rules_docker.git",
    tag = "v0.5.1",
)

load(
    "@io_bazel_rules_docker//container:container.bzl",
    "container_pull",
    container_repositories = "repositories",
)

container_repositories()

load(
    "@io_bazel_rules_docker//go:image.bzl",
    _go_image_repos = "repositories",
)

_go_image_repos()

## Pull some standard base images
container_pull(
    name = "alpine",
    registry = "gcr.io",
    repository = "jetstack-build-infra/alpine",
    tag = "3.7-v20180822-0201cfb11",
)

container_pull(
    name = "kind-1.12",
    registry = "eu.gcr.io",
    repository = "jetstack-build-infra-images/kind",
    tag = "1.12.2-1",
)

container_pull(
    name = "kind-1.11",
    registry = "eu.gcr.io",
    repository = "jetstack-build-infra-images/kind",
    tag = "1.11.4-1",
)

## Fetch helm for use in template generation and testing
new_http_archive(
    name = "helm_darwin",
    sha256 = "7c4e6bfbc211d6b984ffb4fa490ce9ac112cc4b9b8d859ece27045b8514c1ed1",
    urls = ["https://storage.googleapis.com/kubernetes-helm/helm-v2.10.0-darwin-amd64.tar.gz"],
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

new_http_archive(
    name = "helm_linux",
    sha256 = "0fa2ed4983b1e4a3f90f776d08b88b0c73fd83f305b5b634175cb15e61342ffe",
    urls = ["https://storage.googleapis.com/kubernetes-helm/helm-v2.10.0-linux-amd64.tar.gz"],
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

## Install 'kind', for creating kubernetes-in-docker clusters
go_repository(
    name = "io_kubernetes_sigs_kind",
    commit = "f8aa772a580596b7abc4c9a84e791640b4c604d0",
    importpath = "sigs.k8s.io/kind",
)

## Install dep for dependency management
http_file(
    name = "dep_darwin",
    executable = 1,
    sha256 = "1a7bdb0d6c31ecba8b3fd213a1170adf707657123e89dff234871af9e0498be2",
    urls = ["https://github.com/golang/dep/releases/download/v0.5.0/dep-darwin-amd64"],
)

http_file(
    name = "dep_linux",
    executable = 1,
    sha256 = "287b08291e14f1fae8ba44374b26a2b12eb941af3497ed0ca649253e21ba2f83",
    urls = ["https://github.com/golang/dep/releases/download/v0.5.0/dep-linux-amd64"],
)

## Brodocs and associated dependencies
new_git_repository(
    name = "brodocs",
    remote = "https://github.com/munnerz/brodocs.git",
    # We use this specific revision as it contains changes that allow us to
    # specify custom paths when building documentation.
    commit = "94937a75f3fd680df04a2cfb06ea7299aad156e9",
    build_file_content = """
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

# Setup npm for brodocs doc generation
git_repository(
    name = "build_bazel_rules_nodejs",
    remote = "https://github.com/bazelbuild/rules_nodejs.git",
    tag = "0.15.0",  # check for the latest tag when you install
)

load("@build_bazel_rules_nodejs//:package.bzl", "rules_nodejs_dependencies")

rules_nodejs_dependencies()

load("@build_bazel_rules_nodejs//:defs.bzl", "node_repositories")

# TODO: do we need to specify this package.json in node_repositories as well as
# in npm_install?
node_repositories(package_json = ["@brodocs//:package.json"])

load("@build_bazel_rules_nodejs//:defs.bzl", "npm_install")

npm_install(
    name = "brodocs_modules",
    package_json = "@brodocs//:package.json",
    package_lock_json = "//docs/generated/reference/generate/bin:package-lock.json",
)

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
