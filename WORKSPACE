load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")

## Load rules_go and dependencies
http_archive(
    name = "io_bazel_rules_go",
    urls = ["https://github.com/bazelbuild/rules_go/releases/download/0.16.6/rules_go-0.16.6.tar.gz"],
    sha256 = "ade51a315fa17347e5c31201fdc55aa5ffb913377aa315dceb56ee9725e620ee",
)

load(
    "@io_bazel_rules_go//go:def.bzl",
    "go_rules_dependencies",
    "go_register_toolchains",
)

go_rules_dependencies()

go_register_toolchains(
    go_version = "1.11.5",
)

## Load gazelle and dependencies
http_archive(
    name = "bazel_gazelle",
    url = "https://github.com/bazelbuild/bazel-gazelle/releases/download/0.16.0/bazel-gazelle-0.16.0.tar.gz",
    sha256 = "7949fc6cc17b5b191103e97481cf8889217263acf52e00b560683413af204fcb",
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
    tag = "v0.7.0",
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

## Pull some standard base images
container_pull(
    name = "alpine_linux-amd64",
    digest = "sha256:cf2412cab4f40318e722d2604fa6c79b3d28a7cb37988d95ab2453577417359a",
    registry = "index.docker.io",
    repository = "munnerz/alpine",
    tag = "3.8-amd64",
)

container_pull(
    name = "alpine_linux-arm64",
    digest = "sha256:4b8a5fc687674dd11ab769b8a711acba667c752b08697a03f6ffb1f1bcd123e5",
    registry = "index.docker.io",
    repository = "munnerz/alpine",
    tag = "3.8-arm64",
)

container_pull(
    name = "alpine_linux-arm",
    digest = "sha256:185cad013588d77b0e78018b5f275a7849a63a33cd926405363825536597d9e2",
    registry = "index.docker.io",
    repository = "munnerz/alpine",
    tag = "3.8-arm",
)

## Fetch helm & tiller for use in template generation and testing
## You can bump the version of Helm & Tiller used during e2e tests by tweaking
## the version numbers in these rules.
http_archive(
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

http_archive(
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

container_pull(
    name = "io_gcr_helm_tiller",
    registry = "gcr.io",
    repository = "kubernetes-helm/tiller",
    tag = "v2.10.0",
)

## Install 'kind', for creating kubernetes-in-docker clusters
go_repository(
    name = "io_kubernetes_sigs_kind",
    commit = "9307ec01e70ffd56d3a5bc16fb977d4f557a615f",
    importpath = "sigs.k8s.io/kind",
)

## Fetch pebble for use during e2e tests
## You can change the version of Pebble used for tests by changing the 'commit'
## field in this rule
go_repository(
    name = "org_letsencrypt_pebble",
    commit = "2e69bb16af048c491720f23cb284fce685e65fec",
    importpath = "github.com/letsencrypt/pebble",
    build_external = "vendored",
    # Expose the generated go_default_library as 'public' visibility
    patch_cmds = ["sed -i -e 's/private/public/g' 'cmd/pebble/BUILD.bazel'"],
)

## Fetch nginx-ingress for use during e2e tests
## You can change the version of nginx-ingress used for tests by changing the
## 'tag' field in this rule
container_pull(
    name = "io_kubernetes_ingress-nginx",
    registry = "quay.io",
    repository = "kubernetes-ingress-controller/nginx-ingress-controller",
    tag = "0.23.0",
)

container_pull(
    name = "io_gcr_k8s_defaultbackend",
    registry = "k8s.gcr.io",
    repository = "defaultbackend",
    tag = "1.4",
)

## Fetch vault for use during e2e tests
## You can change the version of vault used for tests by changing the 'tag'
## field in this rule
container_pull(
    name = "com_hashicorp_vault",
    registry = "index.docker.io",
    repository = "library/vault",
    tag = "0.9.3",
)

## Fetch kind images used during e2e tests
container_pull(
    name = "kind-1.11",
    registry = "index.docker.io",
    repository = "kindest/node",
    tag = "v1.11.3",
)

container_pull(
    name = "kind-1.12",
    registry = "index.docker.io",
    repository = "kindest/node",
    tag = "v1.12.3",
)

container_pull(
    name = "kind-1.13",
    registry = "index.docker.io",
    repository = "kindest/node",
    tag = "v1.13.2",
)

## Fetch kubectl for use during e2e tests
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

## Install buildozer, for mass-editing BUILD files
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
    tag = "0.26.0",  # check for the latest tag when you install
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

# Load the controller-tools repository in order to build the crd generator tool
go_repository(
    name = "io_kubernetes_sigs_controller-tools",
    commit = "538db3af1387ce55d50b93e500a49925a5768c82",
    importpath = "sigs.k8s.io/controller-tools",
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
