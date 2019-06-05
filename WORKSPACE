load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_archive")
load("@bazel_tools//tools/build_defs/repo:http.bzl", "http_file")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "git_repository")
load("@bazel_tools//tools/build_defs/repo:git.bzl", "new_git_repository")

## Load rules_go and dependencies
http_archive(
    name = "io_bazel_rules_go",
    url = "https://github.com/bazelbuild/rules_go/releases/download/0.18.2/rules_go-0.18.2.tar.gz",
    sha256 = "31f959ecf3687f6e0bb9d01e1e7a7153367ecd82816c9c0ae149cd0e5a92bf8c",
)

load("@io_bazel_rules_go//go:deps.bzl", "go_rules_dependencies", "go_register_toolchains")

go_rules_dependencies()

go_register_toolchains(
    go_version = "1.12",
)

## Load gazelle and dependencies
http_archive(
    name = "bazel_gazelle",
    url = "https://github.com/bazelbuild/bazel-gazelle/releases/download/0.17.0/bazel-gazelle-0.17.0.tar.gz",
    sha256 = "3c681998538231a2d24d0c07ed5a7658cb72bfb5fd4bf9911157c0e9ac6a2687",
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
    commit = "df02ded38f9506e5bbcbf21702034b4fef815f2f",
    remote = "https://github.com/kubernetes/repo-infra.git",
)

## Load rules_docker and depdencies, for working with docker images
git_repository(
    name = "io_bazel_rules_docker",
    remote = "https://github.com/bazelbuild/rules_docker.git",
    commit = "3732c9d05315bef6a3dbd195c545d6fea3b86880",
    shallow_since = "1547471117 +0100",
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
    commit = "161151a26faf0dbe962ac9f323cc0cdebac79ba8",
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
    tag = "v1.12.5",
)

container_pull(
    name = "kind-1.13",
    registry = "index.docker.io",
    repository = "kindest/node",
    tag = "v1.13.4",
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

http_file(
    name = "kube-apiserver_1_14_darwin",
    executable = 1,
    sha256 = "8a7a21a5683386998ebd3a4fe9af346626ebdaf84a59094a2b2188e59e13b6d6",
    urls = ["https://storage.googleapis.com/cert-manager-testing-assets/kube-apiserver-1.14.1_darwin_amd64"],
)

http_file(
    name = "kube-apiserver_1_14_linux",
    executable = 1,
    sha256 = "1ce67dda7b125dc1adadc10ab93fe339f6ce40211ae4f1552d6de177e36a430d",
    urls = ["https://storage.googleapis.com/kubernetes-release/release/v1.14.1/bin/linux/amd64/kube-apiserver"],
)

http_archive(
    name = "etcd_v3_3_darwin",
    sha256 = "c8f36adf4f8fb7e974f9bafe6e390a03bc33e6e465719db71d7ed3c6447ce85a",
    urls = ["https://github.com/etcd-io/etcd/releases/download/v3.3.12/etcd-v3.3.12-darwin-amd64.zip"],
    build_file_content = """
filegroup(
    name = "file",
    srcs = [
        "etcd-v3.3.12-darwin-amd64/etcd",
    ],
    visibility = ["//visibility:public"],
)
""",
)

http_archive(
    name = "etcd_v3_3_linux",
    sha256 = "dc5d82df095dae0a2970e4d870b6929590689dd707ae3d33e7b86da0f7f211b6",
    urls = ["https://github.com/etcd-io/etcd/releases/download/v3.3.12/etcd-v3.3.12-linux-amd64.tar.gz"],
    build_file_content = """
filegroup(
    name = "file",
    srcs = [
        "etcd-v3.3.12-linux-amd64/etcd",
    ],
    visibility = ["//visibility:public"],
)
""",
)

## Install buildozer, for mass-editing BUILD files
http_file(
    name = "buildozer_darwin",
    executable = 1,
    sha256 = "f2bcb59b96b1899bc27d5791f17a218f9ce76261f5dcdfdbd7ad678cf545803f",
    urls = ["https://github.com/bazelbuild/buildtools/releases/download/0.22.0/buildozer.osx"],
)

http_file(
    name = "buildozer_linux",
    executable = 1,
    sha256 = "7750fe5bfb1247e8a858f3c87f63a5fb554ee43cb10efc1ce46c2387f1720064",
    urls = ["https://github.com/bazelbuild/buildtools/releases/download/0.22.0/buildozer"],
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

http_file(
    name = "jq_linux",
    executable = 1,
    sha256 = "c6b3a7d7d3e7b70c6f51b706a3b90bd01833846c54d32ca32f0027f00226ff6d",
    urls = ["https://github.com/stedolan/jq/releases/download/jq-1.5/jq-linux64"],
)

http_file(
    name = "jq_osx",
    executable = 1,
    sha256 = "386e92c982a56fe4851468d7a931dfca29560cee306a0e66c6a1bd4065d3dac5",
    urls = ["https://github.com/stedolan/jq/releases/download/jq-1.5/jq-osx-amd64"],
)

## Brodocs and associated dependencies
new_git_repository(
    name = "brodocs",
    remote = "https://github.com/munnerz/brodocs.git",
    # We use this specific revision as it contains changes that allow us to
    # specify custom paths when building documentation.
    commit = "28714834053271ebb5a6a5fe22af29f98fc0b6d0",
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
    commit = "11271418a6bbd2529170270a7e61dcc5167bb16d",
    shallow_since = "1554849870 -0700",
)

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
