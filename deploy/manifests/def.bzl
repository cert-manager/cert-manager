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

load("@io_k8s_repo_infra//defs:go.bzl", "go_genrule")

def generated_crds(name, go_prefix, paths, visibility = [], deps = []):
    go_genrule(
        name = name,
        tools = [
            "@io_k8s_sigs_controller_tools//cmd/controller-gen",
            "@go_sdk//:bin/go",
        ],
        cmd = " ".join([
            # Make the 'go' tool accessible to controller-gen
            "go=$$(pwd)/$(location @go_sdk//:bin/go);",
            "export PATH=$$(dirname \"$$go\"):$$PATH;",
            # controller-gen requires GOPATH to be non-relative
            "relative_gopath=$$GOPATH;",
            "export GOPATH=$$(pwd)/$$relative_gopath;",
            "export GOROOT=$$(pwd)/$$GOROOT;",
            # GOCACHE must be non-empty if HOME is not set
            "export GOCACHE=$$(mktemp -d);",
            # create an output directory to store each CRD file
            "output_dir=$$(mktemp -d);",
            "out=$$(pwd)/$(location :crds.yaml.generated);",
            # obtain absolute path to controller-gen
            "cg=\"$$(pwd)/$(location @io_k8s_sigs_controller_tools//cmd/controller-gen)\";",
            "cd \"$$GOPATH/src/" + go_prefix + "\";",
            "$$cg",
            "paths=%s" % ",".join(paths),
            "crd:trivialVersions=true",
            "output:crd:dir=$${output_dir};",
            "touch $$out;",
            "for file in $$(find \"$${output_dir}\" -type f | sort -V); do",
            "  cat \"$$file\" >> \"$$out\";",
            "  echo \"---\" >> \"$$out\";",
            "done;",
        ]),
        outs = ["crds.yaml.generated"],
        go_deps = [
            "//pkg/apis/certmanager/v1alpha2:go_default_library",
            "//pkg/apis/acme/v1alpha2:go_default_library",
            "//pkg/apis/meta/v1:go_default_library",
        ],
        visibility = visibility,
    )
