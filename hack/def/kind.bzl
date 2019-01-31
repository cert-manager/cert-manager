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

def kind_cluster(
    name,
    version,
    config = None):
  image = "kindest/node:%s" % version

  native.genrule(
    name = name,
    srcs = [
        config,
    ],
    tools = [
        "@io_kubernetes_sigs_kind//:kind",
        "//hack/def:kind.sh",
    ],
    cmd = " ".join([
        "$(location //hack/def:kind.sh)",
        name,
        "$(location @io_kubernetes_sigs_kind//:kind)",
        image,
        "$(location %s)" % config,
        "$(location %s.kubeconfig)" % name,
    ]),
    tags = ["no-cache", "manual"],
    outs = ["%s.kubeconfig" % name],
    # Set stamp = 1 so we re-run the provisioning script if the STABLE_KIND_STATUS
    # variable changes, which indicates we may need to rebuild the cluster.
    stamp = 1,
    visibility = ["//visibility:public"],
  )
