# Copyright 2020 The Jetstack cert-manager contributors.
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

def helm_pkg(
        name,
        path,
        chart_name = None,
        srcs = [],
        helm_cmd = "//hack/bin:helm",
        **kwargs,
):
    if chart_name == None:
        parts = path.split("/")
        chart_name = parts[len(parts) - 1]
    cmds = []
    cmds = cmds + ["version=$$(cat $(location //:version))"]
    cmds = cmds + [" ".join([
        "$(location %s)" % helm_cmd,
        "package",
        "--app-version=$$version",
        "--version=$$version",
        path,
    ])]
    cmds = cmds + ["mv \"%s-$$version.tgz\" $@" % chart_name]
    native.genrule(
        name = name,
        srcs = srcs + ["//:version"],
        stamp = 1,
        outs = ["%s.tgz" % chart_name],
        cmd = "; ".join(cmds),
        tools = [helm_cmd],
        **kwargs,
    )

def helm_tmpl(
        name,
        helm_pkg,
        release_namespace,
        release_name,
        values = {},
        helm_cmd = "//hack/bin:helm",
        **kwargs,
):
    cmds = []
    set_args = []
    for k, v in values.items():
        set_args = set_args + ["--set=%s=%s" % (k, v)]
    tmpl_cmd = [
        "$(location %s)" % helm_cmd,
        "template",
        "--namespace=%s" % release_namespace,
        release_name,
        "$(location %s)" % helm_pkg,
    ] + set_args + ["> $@"]
    cmds = cmds + [" ".join(tmpl_cmd)]
    native.genrule(
        name = name,
        srcs = [helm_pkg, "//:version"],
        stamp = 1,
        outs = ["%s.yaml" % name],
        cmd = "; ".join(cmds),
        tools = [helm_cmd],
        **kwargs,
    )
