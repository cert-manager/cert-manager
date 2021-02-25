# Copyright 2020 The cert-manager Authors.
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

load("@io_bazel_rules_docker//container:image.bzl", "container_image")
load("@io_bazel_rules_docker//container:bundle.bzl", "container_bundle")
load("@io_bazel_rules_docker//go:image.bzl", "go_image")
load("@io_bazel_rules_go//go:def.bzl", "go_test")

def covered_image(name, component, **kwargs):
    native.genrule(
        name = "%s.covered-testfile" % name,
        cmd = """
name="%s";
cat <<EOF > "$@"
package main
import (
  "testing"
  "github.com/cert-manager/cert-manager/pkg/util/coverage"
)
func TestMain(m *testing.M) {
  // Get coverage running
  coverage.InitCoverage("$${name}")
  // Go!
  main()
  // Make sure we actually write the profiling information to disk, if we make it here.
  // On long-running services, or anything that calls os.Exit(), this is insufficient,
  // so we also flush periodically with a default period of five seconds (configurable by
  // the COVERAGE_FLUSH_INTERVAL environment variable).
  coverage.FlushCoverage()
}
EOF
        """ % component,
        outs = ["main_test.go"],
    )

    go_test(
        name = "%s.covered-app" % name,
        srcs = ["main_test.go"],
        embed = [":go_default_library"],
        deps = ["//pkg/util/coverage:go_default_library"],
        tags = ["manual"],
    )

    go_image(
        name = "%s.covered-image" % name,
        base = "@static_base//image",
        binary = "%s.covered-app" % name,
        testonly = True,
    )

    container_image(
        name = name,
        base = "%s.covered-image" % name,
        testonly = True,
        **kwargs)

    container_bundle(
        name = name + ".export",
        images = {
            component + ":{STABLE_APP_GIT_COMMIT}": ":" + name,
        },
        testonly = True,
    )
