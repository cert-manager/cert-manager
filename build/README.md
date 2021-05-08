## Images

### Stamping

Bazel has a concept of stamping which allows embedding additional information into binaries and ensuring that those binaries get rebuilt when the information changes. 
The additional information has to come from Bazel's stable workspace variables, see https://docs.bazel.build/versions/master/user-manual.html#workspace_status.
Stamping can be used with rules that have the `stamp` attribute such as `go_image`.
To enable stamping on a particular rule and build, we set `stamp = True` on the rule and pass `--stamp` to the `bazel build` command.

We use stamping to tag images with a name of a Docker registry and a version and ensure that if a different registry or version is specified, the image will be re-bundled.

Stamping values come from `STABLE_DOCKER_REGISTRY`, `STABLE_DOCKER_TAG` stable workspace variables declared in ./hack/build/print-workspace-status.sh.
This script will be run before every Bazel build as specified in our in .bazelrc file.
