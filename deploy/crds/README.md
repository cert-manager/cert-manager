# CRDs source directory

> **WARNING**: if you are an end-user, you do NOT need to use the files in this
> directory. These files are for **development purposes only**.

This directory contains 'source code' used to build our CustomResourceDefinition
resources in a way that can be consumed by all our different deployment methods.

This package exposes a number of different Bazel targets:

* `templates.regular`: the Helm templates for the 'regular' CRD manifests
* `templates.legacy`: the Helm templates for the 'legacy' CRD manifests
* `crds.regular`: the templated 'regular' CRD manifests (after running `helm template`)
* `crds.legacy`: the templated 'legacy' CRD manifests (after running `helm template`)
* `crd-<crd-name>.templated`: for each CRD type, the one CRD after running `helm template`
* `templated_files`: a filegroup containing all of the individual templated CRD files

Most users should never utilise the files in this directory directly. Instead, Bazel
build targets in other packages (i.e. `//deploy/manifests`, `//deploy/charts` etc)
will be configured to automatically consume the appropriate artifact listed above.
