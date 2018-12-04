# Deployment files

This directory contains the Kubernetes manifests needed to deploy cert-manager.

For full information on deploying cert-manager, see the [getting started guide](TODO).

## Where do these come from?

The manifests in this are generated from the Helm chart automatically.
The [helm-values.yaml](./helm-values.yaml) file in this directory is used to
generate the [cert-manager.yaml](./cert-manager.yaml) manifest.

They are automatically generated using `bazel run //hack:update-deploy-gen`.
