# Deployment files

This directory contains the Kubernetes manifests needed to deploy cert-manager.

For full information on deploying cert-manager, see the [getting started guide](https://docs.cert-manager.io/en/latest/getting-started/index.html).

## Where do these come from?

The manifests in this are generated from the Helm chart automatically.
The [helm-values.yaml](./helm-values.yaml) file in this directory is used to
generate the [cert-manager.yaml](./cert-manager.yaml) manifest.

They are automatically generated using `bazel run //hack:update-deploy-gen`.

The [cert-manager-no-webhook.yaml](./cert-manager-no-webhook.yaml) file should
only be used in cases where you are deploying to a cluster **older than v1.9**
or otherwise are not able to make use of ValidatingWebhookConfiguration
resources due to your apiserver not being configured properly.
For more information on the webhook component, please read the 'Resource
Validation Webhook' document under the 'Administrative tasks' section of the
documentation.
