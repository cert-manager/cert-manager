# Deployment files

This directory previously contained the Kubernetes manifests needed to deploy cert-manager.

For full information on deploying cert-manager, see the [getting started guide](https://docs.cert-manager.io/en/latest/getting-started/index.html).

## Where are the manifests now?

From v0.8 onwards, the 'static deployment manifests' are generated
automatically from the [official helm chart](../charts/cert-manager).

When a new release of cert-manager is cut, these manifests will be
automatically generated and published as an asset **attached to the GitHub release**.

## How can I generate my own manifests?

If you want to build a copy of your own manifests for testing purposes, you
can do so using Bazel.

To build the manifests, run:

```bash
$ bazel build //deploy/manifests:cert-manager
# Alternatively, build the openshift variant with:
$ bazel build //deploy/manifests:cert-manager-openshift.yaml
# Or the no-webhook variant with:
$ bazel build //deploy/manifests:cert-manager-no-webhook
```

This will generate the static deployment manifests at
`bazel-bin/deploy/manifests/cert-manager.yaml`.
