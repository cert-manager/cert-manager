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
can do so using the 'release' tool in this repository.

To build the manifests, run:

```bash
$ bazel run //hack/release -- \
    --manifests \
    --app-version={image tag} \
    --docker-repo=quay.io/myuser
```

This will generate static deployment manifests that are configured to use the
specified image repository and tag, making it easy for you to test and
distribute sample manifests.
