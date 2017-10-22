# cert-manager [![Build Status](https://travis-ci.org/jetstack/cert-manager.svg?branch=master)](https://travis-ci.org/jetstack/cert-manager)

cert-manager is a Kubernetes add-on to automate the management and issuance of
TLS certificates from various issuing sources.

It will ensure certificates are valid and up to date periodically, and attempt
to renew certificates at an appropriate time before expiry.

It is loosely based upon the work of [kube-lego](https://github.com/jetstack/kube-lego)
and has borrowed some wisdom from other similar projects e.g.
[kube-cert-manager](https://github.com/PalmStoneGames/kube-cert-manager).

![cert-manager high level overview diagram](/docs/high-level-overview.png)

## Current status

This project is not yet ready to be a component in a critical production stack,
however it *is* at a point where it offers comparable features to other
projects in the space. If you have a non-critical piece of infrastructure, or
are feeling brave, please do try cert-manager and report your experience here
in the issue section.

**NOTE:** currently we provide no guarantees on our API stability. This means
there may be breaking changes that will require changes to *all*
`Issuer`/`Certificate` resources you have already created. We aim to provide a
stable API after a 1.0 release.

## Quickstart

> Prebuilt images for cert-manager are made available on Dockerhub.

### Pre-requisites

* Kubernetes cluster with `CustomResourceDefinition` or `ThirdPartyResource`
support

### Deploying cert-manager

The easiest way to deploy cert-manager into your cluster is to use the Helm
chart. For information on how to do this see the [Deploying cert-manager using
Helm](docs/user-guides/helm.md) user guide.

### Creating your first Issuer and Certificate

An `Issuer` in cert-manager describes a source of X.509 certificates. A
`Certificate` in cert-manager defines a desired X.509 certificate. Below is a
list of user guides that can be used to get started with both resources:

* [Creating a simple CA based Issuer](docs/user-guides/ca-based-issuer.md)
* [Creating cluster wide Issuers](docs/user-guides/cluster-issuers.md)
* [Issuing an ACME certificate using HTTP
validation](docs/user-guides/acme-http-validation.md)
* [Issuing an ACME certificate using DNS
validation](docs/user-guides/acme-dns-validation.md)

## Further documentation

For further documentation, please check the [/docs](/docs) directory in this
repository.

## Troubleshooting

If you encounter any issues whilst using cert-manager, and your issue is not
documented, please [file an issue](https://github.com/jetstack/cert-manager/issues).

## Contributing

We welcome pull requests with open arms! There's a lot of work to do here, and
we're especially concerned with ensuring the longevity and reliability of the
project.

Please take a look at our [issue tracker](https://github.com/jetstack/cert-manager/issues)
if you are unsure where to start with getting involved!

We also use the #kube-lego channel on kubernetes.slack.com for chat relating to
the project.

Developer documentation should be available soon at [docs/devel](docs/devel).

## Changelog

The [list of releases](https://github.com/jetstack/cert-manager/releases)
is the best place to look for information on changes between releases.
