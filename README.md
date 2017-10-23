# cert-manager [![Build Status](https://travis-ci.org/jetstack-experimental/cert-manager.svg?branch=master)](https://travis-ci.org/jetstack-experimental/cert-manager)

cert-manager is a Kubernetes addon to automate the management and issuance of
TLS certificates from various issuing sources.

It will ensure certificates are valid and up to date periodically, and attempt
to renew certificates at an appropriate time before expiry.

It is loosely based upon the work of [kube-lego](https://github.com/jetstack/kube-lego)
and has borrowed some wisdom from other similar projects e.g.
[kube-cert-manager](https://github.com/PalmStoneGames/kube-cert-manager).

![cert-manager high level overview diagram](/docs/high-level-overview.png)

## Current status

This project is not yet ready to be a component in a critical production stack,
however is at a point where it offers comparable features to other projects
in the space. If you have a non-critical piece of infrastructure, or are
feeling brave, please do try cert-manager and report your experience here in
the issue section.

**NOTE:** currently we provide no guarantees on our API stability. This means
there may be breaking changes that will require changes to *all* `Issuer`/`Certificate`
resources you have already created. We aim to provide a stable API after a 1.0
release.

## Quickstart

> Prebuilt images for cert-manager are made available on Dockerhub.

This guide sets up cert-manager to run as a Deployment on your Kubernetes cluster. It will then describe the best places to find the information you need to set up an `Issuer` in your cluster and to start provisioning certificates using `Certificate` resources.

### 0. Pre-requisites

* Kubernetes cluster with CustomResourceDefinitions or ThirdPartyResource
support

### 1. Deploy cert-manager using Helm

To deploy the latest version of cert-manager, follow the [Deploying cert-manager using Helm](docs/user-guides/helm.md) user guide.

### 2. Set up an Issuer

An `Issuer` in cert-manager describes a source for signed TLS certificates that cert-manager can use to fulfil `Certificate` resources in a Kubernetes cluster. You can read more about the `Issuer` resource [here][2].

The [user guides](docs/user-guides) cover common ways to configure an `Issuer`.

### 3. Create a Certificate resource

Now we have an `Issuer` configured, we can create a `Certificate` resource that
uses it. A `Certificate` represents the lifecycle of a TLS certificate in your
cluster. When a `Certificate` is created, cert-manager will verify the
certificate is valid for the requested domains and if not, will attempt to
retrieve a signed `Certificate` from the specified `Issuer.`

The [user guides](docs/user-guides) cover common ways to obtain `Certificates` using a configured `Issuer`.

### 4. Ensuring the Certificate request has been fulfiled

cert-manager logs events about `Issuers` and `Certificates` back to the Kubernetes
API in the form of Event resources.

You can check the events produced about a Certificate with `kubectl describe`:

```
$ kubectl describe certificate test-jetstack-net
Events:
  Type     Reason                 Age              From                     Message
  ----     ------                 ----             ----                     -------
  Warning  ErrorCheckCertificate  33s              cert-manager-controller  Error checking existing TLS certificate: secret "example-com" not found
  Normal   PrepareCertificate     33s              cert-manager-controller  Preparing certificate with issuer
  Normal   PresentChallenge       33s              cert-manager-controller  Presenting http-01 challenge for domain example.com
  Normal   PresentChallenge       33s              cert-manager-controller  Presenting http-01 challenge for domain www.example.com
  Normal   PresentChallenge       33s              cert-manager-controller  Presenting dns-01 challenge for domain example2.com
  Normal   SelfCheck              32s              cert-manager-controller  Performing self-check for domain example.com
  Normal   SelfCheck              32s              cert-manager-controller  Performing self-check for domain www.example.com
  Normal   SelfCheck              32s              cert-manager-controller  Performing self-check for domain example2.com
  Normal   ObtainAuthorization    6s               cert-manager-controller  Obtained authorization for domain example.com
  Normal   ObtainAuthorization    6s               cert-manager-controller  Obtained authorization for domain www.example.com
  Normal   ObtainAuthorization    6s               cert-manager-controller  Obtained authorization for domain example2.com
  Normal   IssueCertificate       6s               cert-manager-controller  Issuing certificate...
  Normal   CeritifcateIssued      5s               cert-manager-controller  Certificated issued successfully
```

You can also check whether issuance was successful with `kubectl get secret -o yaml`. You should see a base64 encoded signed TLS key pair.

## Further documentation

For further documentation, please check the [/docs](/docs) directory in this
repository.

## Troubleshooting

If you encounter any issues whilst using cert-manager, and your issue is not
documented, please [file an issue](https://github.com/jetstack-experimental/cert-manager/issues).

## Contributing

We welcome pull requests with open arms! There's a lot of work to do here, and
we're especially concerned with ensuring the longevity and reliability of the
project.

Please take a look at our [issue tracker](https://github.com/jetstack-experimental/cert-manager/issues)
if you are unsure where to start with getting involved!

We also use the #kube-lego channel on kubernetes.slack.com for chat relating
to the project.

Developer documentation should be available soon at [docs/devel](docs/devel).

## Changelog

The [list of releases](https://github.com/jetstack-experimental/cert-manager/releases)
is the best place to look for information on changes between releases.
