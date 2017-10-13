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
there may be breaking changes that will require changes to *all* Issuer/Certificate
resources you have already created. We aim to provide a stable API after a 1.0
release.

## Quickstart

> Prebuilt images for cert-manager are made available on Dockerhub.

This guide sets up cert-manager to run as a Deployment on your Kubernetes
cluster.
It will then go on to set up the [Let's Encrypt ACME staging server](https://letsencrypt.org/docs/staging-environment/)
as a Certificate issuer, and request a Certificate for a domain you control
using both the HTTP01 and DNS01 challenge mechanisms.

By default, it will be configured to fulfil Certificate resources in all
namespaces.

### 0. Pre-requisites

* Kubernetes cluster with CustomResourceDefinitions or ThirdPartyResource
support

### 1. Deploy cert-manager using Helm

To deploy the latest version of cert-manager using Helm, run:

```
$ helm install --name cert-manager --namespace kube-system contrib/charts/cert-manager
```

There are a number of options you can customise when deploying, as detailed in
[the chart itself](https://github.com/jetstack-experimental/cert-manager/tree/master/contrib/charts/cert-manager).

### 2. Set up letsencrypt staging issuer

An Issuer in cert-manager describes a source for signed TLS certificates that
cert-manager can use to fulfil Certificate resources in a Kubernetes cluster.

Within the Issuer's spec, we can define any configuration that may be required
(e.g. credentials for updating a DNS server) on a per-issuer basis.

In the below example, you **must** remember to fill in the `spec.acme.email`
field.

```yaml
apiVersion: certmanager.k8s.io/v1alpha1
kind: Issuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    # The ACME server URL
    server: https://acme-staging.api.letsencrypt.org/directory
    # Email address used for ACME registration
    email: ""
    # Name of a secret used to store the ACME account private key
    privateKeySecretRef:
      name: letsencrypt-staging
    # Enable the HTTP-01 challenge provider
    http01: {}
    # ACME dns-01 provider configurations
    dns01:
      # Here we define a list of DNS-01 providers that can solve DNS challenges
      providers:
      # We define a provider named 'prod-dns', with configuration for the
      # clouddns challenge provider.
      - name: prod-dns
        clouddns:
          # A secretKeyRef to a the google cloud json service account
          serviceAccountSecretRef:
            name: clouddns-service-account
            key: service-account.json
          # The project in which to update the DNS zone
          project: gcloud-prod-project
```

This is an example Issuer for the letsencrypt staging server. Here, we define
one DNS provider, named clouddns, that can be used to solve ACME challenges.

HTTP-01 is also supported without additional configuration when using the ACME
issuer.

Upon creation of the Issuer, any initial preparation for that Issuer will be
performed, e.g. for the ACME issuer, an account is registered with the ACME
server specified in the spec, and a corresponding private key generated too if
required.

Multiple Issuers may exist at any one time, and they should be referenced by
name in a Certificate resource. The Issuer and Certificate resource must exist
in the same namespace, as cert-manager does not allow the traversal of
namespace boundaries.

If you would like to deploy a cluster-wide issuer, you can deploy a
ClusterIssuer. The structure of a ClusterIssuer is identical to that of an
Issuer. You can find more information in the [Issuer api type docs](docs/api-types/issuer).

### 3. Create a Certificate resource

Now we have an Issuer configured, we can create a Certificate resource that
uses it. A Certificate represents the lifecycle of a TLS certificate in your
cluster. When a Certificate is created, cert-manager will verify the
certificate is valid for the requested domains and if not, will attempt to
retrieve a signed Certificate from the specified Issuer.

```yaml
## Example Certificate that uses multiple challenge mechanisms to obtain
## a SAN certificate for multiple domains from the letsencrypt-staging issuer.
apiVersion: certmanager.k8s.io/v1alpha1
kind: Certificate
metadata:
  name: example-com
spec:
  # The name of the Kubernetes secret resource to store the signed TLS keypair
  secretName: example-com
  # The Issuer to use for this certificate
  issuerRef:
    name: letsencrypt-staging
  # A list of domains to include on the TLS certificate
  dnsNames:
  - example.com
  - www.example.com
  - example2.com
  acme:
    # A pairing of domains to challenge types for the ACME provider to use
    # when attempting to validate domain ownership for the listed domains
    config:
    - domains:
      - example.com
      - www.example.com
      http01:
        ingressClass: nginx
    - domains:
      - example2.com
      dns01:
        provider: prod-dns
```

### 4. Ensuring the Certificate request has been fulfiled

cert-manager logs events about Issuers and Certificates back to the Kubernetes
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

You can also check the signed TLS keypair exists with:

```
$ kubectl get secret -o yaml example-com
```

You should see a base64 encoded TLS keypair if issuance was successful.

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

Developer documentation should soon be available at [docs/devel](docs/devel).

## Changelog

The [list of releases](https://github.com/jetstack-experimental/cert-manager/releases)
is the best place to look for information on changes between releases.
