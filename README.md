# cert-manager [![Build Status](https://travis-ci.org/jetstack-experimental/cert-manager.svg?branch=master)](https://travis-ci.org/jetstack-experimental/cert-manager)

cert-manager is a Kubernetes addon to automate the management and issuance of
TLS certificates from various issuing sources.

It will ensure certificates are valid and up to date periodically, and attempt
to renew certificates at an appropriate time before expiry.

It is loosely based upon the work of [kube-lego](https://github.com/jetstack/kube-lego)
and has borrowed some wisdom from other similar projects e.g.
[kube-cert-manager](https://github.com/PalmStoneGames/kube-cert-manager).

## Current status

This project is still heavily under development and is not ready for use
**yet**. However, if you want to experiment, please do try running the current
development build and reporting any issues you run into.

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

* Kubernetes cluster with CustomResourceDefinitions enabled (1.7+) (see [#49](https://github.com/jetstack-experimental/cert-manager/issues/49))

### 1. Deploy cert-manager

To deploy the latest version of cert-manager, run:

```
$ kubectl create -f https://raw.githubusercontent.com/jetstack-experimental/cert-manager/master/docs/cert-manager.yaml
```

**NOTE**

* In future this may be replaced with a Helm chart.
* There are currently no official RBAC roles defined for cert-manager (see [#34](https://github.com/jetstack-experimental/cert-manager/issues/34))

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
    privateKey: letsencrypt-staging
    # ACME dns-01 provider configurations
    dns-01:
      # Here we define a list of DNS-01 providers that can solve DNS challenges
      providers:
      # We define a provider named 'prod-dns', with configuration for the
      # clouddns challenge provider.
      - name: prod-dns
        clouddns:
          # A secretKeyRef to a the google cloud json service account
          serviceAccount:
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
  issuer: letsencrypt-staging
  # A list of domains to include on the TLS certificate
  domains:
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
      http-01:
        ingressClass: nginx
    - domains:
      - example2.com
      dns-01:
        provider: prod-dns
```

### 4. Ensuring the Certificate request has been fulfiled

> Currently, cert-manager does not log Events on Certificates or Issuers to the
Kubernetes Events API (see [#54](https://github.com/jetstack-experimental/cert-manager/issues/54)).

Until then, we can view the logs of cert-manager with the following:

```
$ kubectl logs -l app=cert-manager
2017/08/29 12:54:37 Preparing Certificate 'default/test-jetstack-net'
2017/08/29 12:54:37 getting private key for acme issuer default/letsencrypt-staging
2017/08/29 12:54:37 need to get authorizations for [test.jetstack.net]
2017/08/29 12:54:37 requested authorizations for [test.jetstack.net]
2017/08/29 12:54:37 picking challenge type for domain 'test.jetstack.net'
2017/08/29 12:54:37 using challenge type http-01 for domain 'test.jetstack.net'
2017/08/29 12:54:37 presenting challenge for domain test.jetstack.net, token FdVsxK2U1NRqTpEtFux29xy-0SVkcHc2qbguttdZLy8 key FdVsxK2U1NRqTpEtFux29xy-0SVkqHc2qbguttdZLy8.HwRbVJxMBmV9fJ9UxUtbN5tvjnEeCTtHnH5G9JLSYhc
2017/08/29 12:54:38 waiting for key to be available to acme servers for domain test.jetstack.net
2017/08/29 12:54:38 [test.jetstack.net] Error self checking HTTP01 challenge: wrong status code '503'
2017/08/29 12:54:44 [test.jetstack.net] Error self checking HTTP01 challenge: wrong status code '503'
2017/08/29 12:54:49 [test.jetstack.net] Error self checking HTTP01 challenge: wrong status code '503'
2017/08/29 12:54:54 [test.jetstack.net] Error self checking HTTP01 challenge: wrong status code '503'
2017/08/29 12:54:59 [test.jetstack.net] Error self checking HTTP01 challenge: wrong status code '503'
2017/08/29 12:55:04 [test.jetstack.net] Error self checking HTTP01 challenge: wrong status code '503'
2017/08/29 12:55:09 [test.jetstack.net] HTTP01 challenge self checking passed
2017/08/29 12:55:09 accepting http-01 challenge for domain test.jetstack.net
2017/08/29 12:55:09 waiting for authorization for domain test.jetstack.net (https://acme-staging.api.letsencrypt.org/acme/challenge/MEFHD2piP1SpkG3tMcE9CRldMO-pS7OqzeJs6AK7AiE/1704174337)...
2017/08/29 12:55:09 got successful authorization for domain test.jetstack.net
2017/08/29 12:55:09 Finished preparing Certificate 'default/test-jetstack-net'
2017/08/29 12:55:09 [default/test-jetstack-net] Issuing certificate...
2017/08/29 12:55:15 successfully got certificate: domains=[test.jetstack.net] url=https://acme-staging.api.letsencrypt.org/acme/cert/03ed2ed8bac6c402a04ef8d9e83a536ad823
2017/08/29 12:55:15 [default/test-jetstack-net] Successfully issued certificate (test-jetstack-net)
2017/08/29 12:55:15 [default/test-jetstack-net] Scheduling renewal in 1438 hours
2017/08/29 12:55:15 finished processing work item
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
