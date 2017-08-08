# cert-manager proposal

## Problem

Currently in Kubernetes, a number of different components including user
applications require TLS certificates. Right now, users can provide
certificates to workloads on the cluster by creating `Secret` resources that
contain a private/public keypair.

A number of projects (see: [kube-lego](https://github.com/jetstack/kube-lego),
[kube-cert-manager](https://github.com/PalmStoneGames/kube-cert-manager)
and [kubernetes-letsencrypt](https://github.com/tazjin/kubernetes-letsencrypt))
came about in order to automate the retrieval of certificates from an [ACME](https://github.com/ietf-wg-acme/acme/)
compliant server. This has served the community well, especially with the rise
in popularity of ACME due to [letsencrypt](https://letsencrypt.org). These
projects also attempt to renew the certificate as it reaches it's expiry time.

Whilst each project has invented it's own schema/methodology for obtaining
these certificates, the end goal has largely been the same. To provide a signed
keypair in a Secret resource to then be consumed, either by an Ingress
controller or some other workload in-cluster, and then keep that keypair up to
date.

Looking beyond the capabilities of all of these projects, it'd also be
beneficial for users to be able to utilise alternative issuer backends, other
than ACME. This could include [Hashicorp Vault](https://vaultproject.io), a
plain CA (backed by Kubernetes secret resources), or any other cloud based
service.

It is therefore proposed that a new project, `cert-manager`, is created that
aims to generalise the issuance and renewal of certificates from an arbitrary
certificate source. This project should be designed in a similar manner to
other Kubernetes controllers (eg. kube-controller-manager, service-catalog et
al.).

## Definitions

* `Issuer` - an Issuer is a generic backend that issues certificates. cert-manager
will contain logic on how to process each issuer, and multiple Issuer resources
utilising the same issuer implementation may exist (e.g. to allow issuing
certificates from both letsencrypt production & staging). An example manifest for
an Issuer resource:

```yaml
kind: Issuer
metadata:
  name: letsencrypt-staging
spec:
  acme:
    # The ACME server URL
    server: https://acme-staging.api.letsencrypt.org/directory
    # Email address used for ACME registration
    email: user@example.com
    # Name of a secret used to store the ACME account private key
    privateKey: letsncrypt-staging
    # ACME dns-01 provider configurations
    dns-01:
      # Here we define a list of DNS-01 providers that can solve DNS challenges
      providers:
      # We define a provider named 'clouddns', with configuration for the
      # clouddns challenge provider.
      - name: clouddns
        clouddns:
          # A secretKeyRef to a the google cloud json service account
          serviceAccount:
            name: clouddns-service-account
            key: service-account.json
          # The project in which to update the DNS zone
          project: gcloud-project
      # We define a provider named 'cloudflare', with configuration for the
      # cloudflare challenge provider.
      - name: cloudflare
        cloudflare:
          # A secretKeyRef to a the cloudflare api key
          apiKey:
            name: cloudflare-config
            key: api-key
          # The cloudflare user account email
          email: cloudflare-user@example.com
```

* `Certificate` - a Certificate resource details a Certificate keypair to
manage with cert-manager. It contains details such as the hostnames to be listed
on the certificate, as well as details of which issuer to issuer certificates with,
and any additional configuration required for the selected issuer. An example
manifest for a Certificate resource:

```yaml
## Example Certificate that uses multiple challenge mechanisms to obtain
## a SAN certificate for multiple domains from the letsencrypt-staging issuer.
apiVersion: certmanager.k8s.io/v1alpha1
kind: Certificate
metadata:
  name: cm-http-nginx-k8s-group
spec:
  secretName: cm-http-nginx-k8s-group
  issuer: letsencrypt-staging
  domains:
  - cm-http-nginx.k8s.group
  - cm-http-nginx2.k8s.group
  - cm-http-gce.k8s.group
  - cm-http-clouddns.k8s.group
  - cm-http-cloudflare.k8s.group
  acme:
    config:
    - http-01:
        ingressClass: nginx
      domains:
      - cm-http-nginx.k8s.group
      - cm-http-nginx2.k8s.group
    - http-01:
        ingressName: my-gce-ingress
      domains:
      - cm-http-gce.k8s.group
    - dns-01:
        provider: clouddns
      domains:
      - cm-dns-clouddns.k8s.group
    - dns-01:
        provider: cloudflare
      domains:
      - cm-dns-cloudflare.k8s.group
```

These example manifests do not describe a finalised API, but instead aim to
help communicate the concept of Issuer vs Certificate.

## Goals

* Provide a non-opinionated interface for new issuers to be added to
cert-manager

* Provide reliable support for at least ACME HTTP01 and DNS01 challenge types
in the ACME provider. TLS-SNI-02 support is not a goal listed here due to
potential difficulties in implementation with the current Ingress controller
specification. In future, TLS-SNI-02 support for ACME may be considered.

* Provide clear, understable Events/log messages to users to inform them that
issuance/renewal of a certificate has failed. Also provide metrics endpoints
that can be scrapped by metrics collection software (such as Prometheus).

* Attempt to obtain certificates from the specified issuing backend, and then
keep those certificates up to date by renewing them as they near expiry.

* Provide a relatively easy upgrade path for existing users of kube-lego and
kube-cert-manager. Whilst we won't have 1:1 compatility, the concepts should
be relatively similar/transfer across well.

## Non-goals

* We specifically do not want to tie ourselves to Ingress resources, as
previous projects in this space have done. With the out-of-tree nature of
Ingress, and with some areas having loose specification (ie.
[kubernetes/ingress#555](https://github.com/kubernetes/ingress/issues/555),
it's desired that we don't specifically list a set of 'supported' Ingress
controllers. This particularly limitation specifically applies to the ACME
challenge provider at this point.

* Tying ourselves to any specific issuer implementation. Whilst previous work
has focused heavily on ACME, we do not want to be in any way tied to this
provider. Additional issuers such as [Hashicorp Vault](https://vaultproject.io)
are planned in future.

## Roadmap

### Short term

* Stabilise application to bring it to a comparable state to kube-lego and
kube-cert-manager.

* Implement a fairly robust test suite so we can confidently move forwards.

* Creating our own Controller and resource types, namely 'Issuer' and
'Certificate'.

* Writing up retrospective design proposals for what we have already.

* Filling out documentation and creating tutorials to make the project
user-friendly from day one. Tutorials should be clear and cover common
user stories.

### Medium term

* Implement a metrics endpoint to expose useful information such as number
of certificates issued, number of attempts per certificate, etc.

* Implement API server that registers with aggregator, or utilise new
validation APIs in future Kubernetes versions.

### Longer term

* Implementing additional certificate issuers (eg. Vault, Amazon?).

* Investigate how this can inter-play with the Kubernetes Certificates API.
