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
(kubernetes/ingress#555)[https://github.com/kubernetes/ingress/issues/555]),
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
