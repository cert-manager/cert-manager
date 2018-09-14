===========================
Upgrading from v0.4 to v0.5
===========================

Version 0.5 of cert-manager introduces a new 'webhook' component, which is used
by the Kubernetes apiserver to validate our CRD resource types.

This should help in future to reduce errors caused by misconfigured Certificate
and Issuer resources.

When upgrading from a previous release using Helm, it is **essential** that
you perform one extra step before upgrading.

Disabling resource validation on the cert-manager namespace
===========================================================

Before upgrading, you should add the ``certmanager.k8s.io/disable-validation: "true"``
label to the ``cert-manager`` namespace.

This will allow the system resources that cert-manager requires to bootstrap
TLS to be created in its own namespace.
