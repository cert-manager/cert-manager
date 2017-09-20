# Issuers

cert-manager has the concept of 'Issuers' that define a source of X.509
certificates, including any configuration required for that source.

An example of an Issuer is ACME. A simple ACME issuer could be defined as:

```yaml
kind: Issuer
metadata:
  name: letsencrypt-prod
  namespace: edge-services
spec:
  acme:
    # The ACME server URL
    server: https://acme-v01.api.letsencrypt.org/directory
    # Email address used for ACME registration
    email: user@example.com
    # Name of a secret used to store the ACME account private key
    privateKey: letsncrypt-prod
```

This is the simplest of ACME issuers - it specifies no DNS-01 challenge
providers. HTTP-01 validation can be performed through using Ingress
resources without any additional configuration on the Issuer resource.

## Namespacing

An Issuer is a namespaced resource, and it is not possible to issue
certificates from an Issuer in a different namespace. This means you will need
to create an Issuer in each namespace you wish to obtain Certificates in.

If you want to create a single issuer than can be consumed in multiple
namespaces, you should consider creating a `ClusterIssuer` resource. This is
almost identical to the `Issuer` resource, however is non-namespaced and so can
be great at the cluster level.

## Supported issuer types

cert-manager has been designed to support pluggable Issuer backends. Below is
a list of the currently supported issuers and a link to the spec for their
definition.

* [ACME](spec.md#acme-configuration)
* [CA](spec.md#ca-configuration)

This list will be kept up to date as new issuers are added.
