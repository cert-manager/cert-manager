==================
Setting up Issuers
==================

Before you can begin issuing certificates, you must configure at least one
Issuer or ClusterIssuer resource in your cluster.

These represent a certificate authority from which signed x509 certificates can
be obtained, such as Let's Encrypt, or your own signing key pair stored in a
Kubernetes Secret resource. They are referenced by Certificate resources in
order to request certificates from them.

An :doc:`Issuer </reference/issuers>` is scoped to a single namespace, and can
only fulfill :doc:`Certificate </reference/certificates>` resources within its
own namespace. This is useful in a multi-tenant environment where multiple
teams or independent parties operate within a single cluster.

On the other hand, a :doc:`ClusterIssuer </reference/clusterissuers>` is a
cluster wide version of an :doc:`Issuer </reference/issuers>`. It is able to be
referenced by :doc:`Certificate </reference/certificates>` resources in any
namespace.

Users often create ``letsencrypt-staging`` and ``letsencrypt-prod``
:doc:`ClusterIssuers </reference/clusterissuers>` if they operate a
single-tenant environment and want to expose a cluster-wide mechanism for
obtaining TLS certificates from `Let's Encrypt`_.

Supported issuer types
======================

cert-manager supports a number of different issuer backends, each with their
own different types of configuration.

Please follow one of the below linked guides to learn how to set up the issuer
types you require:

* :doc:`CA <./setup-ca>` - issue certificates signed by a X509 signing keypair,
  stored in a Secret in the Kubernetes API server.
* :doc:`Self signed <./setup-selfsigned>` - issue self signed certificates.
* :doc:`ACME <./setup-acme/index>` - issue certificates obtained by performing
  challenge validations against an ACME server such as `Let's Encrypt`_.
* :doc:`Vault <./setup-vault>`- issue certificates from a Vault instance
  configured with the `Vault PKI backend`_.
* :doc:`Venafi <./setup-venafi>` - issue certificates from a Venafi_ Cloud
  or Trust Protection Platform instance.

Additional information
======================

There are a few key things to know about Issuers, but for full information
you can refer to the :doc:`Issuer reference docs </reference/issuers>`.

.. _issuer_vs_clusterissuer:

Difference between Issuers and ClusterIssuers
---------------------------------------------

ClusterIssuers are a resource type similar to :doc:`Issuers </reference/issuers>`.
They are specified in exactly the same way, but they do not belong to a single
namespace and can be referenced by Certificate resources from multiple different
namespaces.

They are particularly useful when you want to provide the ability to obtain
certificates from a central authority (e.g. Letsencrypt, or your internal CA)
and you run single-tenant clusters.

The resource spec is identical, and you should set the
``certificate.spec.issuerRef.kind`` field to ClusterIssuer when creating your
Certificate resources.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   setup-acme/index
   setup-ca
   setup-selfsigned
   setup-vault
   setup-venafi

.. _`Let's Encrypt`: https://letsencrypt.org
.. _`Vault PKI backend`: https://www.vaultproject.io/docs/secrets/pki/index.html
.. _Venafi: https://venafi.com
