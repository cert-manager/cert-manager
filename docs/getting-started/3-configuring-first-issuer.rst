=================================================
3. Configuring your first Issuer or ClusterIssuer
=================================================

Before you can issue any Certificates, you will need to configure an :doc:`Issuer </reference/issuers>`
or :doc:`ClusterIssuer </reference/clusterissuers>` resource.

These represent a certificate authority from which signed x509 certificates can
be obtained, such as Let's Encrypt, or your own signing key pair stored in a
Kubernetes Secret resource.

An :doc:`Issuer </reference/issuers>` is scoped to a single namespace, and can
only fulfill :doc:`Certificate </reference/certificates>` resources within its
own namespace. This is useful in a multi-tenant environment where multiple
teams or independent parties operate within a single cluster.

On the other hand, a :doc:`ClusterIssuer </reference/clusterissuers>` is a
cluster wide version of an :doc:`Issuer </reference/issuers>`. It is able to be
referenced by :doc:`Certificate </reference/certificates>` resources in any
namespace. Users often create ``letsencrypt-staging`` and ``letsencrypt-prod``
:doc:`ClusterIssuers </reference/clusterissuers>` if they operate a
single-tenant environment and want to expose a cluster-wide mechanism for
obtaining TLS certificates from `Let's Encrypt`_.

.. _`Let's Encrypt`: https://letsencrypt.org
