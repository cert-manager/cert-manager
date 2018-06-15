=======
Issuers
=======

Issuers (and :doc:`ClusterIssuers </reference/clusterissuers>`) represent a
certificate authority from which signed x509 certificates can be obtained, such
as `Let's Encrypt`_. You will need at least one Issuer or ClusterIssuer in
order to begin issuing certificates within your cluster.

An example of an Issuer type is ACME. A simple ACME issuer could be defined as:

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 11, 16

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Issuer
   metadata:
     name: letsencrypt-prod
     namespace: edge-services
   spec:
     acme:
       # The ACME server URL
       server: https://acme-v02.api.letsencrypt.org/directory
       # Email address used for ACME registration
       email: user@example.com
       # Name of a secret used to store the ACME account private key
       privateKeySecretRef:
         name: letsencrypt-prod
       # Enable HTTP01 validations
       http01: {}


This is the simplest of ACME issuers - it specifies no DNS-01 challenge
providers. HTTP-01 validation can be performed through using Ingress
resources by enabling the HTTP-01 challenge mechanism (with the ``http01: {}``
field). More information on configuring ACME Issuers can be in later sections
of this document.

***********
Namespacing
***********

An Issuer is a namespaced resource, and it is not possible to issue
certificates from an Issuer in a different namespace. This means you will need
to create an Issuer in each namespace you wish to obtain Certificates in.

If you want to create a single issuer than can be consumed in multiple
namespaces, you should consider creating a :doc:`ClusterIssuer <clusterissuers>`
resource. This is almost identical to the Issuer resource, however is
non-namespaced and so it can be used to issue Certificates across all namespaces.

***************************************
Certificate Duration and Renewal Window
***************************************

Cert-manager's issuers and clusterissuers support custom certificate duration
and renewal window.

**Important**: The backend service implementation can choose to generate a
certificate with a different validity period than what is requested in the
issuer.

The table below shows the support state of the different backend services used
by issuer types:

=======  ============================================================
Issuer   Description
=======  ============================================================
ACME     The protocol supports it but it is currently not supported
         in Boulder (Let's Encrypt).
CA       Fully supported.
Vault    Fully supported. (Although the requested duration must be
         lower than the configured Vault role's TTL)
=======  ============================================================

The table below shows the default duration and renewal window per
issuer:

======  =========================  =========================
Issuer  Duration                   RenewBefore
======  =========================  =========================
ACME    Implementation dependent   30 days
        (Let's Encrypt - 90 days)
CA      90 days                    30 days
Vault   90 days                    30 days
======  =========================  =========================

The *duration* and *renewBefore* parameters must be given in the golang
`parseDuration string format <https://golang.org/pkg/time/#ParseDuration>`__.

Example Usage
=============

Here an example of an issuer specifying the duration and renewal window.
The issuer will negotiate a certificate validity period of 24 hours and begin
trying to renew the certificate 12 hours before the certificate expiration.

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 6,7

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: ClusterIssuer
   metadata:
     name: letsencrypt-prod
   spec:
     duration: 24h
     renewBefore: 12h
     acme:
       server: https://acme-v02.api.letsencrypt.org/directory
       email: user@example.com
       privateKeySecretRef:
         name: letsencrypt-prod
       http01: {}


*******************
Ambient Credentials
*******************

Some API clients are able to infer credentials to use from the environment they
run within. Notably, this includes cloud instance-metadata stores and
environment variables.
In cert-manager, the term 'ambient credentials' refers to such credentials.
They are always drawn from the environment of the 'cert-manager-controller'
deployment.

Example Usage
=============

If cert-manager is deployed in an environment with ambient AWS credentials,
such as with a kube2iam_ role, the following ClusterIssuer would make use of
those credentials to perform the ACME DNS01 challenge with route53.

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 14-15

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: ClusterIssuer
   metadata:
     name: letsencrypt-prod
   spec:
     acme:
       server: https://acme-v02.api.letsencrypt.org/directory
       email: user@example.com
       privateKeySecretRef:
         name: letsencrypt-prod
       dns01:
         providers:
         - name: route53
           route53:
             region: us-east-1

It is important to note that the ``route53`` section does not specify any
``accessKeyID`` or ``secretAccessKeySecretRef``. If either of these are
specified, ambient credentials will not be used.

When are Ambient Credentials used
=================================

Ambient credentials are supported for the 'route53' ACME DNS01 challenge
provider.

They will only be used if no credentials are supplied, even if the supplied
credentials are invalid.

By default, ambient credentials may be used by ClusterIssuers, but not regular
issuers. The ``--issuer-ambient-credentials`` and
``--cluster-issuer-ambient-credentials=false`` flags on cert-manager may be
used to override this behavior.

Note that ambient credentials are disabled for regular Issuers by default to
ensure unprivileged users who may create issuers cannot issue certificates
using any credentials cert-manager incidentally has access to.

**********************
Supported Issuer types
**********************

cert-manager has been designed to support pluggable Issuer backends. The
currently supported Issuer types are:

+-----------------------------------------------+----------------------------------------------------------------------+
| Name                                          | Description                                                          |
+===============================================+======================================================================+
| :doc:`ACME <issuers/acme/index>`              | Supports obtaining certificates from an ACME server, validating with |
|                                               | HTTP01 or DNS01                                                      |
+-----------------------------------------------+----------------------------------------------------------------------+
| :doc:`CA <issuers/ca/index>`                  | Supports issuing certificates using a simple signing keypair, stored |
|                                               | in a Secret in the Kubernetes API server                             |
+-----------------------------------------------+----------------------------------------------------------------------+
| :doc:`Vault <issuers/vault/index>`            | Supports issuing certificates using HashiCorp Vault.                 |
+-----------------------------------------------+----------------------------------------------------------------------+
| :doc:`Self signed <issuers/selfsigned/index>` | Supports issuing self signed certificates                            |
+-----------------------------------------------+----------------------------------------------------------------------+


Each Issuer resource is of one, and only one type. The type of an Issuer is
inferred by which field it specifies in its spec, such as ``spec.acme``
for the ACME issuer, or ``spec.ca`` for the CA based issuer.

.. toctree::

   issuers/acme/index
   issuers/ca/index
   issuers/vault/index

.. _`Let's Encrypt`: https://letsencrypt.org
.. _kube2iam: https://github.com/jtblin/kube2iam
