=======================
Setting up ACME Issuers
=======================

The ACME Issuer type represents a single Account registered with the ACME
server.

When you create a new ACME Issuer, cert-manager will generate a private key
which is used to identify you with the ACME server.

To set up a basic ACME issuer, you should create a new Issuer or ClusterIssuer
resource.

In this example, we will create a non-namespaced ClusterIssuer resource for
the `Let's Encrypt staging endpoint`_ that has only the
:doc:`HTTP01 Challenge Provider </tasks/acme/configuring-http01>` enabled.

You should read the guides linked at the bottom of this page to learn more
about the ACME challenge validation mechanisms that cert-manager supports and
how to configure the various DNS01 provider implementations.

Creating a basic ACME Issuer
============================

The below example configures a ClusterIssuer named ``letsencrypt-staging`` that
is configured to enable the HTTP01 challenge validation mechanism **only**.

You should copy and paste this example into a new file named
``letsencrypt-staging.yaml`` and update the ``spec.acme.email`` field to be your
own email address.

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 7-10, 13-14, 15-16

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: ClusterIssuer
   metadata:
     name: letsencrypt-staging
   spec:
     acme:
       # You must replace this email address with your own.
       # Let's Encrypt will use this to contact you about expiring
       # certificates, and issues related to your account.
       email: user@example.com
       server: https://acme-staging-v02.api.letsencrypt.org/directory
       privateKeySecretRef:
         # Secret resource used to store the account's private key.
         name: example-issuer-account-key
       # Enable the HTTP01 challenge mechanism for this Issuer
       http01: {}

You can then create this resource:

.. code-block:: shell

   kubectl apply -f letsencrypt-staging.yaml

To verify that the account has been registered successfully, you can run
``kubectl describe`` and check the 'Ready' condition:

.. code-block:: shell

   kubectl describe clusterissuer letsencrypt-staging
   ...
   Status:
     Acme:
       Uri:  https://acme-staging-v02.api.letsencrypt.org/acme/acct/7571319
     Conditions:
       Last Transition Time:  2019-01-30T14:52:03Z
       Message:               The ACME account was registered with the ACME server
       Reason:                ACMEAccountRegistered
       Status:                True
       Type:                  Ready

Notes on issuing ACME certificates
----------------------------------

Currently, there is some additional configuration needed on Certificate
resources when issuing certificates from ACME issuers.

You should read the
:doc:`Issuing Certificates using ACME </tasks/acme/issuing-certificates>`
documentation for more information on how to configure these additional fields.

Advanced HTTP01 configuration
=============================

There are a few additional options that can be set on the Issuer resource to
alter the behaviour of the HTTP01 solver.

For full details, read the
:doc:`HTTP01 Challenge Provider </tasks/acme/configuring-http01>` documentation
to learn about these options.

Configuring DNS01 providers
===========================

It is also possible to validate domain ownership using DNS01 validation.

In order to do this, your Issuer resource must be configured with credentials
for a supported DNS provider's account.

The full list of support DNS providers, and information on how to configure
them can be found in the
:doc:`DNS01 Challenge Provider </tasks/acme/configuring-dns01/index>`
documentation.

.. _`Let's Encrypt staging endpoint`: https://letsencrypt.org/docs/staging-environment/
.. _`HTTP01 challenge type`:
