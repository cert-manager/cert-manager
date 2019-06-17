=======================
Setting up ACME Issuers
=======================

The ACME Issuer type represents a single Account registered with the ACME
server.

When you create a new ACME Issuer, cert-manager will generate a private key
which is used to identify you with the ACME server.

To set up a basic ACME issuer, you should create a new Issuer or ClusterIssuer
resource.

You should read the guides linked at the bottom of this page to learn more
about the ACME challenge validation mechanisms that cert-manager supports and
how to configure the various DNS01 provider implementations.

Creating a basic ACME Issuer
============================

The below example configures a ClusterIssuer named ``letsencrypt-staging`` that
is configured to HTTP01 challenge solving with configuration suitable for
ingress controllers such as ingress-nginx_.

You should copy and paste this example into a new file named
``letsencrypt-staging.yaml`` and update the ``spec.acme.email`` field to be your
own email address.

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 7-10, 13-14, 19

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
       # Add a single challenge solver, HTTP01 using nginx
       solvers:
       - http01:
           ingress:
             class: nginx

You can then create this resource using ``kubectl apply``:

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

Any Certificate you create that references this Issuer resource will use the
HTTP01 challenge solver you have configured above.

.. note::
   Let's Encrypt does not support issuing wildcard certificates with HTTP-01 challenges.
   To issue wildcard certificates, you must use the DNS-01 challenge.

.. _multiple-solver-types:

Adding multiple solver types
============================

You may want to use different types of challenge solver configuration for
different ingress controllers, for example if you want to issue wildcard
certificates using DNS01 alongside other certificates that are validated using
HTTP01.

The ``solvers`` stanza has an optional ``selector`` field, that can be used to
specify which Certificates, and further, what DNS names **on those certificates**
should be used to solve challenges.

For example, to configure HTTP01 using nginx ingress as the default solver,
along with a DNS01 solver that can be used for wildcard certificates:

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 14-15

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: ClusterIssuer
   metadata:
     name: letsencrypt-staging
   spec:
     acme:
       ...
       solvers:
       - http01:
           ingress:
             class: nginx
       - selector:
           matchLabels:
             use-cloudflare-solver: "true"
         dns01:
           cloudflare:
             email: user@example.com
             apiKeySecretRef:
               name: cloudflare-apikey-secret
               key: apikey

In order to utilise the configured cloudflare DNS01 solver, you must add the
``use-cloudflare-solver: "true"`` label to your Certificate resources.

Using multiple solvers for a single certificate
-----------------------------------------------

The solver's ``selector`` stanza has an additional field ``dnsNames`` that
further refines the set of domains that the solver configuration applies to.

If any ``dnsNames`` are specified, then that challenge solver will be used if
the domain being validated is named in that list.

For example:

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 14-15

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: ClusterIssuer
   metadata:
     name: letsencrypt-staging
   spec:
     acme:
       ...
       solvers:
       - http01:
           ingress:
             class: nginx
       - selector:
           dnsNames:
           - '*.example.com'
         dns01:
           cloudflare:
             email: user@example.com
             apiKeySecretRef:
               name: cloudflare-apikey-secret
               key: apikey

In this instance, a Certificate that specified both ``*.example.com`` and
``example.com`` would use the HTTP01 challenge solver for ``example.com`` and
the DNS01 challenge solver for ``*.example.com``.

It is possible to specify both ``matchLabels`` AND ``dnsNames`` on an ACME
solver selector.

.. toctree::
   :maxdepth: 2
   :caption: Contents:

   http01/index
   dns01/index

.. _`Let's Encrypt staging endpoint`: https://letsencrypt.org/docs/staging-environment/
