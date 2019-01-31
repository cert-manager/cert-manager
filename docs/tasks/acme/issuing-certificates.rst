===============================
Issuing Certificates using ACME
===============================

ACME certificates currently require additional configuration on the Certificate
resource that you create in order to determine how to solve the
`ACME challenges`_ that the ACME protocol requires.

In future releases of cert-manager, this configuration is likely to move off of
the Certificate resource and onto the Issuer resource in order to create a
better separation of concerns. More info can be found on issue `#XXX`_.

.. _`ACME challenges`:
.. _`#XXX`:

Configuring Certificates for ACME issuance
==========================================

In order to issue certificates using the ACME issuer type, you must configure
which ACME challenge provider is used for each domain name you are requesting
a Certificate for.

This is done by configuring a mapping between domain names and the solver types
that have been configured on the corresponding Issuer resource.

Using HTTP01 challenges
-----------------------

In order to use the HTTP01 challenge provider, you must first configure your
Issuer with the appropriate settings described in the :doc:`configuring-http01`
documentation.

Assuming you've created the same example ACME Issuer with http01 enabled as in
the :doc:`../issuers/setup-acme` guide:

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 7-10, 15-16

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

We must configure our Certificate resource with the 'ingress class' that will
be used to solve the ACME HTTP01 challenges:

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 14-20

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Certificate
   metadata:
     name: example-com
     namespace: default
   spec:
     secretName: example-com-tls
     issuerRef:
       name: letsencrypt-staging
     commonName: example.com
     dnsNames:
     - example.com
     - www.example.com
     acme:
       config:
       - http01:
           ingressClass: nginx
         domains:
         - example.com
         - www.example.com

.. note::
   If you use 'ingress-gce', aka the GCLB ingress controller, you will need to
   modify your Certificate definition to specify the
   ``certificate.spec.acme.config.http01.ingress`` field instead of
   ``ingressClass``, like so::

     ...
      acme:
       config:
       - http01:
           ingress: name-of-gce-ingress-resource
         domains:
         - example.com
         - www.example.com

Using DNS01 challenges
-----------------------

In order to use DNS01 validation, you must first configure your Issuer resource
with credentials and connection information needed to access your DNS
provider's administrative console.

You can find more information on the different supported DNS providers and how
to configure them in the :doc:`./configuring-dns01/index` documentation.

The example Issuer on the :doc:`./configuring-dns01/index` page is configured
with credentials for a Google Cloud DNS account:

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 7, 13-18

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: ClusterIssuer
   metadata:
     name: letsencrypt-staging
   spec:
     acme:
       email: user@example.com
       server: https://acme-staging-v02.api.letsencrypt.org/directory
       privateKeySecretRef:
         name: example-issuer-account-key
       dns01:
         providers:
         - name: prod-clouddns
           clouddns:
             project: my-project
             serviceAccountSecretRef:
               name: prod-clouddns-svc-acct-secret
               key: service-account.json

In the above example on line 13, you can see we have named this DNS provider
``prod-clouddns``.

When creating Certificates that intend to utilise this DNS01 provider for
validations, we must remember to include this "provider name" in our
Certificate's spec:

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 17

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Certificate
   metadata:
     name: example-com
     namespace: default
   spec:
     secretName: example-com-tls
     issuerRef:
       name: letsencrypt-staging
     commonName: example.com
     dnsNames:
     - example.com
     - www.example.com
     acme:
       config:
       - dns01:
           provider: prod-clouddns
         domains:
         - example.com
         - www.example.com

If you do not specify a provider name, cert-manager will not know how to solve
challenges for your domains and the issuance process **will not succeed**.
