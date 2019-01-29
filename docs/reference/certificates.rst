============
Certificates
============

cert-manager has the concept of 'Certificates' that define a desired X.509
certificate. A Certificate is a namespaced resource that references an
Issuer or ClusterIssuer for information on how to obtain the certificate.

A simple Certificate could be defined as:

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 17-20

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Certificate
   metadata:
     name: acme-crt
   spec:
     secretName: acme-crt-secret
     dnsNames:
     - foo.example.com
     - bar.example.com
     acme:
       config:
       - ingressClass: nginx
         domains:
         - foo.example.com
         - bar.example.com
     issuerRef:
       name: letsencrypt-prod
       # We can reference ClusterIssuers by changing the kind here.
       # The default value is Issuer (i.e. a locally namespaced Issuer)
       kind: Issuer

This Certificate will tell cert-manager to attempt to use the Issuer
named ``letsencrypt-prod`` to obtain a certificate key pair for the
``foo.example.com`` and ``bar.example.com`` domains. If successful, the
resulting key and certificate will be stored in a secret named
``acme-crt-secret`` with keys of ``tls.key`` and ``tls.crt`` respectively.
This secret will live in the same namespace as the ``Certificate`` resource.

The ``dnsNames`` field specifies a list of `Subject Alternative Names`_ to be
associated with the certificate. If the ``commonName`` field is omitted, the
first element in the list will be the common name.

The referenced Issuer must exist in the same namespace as the Certificate.
A Certificate can alternatively reference a ClusterIssuer which is
non-namespaced.

.. _`Subject Alternative Names`: https://en.wikipedia.org/wiki/Subject_Alternative_Name

***************************************
Certificate Duration and Renewal Window
***************************************

cert-manager Certificate resources also support custom validity durations and
renewal windows.

**Important**: The backend service implementation can choose to generate a
certificate with a different validity period than what is requested in the
issuer.

Although the duration and renewal periods are specified on the Certificate
resources, the corresponding Issuer or ClusterIssuer must support this.

The table below shows the support state of the different backend services used
by issuer types:

===========  ============================================================
Issuer       Description
===========  ============================================================
ACME         Only 'renewBefore' supported
CA           Fully supported
Vault        Fully supported (although the requested duration must be lower
             than the configured Vault role's TTL)
Self Signed  Fully supported
===========  ============================================================

The default duration for all certificates is 90 days and the default renewal
windows is 30 days. This means that certificates are considered valid for 3
months and renewal will be attempted within 1 month of expiration.

The *duration* and *renewBefore* parameters must be given in the golang `parseDuration string format <https://golang.org/pkg/time/#ParseDuration>`__.

Example Usage
=============
Here an example of an issuer specifying the duration and renewal window.

The certificate from the previous section is extended with a validity period of
24 hours and to begin trying to renew 12 hours before the certificate
expiration.

 .. code-block:: yaml
   :linenos:
   :emphasize-lines: 7,8

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Certificate
   metadata:
     name: example
   spec:
     secretName: example-tls
     duration: 24h
     renewBefore: 12h
     dnsNames:
     - foo.example.com
     - bar.example.com
     issuerRef:
       name: my-internal-ca
       kind: Issuer
