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
``foo.example.com`` and ``bar.example.com`` domains. If successful, the resulting
key and certificate will be stored in a secret named ``acme-crt-secret`` with
keys of ``tls.key`` and ``tls.crt`` respectively. This secret will live in the
same namespace as the ``Certificate`` resource. 

The ``dnsNames`` field specifies a list of `Subject Alternative Names`_ to be
associated with the certificate. If the ``commonName`` field is omitted, the
first element in the list will be the common name.

The referenced Issuer must exist in the same namespace as the Certificate. A
Certificate can alternatively reference a ClusterIssuer which is non-namespaced.

.. _`Subject Alternative Names`: https://en.wikipedia.org/wiki/Subject_Alternative_Name

.. toctree::
   :maxdepth: 1
   :hidden:

   certificates/issuer-specific-config/acme