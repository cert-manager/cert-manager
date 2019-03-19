===============================
Setting up self signing Issuers
===============================

.. toctree::
   :maxdepth: 1

Self signed Issuers will issue self signed certificates.

This is useful when building PKI within Kubernetes, or as a means to generate a
root CA for use with the :doc:`CA Issuer <./setup-ca>`.

A self-signed Issuer contains no additional configuration fields, and can be
created with a resource like so:

.. code-block:: yaml

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: ClusterIssuer
   metadata:
     name: selfsigning-issuer
   spec:
     selfSigned: {}

.. note::
   The presence of the ``selfSigned: {}`` line is enough to indicate that this Issuer
   is of type 'self signed'.

Once created, you should be able to issue certificates like usual by
referencing the newly created Issuer in your ``issuerRef``:

.. code-block:: yaml

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Certificate
   metadata:
     name: example-crt
   spec:
     secretName: my-selfsigned-cert
     commonName: "my-selfsigned-root-ca"
     isCA: true
     issuerRef:
       name: selfsigning-issuer
       kind: ClusterIssuer
