====================
Issuing Certificates
====================

The Certificate resource type is used to request certificates from different
Issuers.

In order to issue any certificates, you'll need to configure an Issuer resource
first.

If you have not configured any issuers yet, you should read the
:doc:`Setting up Issuers <../issuers/index>` guide.

Creating Certificate resources
==============================

A Certificate resource specifies fields that are used to generated certificate
signing requests which are then fulfilled by the issuer type you have
referenced.

Certificates specify which issuer they want to obtain the certificate from by
specifying the ``certificate.spec.issuerRef`` field.

A basic Certificate resource, for the ``example.com`` and ``www.example.com``
DNS names that is valid for 90d and renews 15d before expiry is below:

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 9, 10, 11, 12

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Certificate
   metadata:
     name: example-com
     namespace: default
   spec:
     secretName: example-com-tls
     duration: 2160h # 90d
     renewBefore: 360h # 15d
     commonName: example.com
     dnsNames:
     - example.com
     - www.example.com
     issuerRef:
       name: ca-issuer
       # We can reference ClusterIssuers by changing the kind here.
       # The default value is Issuer (i.e. a locally namespaced Issuer)
       kind: Issuer

The signed certificate will be stored in a Secret resource named
``example-com-tls`` once the issuer has successfully issued the requested
certificate.

The Certificate will be issued using the issuer named ``ca-issuer`` in the
``default`` namespace (the same namespace as the Certificate resource).

.. note::
   If you want to create an Issuer that can be referenced by Certificate
   resources in **all** namespaces, you should create a
   :doc:`ClusterIssuer </reference/clusterissuers>` resource and set the
   ``certificate.spec.issuerRef.kind`` field to ``ClusterIssuer``.

.. note::
   The ``renewBefore`` and ``duration`` fields must be specified using Golang's
   ``time.Time`` string format, which does not allow the ``d`` (days) suffix.
   You must specify these values using ``s``, ``m`` and ``h`` suffixes instead.
   Failing to do so without installing the
   :doc:`webhook </getting-started/webhook>` component can prevent cert-manager
   from functioning correctly (`#1269`_).

A full list of the fields supported on the Certificate resource can be found in
the `API reference documentation`_.

.. _`#1269`: https://github.com/jetstack/cert-manager/issues/1269
.. _`API reference documentation`: https://cert-manager.readthedocs.io/en/release-0.6/reference/api-docs/index.html#certificatespec-v1alpha1

Special fields on Certificate resources for ACME Issuers
========================================================

When creating Certificate resources that reference ACME Issuers, you must
set an additional ``certificate.spec.acme`` stanza on the resource to configure
what challenge mechanism to use for each DNS name specified on the certificate.

More information on setting these fields can be found in the
:doc:`../acme/issuing-certificates` guide.

.. toctree::
   :maxdepth: 2

   ingress-shim
