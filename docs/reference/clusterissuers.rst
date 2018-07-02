==============
ClusterIssuers
==============

ClusterIssuers are a resource type similar to :doc:`Issuers </reference/issuers>`.
They are specified in exactly the same way, but they do not belong to a single
namespace and can be referenced by Certificate resources from multiple different
namespaces.

They are particularly useful when you want to provide the ability to obtain
certificates from a central authority (e.g. Letsencrypt, or your internal CA)
and you run single-tenant clusters.

The docs for Issuer resources apply equally to ClusterIssuers.

You can specify a ClusterIssuer resource by changing the ``kind`` attribute of
an Issuer to ``ClusterIssuer``, and removing the ``metadata.namespace`` attribute:

.. code-block:: yaml
   :emphasize-lines: 2

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: ClusterIssuer
   metadata:
     name: letsencrypt-prod
   spec:
   ...

We can then reference a ClusterIssuer from a Certificate resource by setting
the ``spec.issuerRef.kind`` field to ClusterIssuer:

.. code-block:: yaml
   :emphasize-lines: 10

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Certificate
   metadata:
     name: my-certificate
     namespace: my-namespace
   spec:
     secretName: my-certificate-secret
     issuerRef:
       name: letsencrypt-prod
       kind: ClusterIssuer
     ...

When referencing a ``Secret`` resource in ``ClusterIssuer`` resources (eg ``apiKeySecretRef``) the ``Secret`` needs to be in the same namespace as the ``cert-manager`` controller pod. You can optionally override this by using the ``--cluster-resource-namespace`` argument to the controller.

For more information on configuring Issuer resources, see the :doc:`Issuers </reference/issuers>`
reference documentation.
