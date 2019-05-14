=========================
AliDNS
=========================

.. code-block:: yaml
   :emphasize-lines: 10-14

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Issuer
   metadata:
     name: example-issuer
   spec:
     acme:
       ...
       solvers:
       - dns01:
           alidns:
             accessKeyIdSecretRef:
               name: alidns-access-key-secret
               key: accessKeyId
             accessKeySecretSecretRef:
               name: alidns-access-key-secret
               key: accessKeySecret
