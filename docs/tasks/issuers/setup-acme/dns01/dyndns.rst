=========================
DynDNS
=========================

.. code-block:: yaml
   :emphasize-lines: 10-14

   apiVersion: cert-manager.io/v1alpha2
   kind: Issuer
   metadata:
     name: example-issuer
   spec:
     acme:
       ...
       solvers:
       - dns01:
           dyndns:
             username: your-username
             passwordSecretRef:
               name: dyndns-api-password-secret
               key: password
             customerName: your-customerName
             zonename: your-zonename
