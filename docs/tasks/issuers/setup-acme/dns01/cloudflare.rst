=========================
Cloudflare
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
           cloudflare:
             email: my-cloudflare-acc@example.com
             apiKeySecretRef:
               name: cloudflare-api-key-secret
               key: api-key
