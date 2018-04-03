=========================
HTTP01 Challenge Provider
=========================

In order to allow HTTP01 challenges to be solved, we must enable the HTTP01
challenge provider on our Issuer resource. This can be done through setting the
``http01`` field on the ``issuer.spec.acme`` stanza. Cert-manager will then
create and manage Ingress rules in the Kubernetes API server in order to solve
HTTP-01 based challenges.

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 7, 11

   apiVersion: certmanager.k8s.io
   kind: Issuer
   metadata:
     name: example-issuer
   spec:
     acme:
       email: user@example.com
       server: https://acme-staging.api.letsencrypt.org/directory
       privateKeySecretRef:
         name: example-issuer-account-key
       http01: {}
