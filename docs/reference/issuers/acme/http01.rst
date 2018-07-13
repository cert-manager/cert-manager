=========================
HTTP01 Challenge Provider
=========================

In order to allow HTTP01 challenges to be solved, we must enable the HTTP01
challenge provider on our Issuer resource.

This is done through setting the ``http01`` field on the ``issuer.spec.acme``
stanza. Cert-manager will then attempt to solve ACME HTTP-01 challenges by
using Ingress resources

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 7, 11

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Issuer
   metadata:
     name: example-issuer
   spec:
     acme:
       email: user@example.com
       server: https://acme-staging-v02.api.letsencrypt.org/directory
       keysize: 2048
       privateKeySecretRef:
         name: example-issuer-account-key
       http01: {}

.. todo::
   Write a full description of how HTTP01 challenge validation works
