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
       privateKeySecretRef:
         name: example-issuer-account-key
       http01: {}

.. note::
   Let's Encrypt does not support issuing wildcard certificates with HTTP-01 challenges.
   To issue wildcard certificates, you must use the DNS-01 challenge.

How HTTP01 validations work
===========================

.. todo::
   Write a full description of how HTTP01 challenge validation works

Extra options
=============

The HTTP01 Issuer supports a number of additional options.
For full details on the range of options available, read the
`reference documentation`_.

.. _`reference documentation`: https://cert-manager.readthedocs.io/en/latest/reference/api-docs/index.html#acmeissuerhttp01config-v1alpha1

servicePort
-----------

In rare cases it might be not possible/desired to use NodePort as type for the
http01 challenge response service, e.g. because of Kubernetes limit
restrictions. To define which Kubernetes service type to use during challenge
response specify the following http01 config:

.. code-block:: yaml

       http01:
         # Valid values are ClusterIP and NodePort
         serviceType: ClusterIP

By default type NodePort will be used when you don't set http01 or when you set
serviceType to an empty string. Normally there's no need to change this.
