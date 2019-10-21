=====================
cainjector controller
=====================

The cainjector controller injects a Certificate into the ``caBundle`` field
of ValidatingWebhookConfiguration, MutatingWebhookConfiguration or
APIService resources annotated with:

* ``cert-manager.io/inject-apiserver-ca: "true"``  
  Injects the cluster CA.
* ``cert-manager.io/inject-ca-from: <NAMESPACE>/<CERTIFICATE>``  
  Injects the CA from the specified :doc:`certificate </reference/certificates>`.
* ``cert-manager.io/inject-ca-from-secret: <NAMESPACE>/<CERTIFICATE>``  
  Injects the CA from the specified `secret <https://kubernetes.io/docs/concepts/configuration/secret/>`_.  
  the secret is needed the ``cert-manager.io/allow-direct-injection: "true"`` annotation
