============================
Upgrading from v0.9 to v0.10
============================

Due to changes in the way the webhook component's TLS is bootstrapped in v0.10,
you will need to delete your webhook's Certificate and Issuer resources.

If you are using a deployment tool that automatically handles this (i.e. Helm),
there should be no additional action to take.

If you are using the 'static manifests' to install, you should run the following
after upgrading:

.. code-block:: shell

   kubectl delete -n cert-manager issuer cert-manager-webhook-ca cert-manager-webhook-selfsign
   kubectl delete -n cert-manager certificate cert-manager-webhook-ca cert-manager-webhook-webhook-tls
   kubectl delete apiservice v1beta1.admission.certmanager.k8s.io

The Secret resources used to contain TLS assets for the webhook are now
automatically handled internally by cert-manager, so these resources are no
longer required.
