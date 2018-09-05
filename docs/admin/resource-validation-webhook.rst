===========================
Resource Validation Webhook
===========================

In order to provide advanced resource validation, cert-manager includes a
ValidatingWebhookConfiguration which is deployed into the cluster as its own
pod.

This feature requires Kubernetes 1.9 or greater. If you disable the webhook
component, cert-manager will still perform the same resource validation however
will not reject 'create' events when submitting resources to the API server.

The webhook component is disabled by default, and must be enabled when
installing with the helm chart, or installed as an additional component
if using the static manifests.

Enabling the webhook component
==============================

With Helm
---------

To enable the component when using Helm, you must first ensure the namespace
that you deploy cert-manager into has the label
``certmanager.k8s.io/disable-validation: "true"``.

You can add this label like so:

.. code::

   $ kubectl label namespace cert-manager certmanager.k8s.io/disable-validation=true

.. note::
   New installations of cert-manager with Helm v2.10 and later will not require
   this additional step

You can then proceed to upgrade your Helm deployment as usual, adding one
additional flag:

.. code::

   $ helm upgrade cert-manager stable/cert-manager \
         --reuse-values \
         --set webhook.enabled=true

With static manifests
---------------------

When installing using the static manifests, the webhook component is installed
as a separate set of manifests.

You can find the manifests for the webhook in the `deploy directory`_.

FAQ
===

TLS Configuration
-----------------

The ValidatingWebhookConfiguration resource requires that the webhook server
uses TLS.

cert-manager uses a commbination of the SelfSigned and CA Issuer types to
provision the resources required to do this.

In order to do this, when installing with the Helm chart or static deployment
manifests, resource validation is **disabled** on the nammespace cert-manager
is deployed into.

.. note::
   If you have manually created the namespace that cert-manager is deployed into,
   you must ensure your namespace has the ``certmanager.k8s.io/disable-validation: "true"``
   Label set on the Namespace resource.
   This is handled automatically when performing a ``helm install`` for the first
   time by use of an additional selector in the ValidatingWebhookConfiguration

1) First, a self-signed Issuer is created in order to issue self-signed
certificates.
You can see this named ``cm-cert-manager-selfsign`` in the output below.

2) Then, a Certificate resource referencing the self-signed Issuer is created.
This certificate has ``spec.isCA: true`` set. It will be used as our root CA.
You can see this named ``cm-cert-manager-webhook-ca`` in the output below.

3) Then another Issuer resource is created, this time a **CA** Issuer.
This Issuer will issue certificates signed by the self-signed root CA created
in (2).
You can see this named ``cm-cert-manager-webhook-ca`` in the output below.

4) Finally, a second Certificate resource is created. This one will be used by
the webhook to secure communication between the apiserver and the webhook!
You can see this named ``cm-cert-manager-webhook-tls`` in the output below.

You can see the status of the certificates and issuers used for the webhook in
your own cluster by running:

.. code:: shell

   $ kubectl describe certificate --namespace cert-manager
   Name:         cm-cert-manager-webhook-ca
   Namespace:    cert-manager
   Labels:       <none>
   Annotations:  <none>
   API Version:  certmanager.k8s.io/v1alpha1
   Kind:         Certificate
   Metadata:
     Cluster Name:
     Creation Timestamp:  2018-08-07T23:18:53Z
     Generation:          0
     Resource Version:    722
     Self Link:           /apis/certmanager.k8s.io/v1alpha1/namespaces/cert-manager/certificates/cm-cert-manager-webhook-ca
     UID:                 402722a2-9a98-11e8-bf3f-525400856e41
   Spec:
     Common Name:  ca.webhook.cert-manager
     Is CA:        true
     Issuer Ref:
       Name:       cm-cert-manager-selfsign
     Secret Name:  cm-cert-manager-webhook-ca
   Status:
     Conditions:
       Last Transition Time:  2018-08-07T23:18:57Z
       Message:               Certificate issued successfully
       Reason:                CertIssued
       Status:                True
       Type:                  Ready
   Events:
     Type    Reason      Age   From          Message
     ----    ------      ----  ----          -------
     Normal  IssueCert   9m    cert-manager  Issuing certificate...
     Normal  CertIssued  9m    cert-manager  Certificate issued successfully


   Name:         cm-cert-manager-webhook-tls
   Namespace:    cert-manager
   Labels:       <none>
   Annotations:  <none>
   API Version:  certmanager.k8s.io/v1alpha1
   Kind:         Certificate
   Metadata:
     Cluster Name:
     Creation Timestamp:  2018-08-07T23:18:53Z
     Generation:          0
     Resource Version:    738
     Self Link:           /apis/certmanager.k8s.io/v1alpha1/namespaces/cert-manager/certificates/cm-cert-manager-webhook-tls
     UID:                 4021e81e-9a98-11e8-bf3f-525400856e41
   Spec:
     Dns Names:
       cm-cert-manager-webhook
       cm-cert-manager-webhook.cert-manager
       cm-cert-manager-webhook.cert-manager.svc
     Is CA:  false
     Issuer Ref:
       Name:       cm-cert-manager-webhook
     Secret Name:  cm-cert-manager-webhook-tls
   Status:
     Conditions:
       Last Transition Time:  2018-08-07T23:19:01Z
       Message:               Certificate issued successfully
       Reason:                CertIssued
       Status:                True
       Type:                  Ready
   Events:
     Type     Reason          Age   From          Message
     ----     ------          ----  ----          -------
     Warning  IssuerNotReady  9m    cert-manager  Issuer cm-cert-manager-webhook not ready
     Normal   IssueCert       9m    cert-manager  Issuing certificate...
     Normal   CertIssued      9m    cert-manager  Certificate issued successfully


   $ kubectl describe issuer --namespace cert-manager
   Name:         cm-cert-manager-selfsign
   Namespace:    cert-manager
   Labels:       <none>
   Annotations:  <none>
   API Version:  certmanager.k8s.io/v1alpha1
   Kind:         Issuer
   Metadata:
     Cluster Name:
     Creation Timestamp:  2018-08-07T23:18:53Z
     Generation:          0
     Resource Version:    696
     Self Link:           /apis/certmanager.k8s.io/v1alpha1/namespaces/cert-manager/issuers/cm-cert-manager-selfsign
     UID:                 402a07c1-9a98-11e8-bf3f-525400856e41
   Spec:
     Self Signed:
   Status:
     Conditions:
       Last Transition Time:  2018-08-07T23:18:55Z
       Message:
       Reason:                IsReady
       Status:                True
       Type:                  Ready
   Events:                    <none>


   Name:         cm-cert-manager-webhook-ca
   Namespace:    cert-manager
   Labels:       <none>
   Annotations:  <none>
   API Version:  certmanager.k8s.io/v1alpha1
   Kind:         Issuer
   Metadata:
     Cluster Name:
     Creation Timestamp:  2018-08-07T23:18:53Z
     Generation:          0
     Resource Version:    726
     Self Link:           /apis/certmanager.k8s.io/v1alpha1/namespaces/cert-manager/issuers/cm-cert-manager-webhook-ca
     UID:                 402ea69e-9a98-11e8-bf3f-525400856e41
   Spec:
     Ca:
       Secret Name:  cm-cert-manager-webhook-ca
   Status:
     Conditions:
       Last Transition Time:  2018-08-07T23:18:58Z
       Message:               Signing CA verified
       Reason:                KeyPairVerified
       Status:                True
       Type:                  Ready
   Events:
     Type     Reason           Age              From          Message
     ----     ------           ----             ----          -------
     Warning  ErrGetKeyPair    9m               cert-manager  Error getting keypair for CA issuer: secret "cm-cert-manager-webhook-ca" not found
     Warning  ErrInitIssuer    9m               cert-manager  Error initializing issuer: secret "cm-cert-manager-webhook-ca" not found
     Warning  ErrGetKeyPair    9m (x6 over 9m)  cert-manager  Error getting keypair for CA issuer: secret "cm-cert-manager-webhook-ca" not found
     Warning  ErrInitIssuer    9m (x6 over 9m)  cert-manager  Error initializing issuer: secret "cm-cert-manager-webhook-ca" not found
     Normal   KeyPairVerified  9m (x2 over 9m)  cert-manager  Signing CA verified

Keeping Kubernetes PKI resources up to date
-------------------------------------------

Once the root CA certificate has been provisioned, cert-manager also needs to
update the Kubernetes API Server to give it a copy of the root CA in order to
verify connections to the webhook component.

To do this, the ``spec.caBundle`` field on the ``APIService`` resource named
``v1beta1.admission.certmanager.k8s.io`` must be set to the root CA generated
above, and the ValidatingWebhookConfiguration named ``cert-manager-webhook``
must have its own ``caBundle`` fields set to that of your Kubernetes API
Server.

The cert-manager deployment manifests do this automatically by installing a
Kubernetes CronJob resource.
This CronJob will run every 24 hours and ensures that these resources are up to
date.

The code for this component can be found at `munnerz/apiextensions-ca-helper`_

.. _`munnerz/apiextensions-ca-helper`: https://github.com/munnerz/apiextensions-ca-helper
.. _`deploy directory`: https://github.com/jetstack/cert-manager/blob/release-0.5/contrib/manifests/cert-manager
