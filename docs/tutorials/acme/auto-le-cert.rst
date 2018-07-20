========================================================
Automatically obtain TLS certificates using ingress-shim
========================================================

The ingress-shim subcomponent of cert-manager can automatically obtain TLS 
certificates from Let's Encrypt (or another ACME server) through a
ClusterIssuer resource.

1. Launch cert-manager with defaultIssuer

2. Create an ACME ClusterIssuer

3. Configure ingress with a TLS placeholder and annotation

4. Verify each ingress now has a corresponding Certificate

1. Launch cert-manager with defaultIssuer
=========================================

cert-manager should be deployed using Helm, according to our official
:doc:`/getting-started/index` guide.

Pick a name for your ClusterIssuer and set it at launch.

.. code-block:: shell

   helm install \
      --name cert-manager \
      --namespace kube-system \
     --set ingressShim.defaultIssuerName=letsencrypt-staging \
     --set ingressShim.defaultIssuerKind=ClusterIssuer \
     stable/cert-manager

2. Create an ACME ClusterIssuer
===============================

Create a file named ``cluster-issuer.yaml``:

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 11

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: ClusterIssuer
   metadata:
     # Adjust the name here accordingly
     name: letsencrypt-staging
   spec:
     acme:
       # The ACME server URL
       server: https://acme-staging-v02.api.letsencrypt.org/directory
       # Email address used for ACME registration
       email: user@example.com
       # Name of a secret used to store the ACME account private key from step 3
       privateKeySecretRef:
         name: letsencrypt-private-key
       # Enable the HTTP-01 challenge provider
       http01: {}

We then submit this file to our Kubernetes cluster:

.. code-block:: shell

   $ kubectl create -f cluster-issuer.yaml

You should be able to verify the ACME account has been verified successfully:

.. code-block:: shell
   :emphasize-lines: 26-31

   $ kubectl describe clusterissuer letsencrypt-staging
   Name:         letsencrypt-staging
   Namespace:
   Labels:       <none>
   Annotations:  <none>
   API Version:  certmanager.k8s.io/v1alpha1
   Kind:         ClusterIssuer
   Metadata:
     Cluster Name:
     Creation Timestamp:  2017-11-30T22:33:40Z
     Generation:          0
     Resource Version:    4450170
     Self Link:           /apis/certmanager.k8s.io/v1alpha1/letsencrypt-staging
     UID:                 83d04e6b-d61e-11e7-ac26-42010a840044
   Spec:
     Acme:
       Email:  user@example.com
       Http 01:
       Private Key Secret Ref:
         Key:
         Name:  letsencrypt-private-key
       Server:  https://acme-staging-v02.api.letsencrypt.org/directory
   Status:
     Acme:
       Uri:  https://acme-staging-v02.api.letsencrypt.org/acme/acct/11217539
     Conditions:
       Last Transition Time:  2018-04-12T17:32:30Z
       Message:               The ACME account was registered with the ACME server
       Reason:                ACMEAccountRegistered
       Status:                True
       Type:                  Ready


3. Configure ingress with a TLS placeholder and annotation
==========================================================

The ingress-shim watches for ingress resources with 2 conditions

* ``kubernetes.io/tls-acme: "true"`` annotation
* a TLS Certificate resource specified

Allowing the ingress-shim to use the existing ingress to validate would simplify the process, and is necessary when using Rancher. This can be done by adding the following annotation to the ingress as well.
* ``certmanager.k8s.io/acme-http01-edit-in-place: "true"`` annotation

The specified Certificate resource will be overwritten, so you can generate a 
temporary self-signed certificate using openssl to complete this setup.

.. code-block:: shell

   openssl req \
     -newkey rsa:2048 -nodes -keyout domain.key \
     -x509 -out domain.crt

Convert PKCS8 key to PKCS1 key if you are using Rancher

.. code-block:: shell

   openssl rsa -in domain.key -out domain_new.key

4. Verify each ingress now has a corresponding Certificate
==========================================================

Before we finish, we should make sure there is now a Certificate resource.

You should be able to check this by running:

.. code-block:: shell

   $ kubectl get certificates --all-namespaces

We can also verify that cert-manager has 'adopted' the old TLS certificates by
'describing' one of these newly created certificates:

.. code-block:: shell

   $ kubectl describe certificate my-example-certificate
   ...
   Events:
     Type    Reason            Age                 From                     Message
     ----    ------            ----                ----                     -------
     Normal  RenewalScheduled  1m                  cert-manager-controller  Certificate scheduled for renewal in 292 hours

Here we can see cert-manager has verified the existing TLS certificate and
scheduled it to be renewed in 292h time.
