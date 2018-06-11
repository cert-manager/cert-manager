========================
Setting up CFSSL Issuers
========================

The CFSSL Issuer types allows you to obtain certificates from `CFSSL`_ instances.

Automated certificate renewal and management are provided for Certificates
using the CFSSL issuer.

.. note::
   The CFSSL Issuer has been recently added, and the exact structure of the
   Issuer resource is subject to change. Such changes will be clearly
   documented, and migration steps will be provided.

Creating an Issuer resource
===========================

You can configure your Issuer resource to either issue certificates only within
a single namespace, or cluster-wide (using a ClusterIssuer resource).
For more information on the distinction between Issuer and ClusterIssuer
resources, read the issuer_vs_clusterissuer_ section.

Creating a CFSSL Issuer
------------------------------

In order to set up a CFSSL Issuer, you must first create a Kubernetes
Secret resource containing the authkey used to sign requests sent to a CFSSL server.
This is only required if the CFSSL server requires auth key authentication.
CFSSL only accepts hexadecimal authentication keys.

.. code-block:: shell

   kubectl create secret generic \
        cfssl-auth-secret \
        --namespace='NAMESPACE OF YOUR ISSUER RESOURCE' \
        --from-literal=auth-key='YOUR_HEX_FORMAT_AUTH_KEY_HERE'

.. note::
   If you are configuring your Issuer as a ClusterIssuer resource in order to
   issue Certificates across your whole cluster, you must set the
   ``--namespace`` parameter to ``cert-manager``, which is the default 'cluster
   resource namespace'.

The auth key will be used to provide additional security when communicating with
a CFSSL instance.

Once the API key Secret has been created, you can create your Issuer or
ClusterIssuer resource. If you are creating a ClusterIssuer resource, you must
change the ``kind`` field to ``ClusterIssuer`` and remove the
``metadata.namespace`` field.

Save the below content after making your amendments to a file named
``cfssl-issuer.yaml``:

.. code-block:: yaml

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Issuer
   metadata:
     name: cfssl-issuer
     namespace: <NAMESPACE YOU WANT TO ISSUE CERTIFICATES IN>
   spec:
     cfssl:
       server: https://my.cfssl.instance:4433 # Change this to the URL of your CFSSL instance
       authKeySecretRef:
         key: auth-key
         name: cfssl-auth-secret
       caBundle: <base64 encoded string of caBundle PEM file>

You can then create the Issuer using ``kubectl create -f``:

.. code-block:: shell

   kubectl create -f cfssl-issuer.yaml

Verify the Issuer has been initialised correctly using ``kubectl describe``:

.. code-block:: shell

   kubectl describe issuer cfssl-issuer --namespace='NAMESPACE OF YOUR ISSUER RESOURCE'

   Name:         cfssl-issuer
   Namespace:    <NAMESPACE>
   Annotations:  <none>
   API Version:  certmanager.k8s.io/v1alpha1
   Kind:         Issuer
   Metadata:
     Creation Timestamp:  2019-01-01T00:00:00Z
     Generation:          1
     Resource Version:    000011112
     Self Link:           /apis/certmanager.k8s.io/v1alpha1/namespaces/<NAMESPACE>/issuers/cfssl-issuer
     UID:                 00000000-c0de-11de-c0de-c0dec0dec0de
   Spec:
     Cfssl:
       Auth Key Secret Ref:
         Key:   auth-key
         Name:  cfssl-auth-secret
       Server:  https://my.cfssl.instance:4433
       CaBundle: <base64 encoded string of caBundle PEM file>
   Status:
     Conditions:
       Last Transition Time:  2019-01-01T00:00:00Z
       Message:               Required Fields verified
       Reason:                FieldsVerified
       Status:                True
       Type:                  Ready
   Events:                    <none>


You are now ready to issue certificates using the newly provisioned CFSSL
Issuer.

Read the :doc:`Issuing Certificates <../issuing-certificates>` document
for more information on how to create Certificate resources.

.. _CFSSL: https://github.com/cloudflare/cfssl
