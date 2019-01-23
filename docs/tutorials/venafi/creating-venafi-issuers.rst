Setting up a Venafi Cloud or TPP Issuer
=======================================

The Venafi issuer is an extension which supports certificate management from
Venafi Cloud and Venafi Trust Protection Platform.

Deploying cert-manager
----------------------

.. note::
   Please also see the 'Getting Started' guide on the left for more info on how
   to deploy cert-manager.

.. note::
   This guide assumes you already have a functioning Kubernetes cluster
   of version 1.9 or greater.

You can run the following to deploy cert-manager with the Venafi integration
for the first time:

.. code-block:: shell

   kubectl apply -f https://raw.githubusercontent.com/jetstack/cert-manager/venafi/contrib/manifests/cert-manager/with-rbac.yaml

.. note::
   This step only needs to be performed once!
.. note::
   Please verify that no errors were output when you run this command.

Creating Venafi Cloud issuer
----------------------------

Register your account at https://api.venafi.cloud/login and get API key there.

Create a secret containing your authentication credentials for the issuer to
use (in this example, the Issuer will utilise Venafi Cloud and will only issue
certificates in the ``default`` namespace).

.. code-block:: shell

    kubectl create secret generic cloudsecret --from-literal=apikey='YOUR_CLOUD_API_KEY_HERE'

Create the issuer, referencing the secret we just created:

.. code-block:: yaml

    apiVersion: certmanager.k8s.io/v1alpha1
    kind: Issuer
    metadata:
      name: cloud-venafi-issuer
    spec:
      venafi:
        zone: "DevOps"
        cloud:
          apiKeySecretRef:
            name: cloudsecret
            key: apikey

You can create multiple issuers pointing to different Venafi Cloud zones, or
even have 1 issuer pointing to Venafi Platform and another pointing to Venafi
Cloud.

We can then create a certificate resource that utilises this newly configured
issuer:

.. code-block:: yaml

    apiVersion: certmanager.k8s.io/v1alpha1
    kind: Certificate
    metadata:
      name: cert4-venafi-localhost
    spec:
      commonName: cert4.venafi.localhost
      secretName: cert4-venafi-localhost
      issuerRef:
        name: cloud-venafi-issuer

To see the full list of options available on the Certificate resource, take a
look at the ``API reference documentation``.

Creating Venafi Platform issuer
-------------------------------

Similar to how we created credentials and an Issuer resource for TPP Cloud
above, we can also create Issuers for Venafi TPP instances.

Again, you can have multiple Issuer's for different Venafi zones, and even run
Venafi Cloud Issuers alongside Venafi TPP Issuers.

**Requirements for Venafi Platform policy**

1. You **must** allow "User Provided CSRs" as part of your TPP policy, as this
   is the only type supported by the underlying ``vcert`` library we use.

2. MSCA configuration should have http URI set before the ldap URI in
   X509 extensions, otherwise NGINX ingress controller couldn't get
   certificate chain from URL and OSCP will not work. Example:
   TODO: verify this/make it clearer

::

    X509v3 extensions:
        X509v3 Subject Alternative Name:
        DNS:test-cert-manager1.venqa.venafi.com}}
        X509v3 Subject Key Identifier: }}
        61:5B:4D:40:F2:CF:87:D5:75:5E:58:55:EF:E8:9E:02:9D:E1:81:8E}}
        X509v3 Authority Key Identifier: }}
        keyid:3C:AC:9C:A6:0D:A1:30:D4:56:A7:3D:78:BC:23:1B:EC:B4:7B:4D:75}}X509v3 CRL Distribution Points:Full Name:
        URI:http://qavenafica.venqa.venafi.com/CertEnroll/QA%20Venafi%20CA.crl}}
        URI:ldap:///CN=QA%20Venafi%20CA,CN=qavenafica,CN=CDP,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=venqa,DC=venafi,DC=com?certificateRevocationList?base?objectClass=cRLDistributionPoint}}{{Authority Information Access: }}
        CA Issuers - URI:http://qavenafica.venqa.venafi.com/CertEnroll/qavenafica.venqa.venafi.com_QA%20Venafi%20CA.crt}}
        CA Issuers - URI:ldap:///CN=QA%20Venafi%20CA,CN=AIA,CN=Public%20Key%20Services,CN=Services,CN=Configuration,DC=venqa,DC=venafi,DC=com?cACertificate?base?objectClass=certificationAuthority}}

3. Option in Venafi Platform CA configuration template "Automatically include
   CN as DNS SAN" should be set to true. (TODO this shouldn't be a requirement)

**Create a secret with Venafi Platform credentials:**

Like before, we create a Secret resource containing our Venafi TPP credentials:

.. code-block:: shell

    kubectl create secret generic tppsecret \
        --from-literal=user=admin \
        --from-literal=password=tpppassword

Create Venafi Platform issuer

.. code-block:: yaml

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Issuer
   metadata:
     name: tpp-venafi-issuer
   spec:
     zone: devops\cert-manager # must exist in the TPP console
     venafi:
       tpp:
         url: https://tpp.venafi.example/vedsdk
         credentialsRef:
           name: tppsecret

**Create a certificate**

Just the same as before, we can create a Certificate resource that utilises the
TPP Issuer we just created:

.. code-block:: yaml

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Certificate
   metadata:
     name: hellodemo-venafi-localhost
   spec:
     commonName: hellodemo.venafi.localhost
     secretName: hellodemo-venafi-localhost
     issuerRef:
       name: tppvenafiissuer
