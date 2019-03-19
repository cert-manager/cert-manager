=========================
Google CloudDNS
=========================

This guide explains how to set up an Issuer, or ClusterIssuer, to use Google CloudDNS to solve DNS01 ACME challenges. It's advised you read the :doc:`DNS01 Challenge Provider </tasks/acme/configuring-dns01/index>` page first for a more general understanding of how cert-manager handles DNS01 challenges.

.. note::
   This guide assumes that your cluster is hosted on Google Cloud Platform (GCP) and that you already have a domain set up with CloudDNS.

Set up a Service Account
========================

Cert-manager needs to be able to add records to CloudDNS in order to solve the DNS01 challenge. To enable this, a GCP service account must be created with the ``dns.admin`` role.

.. note::
   For this guide the ``gcloud`` command will be used to set up the service account. Ensure that ``gcloud`` is in using the correct project and zone before entering the commands. These steps could also be completed using the Cloud Console.

.. code-block:: shell

   gcloud iam service-accounts create dns01-solver \
    --display-name "dns01-solver"
   # Replace both uses of project-id with the id of your project
   gcloud projects add-iam-policy-binding project-id \
    --member serviceAccount:dns01-solver@project-id.iam.gserviceaccount.com \
    --role roles/dns.admin

Create a Service Account Secret
===============================

To access this service account cert-manager uses a key stored in a Kubernetes Secret. First, create a key for the service account and download it as JSON file, then create a Secret from this file.

.. code-block:: shell

   # Replace use of project-id with the id of your project
   gcloud iam service-accounts keys create key.json \
    --iam-account dns01-solver@project-id.iam.gserviceaccount.com
   kubectl create secret generic clouddns-dns01-solver-svc-acct \
    --from-file=key.json

.. note::
   Keep the key file safe and do not share it, as it could be used to gain access to your cloud resources. The key file can be deleted once it has been used to generate the Secret.

Create an Issuer That Uses CloudDNS
===================================

Next, create an Issuer (or ClusterIssuer) with a ``clouddns`` provider. An example Issuer manifest can be seen below with annotations.

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 16, 17, 18, 19, 20, 21, 22, 23, 24

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Issuer
   metadata:
     name: letsencrypt-staging
   spec:
     acme:
       # Replace with your email address so you can be notified of expiring certificates
       email: user@example.com
       # Use Let's Encrypt staging for testing as production enforces stricter usage limits
       server: https://acme-staging-v02.api.letsencrypt.org/directory
       privateKeySecretRef:
         # The secret that holds the generated private key used to communicate with Let's Encrypt
         name: letsencrypt-staging-account-key
       dns01:
         providers:
         # The name given to this CloudDNS provider, multiple CloudDNS providers can be added with different names
         - name: my-clouddns-provider
           clouddns:
             # The ID of the GCP project
             project: my-project-id
             # This is the secret used to access the service account
             serviceAccountSecretRef:
               name: clouddns-dns01-solver-svc-acct
               key: key.json

For more information about Issuers and ClusterIssuers, see :doc:`Setting Up Issuers</tasks/issuers/index>`.

Once an Issuer (or ClusterIssuer) has been created successfully a Certificate can then be added to verify that everything works.

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 9, 10, 18, 19

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Certificate
   metadata:
     name: example-com
     namespace: default
   spec:
     secretName: example-com-tls
     issuerRef:
       # The issuer created previously
       name: letsencrypt-staging
     commonName: example.com
     dnsNames:
     - example.com
     - www.example.com
     acme:
       config:
       - dns01:
           # The provider in the previously created issuer
           provider: my-clouddns-provider
         domains:
         - example.com
         - www.example.com

For more details about Certificates, see :doc:`Issuing Certificates</tasks/issuing-certificates/index>`.
