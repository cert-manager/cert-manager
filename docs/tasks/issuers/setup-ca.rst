=====================
Setting up CA Issuers
=====================


cert-manager can be used to obtain certificates using an arbitrary signing
key pair stored in a Kubernetes Secret resource.

This guide will show you how to configure and create a CA based issuer, backed
by a signing key pair stored in a Secret resource.

1. (Optional) Generate a signing key pair
=========================================

The CA Issuer does not automatically create and manage a signing key pair for
you. As a result, you will need to either supply your own or generate a self
signed CA using a tool such as openssl_ or cfssl_.

This guide will explain how to generate a new signing key pair, however you can
substitute it for your own so long as it has the ``CA`` flag set.

.. code-block:: shell

   # Generate a CA private key
   $ openssl genrsa -out ca.key 2048

   # Create a self signed Certificate, valid for 10yrs with the 'signing' option set
   $ openssl req -x509 -new -nodes -key ca.key -subj "/CN=${COMMON_NAME}" -days 3650 -reqexts v3_req -extensions v3_ca -out ca.crt

The output of these commands will be two files, ``ca.key`` and ``ca.crt``, the
key and certificate for your signing key pair. If you already have your own key
pair, you should name the private key and certificate ``ca.key`` and ``ca.crt``
respectively.

2. Save the signing key pair as a Secret
========================================

We are going to create an Issuer that will use this key pair to generate signed
certificates. You can read more about the Issuer resource in :doc:`the Issuer
reference docs </reference/issuers>`. To allow the Issuer to reference our key
pair we will store it in a Kubernetes Secret resource.

Issuers are namespaced resources and so they can only reference Secrets in
their own namespace. We will therefore put the key pair into the same namespace
as the Issuer. We could alternatively create a :doc:`ClusterIssuer
</reference/clusterissuers>`, a cluster-scoped version of an Issuer. For more
information on ClusterIssuers, read the :doc:`ClusterIssuer reference
documentation </reference/clusterissuers>`.

The following command will create a Secret containing a signing key pair in the
default namespace:

.. code-block:: shell

   kubectl create secret tls ca-key-pair \
      --cert=ca.crt \
      --key=ca.key \
      --namespace=default

3. Creating an Issuer referencing the Secret
============================================

We can now create an Issuer referencing the Secret resource we just created:

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 8

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Issuer
   metadata:
     name: ca-issuer
     namespace: default
   spec:
     ca:
       secretName: ca-key-pair

We are now ready to obtain certificates!

4. Obtain a signed Certificate
==============================

We can now create the following Certificate resource which specifies the
desired certificate. You can read more about the Certificate resource in
:doc:`the reference docs </reference/certificates>`.

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 9, 10, 11, 12

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Certificate
   metadata:
     name: example-com
     namespace: default
   spec:
     secretName: example-com-tls
     issuerRef:
       name: ca-issuer
       # We can reference ClusterIssuers by changing the kind here.
       # The default value is Issuer (i.e. a locally namespaced Issuer)
       kind: Issuer
     commonName: example.com
     organization:
     - Example CA
     dnsNames:
     - example.com
     - www.example.com

In order to use the Issuer to obtain a Certificate, we must create a
Certificate resource in the **same namespace as the Issuer**, as an Issuer is a
namespaced resource. We could alternatively create a :doc:`ClusterIssuer
</reference/clusterissuers>` if we wanted to reuse the signing key pair across
multiple namespaces.

Once we have created the Certificate resource, cert-manager will attempt to use
the Issuer ``ca-issuer`` to obtain a certificate. If successful, the
certificate will be stored in a Secret resource named ``example-com-tls`` in
the same namespace as the Certificate resource (``default``).

The example above explicitly sets the ``commonName`` field to ``example.com``.
cert-manager automatically adds the ``commonName`` field as a `DNS SAN`_ if it
is not already contained in the ``dnsNames`` field.

If we had **not** specified the ``commonName`` field, then the **first** DNS
SAN that is specified (under ``dnsNames``) would be used as the certificate's
common name.

After creating the above Certificate, we can check whether it has been obtained
successfully like so:

.. code-block:: shell

   $ kubectl describe certificate example-com
   Events:
     Type     Reason                 Age              From                     Message
     ----     ------                 ----             ----                     -------
     Warning  ErrorCheckCertificate  26s              cert-manager-controller  Error checking existing TLS certificate: secret "example-com-tls" not found
     Normal   PrepareCertificate     26s              cert-manager-controller  Preparing certificate with issuer
     Normal   IssueCertificate       26s              cert-manager-controller  Issuing certificate...
     Normal   CertificateIssued      25s              cert-manager-controller  Certificate issued successfully

You can also check whether issuance was successful with
``kubectl get secret example-com-tls -o yaml``. You should see a base64 encoded
signed TLS key pair.

Once the certificate has been obtained, cert-manager will keep checking its
validity and attempt to renew it if it gets close to expiry.
cert-manager considers certificates to be close to expiry when the 'Not After'
field on the certificate is less than the current time plus 30 days. For CA
based Issuers, cert-manager will issue certificates with the 'Not After'
field set to the current time plus 365 days.

.. _openssl: https://github.com/openssl/openssl
.. _cfssl: https://github.com/cloudflare/cfssl
.. _`DNS SAN`: https://en.wikipedia.org/wiki/Subject_Alternative_Name
