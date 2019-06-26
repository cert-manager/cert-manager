=======================
Setting up Step Issuers
=======================

Installing Step Certificates
----------------------------

There are different ways to install Smallstep Step Certificates and initialize
your PKI. The easiest one is probably to use Helm which will generate your PKI
on the fly:

.. code-block:: shell

   # Add the Smallstep Helm repository
   $ helm repo add smallstep  https://smallstep.github.io/helm-charts
   $ helm repo update

   # Install step certificates
   $ helm install --name your-release smallstep/step-certificates

For custom options or a different installation process, refer to the docs on Step
Certificates `documentation <https://github.com/smallstep/certificates>`__.

Creating an Issuer resource
---------------------------

An Step Issuer resource contains the necessary parameters to issue JWT tokens
used by step certificates to validate and sign a certificate signing request or
CSR. This JWT is signed by an encrypted private key configured in the step
certificates configuration. We will need to configure all the necessary
parameters to get the proper provisioner key and decrypt its private key.

Helm automatically initializes one provisioner and stores the password in the
secret named ``your-release-step-certificates-provisioner-password``. But if you
want to use a different provisioner you will have to create a secret for it yourself.
Using kubctl would be:

.. code-block:: shell

   kubectl create secret generic provisioner-secret \
        --namespace='<namespace-of-issuer-resource>' \
        --from-literal=password='<your-provisioner-password>'

Or, alternatively, you can create a secret using the yaml format like:

.. code-block:: yaml

   apiVersion: v1
   kind: Secret
   type: Opaque
   metadata:
     name: provisioner-secret
     namespace: default
   data:
     password: bXktcHJvdmlzaW9uZXItcGFzc3dvcmQ=

The issuer configuration is not complete yet. The following is required to
be able to create provisioning tokens:

* The URL to access the Step Certificates API. Using Helm the URL requires following format
  ``https://your-release-step-certificates.default.svc.cluster.local``.

* The base64 encoded version of the root certificate of Step Certificate PKI.
  Using Helm this is stored in a configmap named ``your-release-step-certificates-certs``,
  and we can retrieve the necessary value with:

  .. code-block:: shell

     # See the contents of the configmap
     $ kubectl get configmaps -o yaml your-release-step-certificates-certs

     apiVersion: v1
     kind: ConfigMap
     ...
     data:
      intermediate_ca.crt: |
        -----BEGIN CERTIFICATE-----
        MII...
        -----END CERTIFICATE-----
      root_ca.crt: |
        -----BEGIN CERTIFICATE-----
        MII...
        -----END CERTIFICATE-----

     # Convert root_ca.crt to base64
     $ kubectl get configmaps -o jsonpath="{.data['root_ca\.crt']}" your-release-step-certificates-certs | base64
     LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSQ...

* The provisioner name. Using Helm the default one is ``admin``. However, feel free to use
  any other name for JWK provisioners.

* The provisioner kid (Key ID) configured in step certificates configuration.
  Using Helm this can be retrieved from the secret named ``your-release-step-certificates-config``.

  .. code-block:: shell

     $ kubectl get configmaps -o yaml your-release-step-certificates-config
     apiVersion: v1
     kind: ConfigMap
     ...
     data:
       ca.json: |-
         {
           "root": "/home/step/certs/root_ca.crt",
           ...
           "authority": {
               "provisioners": [
                 {
                     "type": "jwk",
                     "name": "admin",
                     "key": {
                       "use": "sig",
                       "kty": "EC",
                       "kid": "3z16SrqPaBTNntB0xY0Y3qPg27Rm2EAYrucoVsZxfhk",
                       "crv": "P-256",
                       "alg": "ES256",
                       "x": "5kyqkvQfMSwFr9zTTquFVBw-pLZzYiVkYrHRusbu3wI",
                       "y": "vBRSfWjyr2AQHPdvU8bsbRO0dJtlYBGFMSL0xDa35cI"
                     },
                     "encryptedKey": "eyJhbGciOiJQQkVTMi1IUzI1NitBMTI4S1ciLCJjdHkiOiJqd2sranNvbiIsImVuYyI6IkEyNTZHQ00iLCJwMmMiOjEwMDAwMCwicDJzIjoiRWhuQXJaV2lmRWxoc1huMmRjRHk3USJ9.xaBx2Yl0A0QP-NRa9qWpwmm16nCp3eJr5vGeUirIyZpanRV_Zm1OfA.9EYZVuVUpn9WTVI8.xqHOvNoGdUDte6o6tOqtk6VHjTPhQKQZH-tRCOcHy8pLNjGcIwjJpl6pW-Xpr9f4H4EpbZ1K5omFff8eEpkXTnB_CfcXSYcz3QvExpmh57l1-Ds-eQjRUPyOguaGF_OCQwGPh_kl6RDw4QTECcp2yk2Snkv0VrXNO8xAnR24cJrOWIc3UpGPtPjlP6v_of2uPkKC_4eqn5p3pZFi1MG7HLC5NpKN0p3ebihMo4WBXfuFJDeTCN2bDlGDlVCj8gqQwjhkmPkIH_Ty_348sagM1mUtz5w3qLzyd9NRRaUTtavQ9amxx5FEXj5ZiWmSE5jeEHV9juGs9-25y96BBDM.JGL6ezKz6hKGCMTGSDOzpA"
                 }
               ]
           },
           ...
         }
     ...

With the secret, name and kid in place now we can create the Step certificates issuer
referencing the respective values:

.. code-block:: yaml

  apiVersion: certmanager.k8s.io/v1alpha1
  kind: Issuer
  metadata:
    name: step-issuer
    namespace: default
  spec:
    step:
      url: <step-certificates-url>
      caBundle: <base64 encoded caBundle PEM file>
      provisioner:
        name: <provisioner name>
        kid: <provisioner kid>
        passwordRef:
          name: provisioner-secret
          key: password

An example issuer using values used previously will look like this:

.. code-block:: yaml

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Issuer
   metadata:
     name: step-issuer
     namespace: default
   spec:
     step:
       url: https://your-release-step-certificates.default.svc.cluster.local
       caBundle: LS0tLS1CRUdJTiBDRVJUSUZJQ0FURS0tLS0tCk1JSUJpekNDQVRHZ0F3SUJBZ0lRU3U1Q3FtUmhtRVlxVTMyZjV3ZUFjakFLQmdncWhrak9QUVFEQWpBa01TSXcKSUFZRFZRUURFeGxUZEdWd0lFTmxjblJwWm1sallYUmxjeUJTYjI5MElFTkJNQjRYRFRFNU1EWXhPREUyTlRVdwpORm9YRFRJNU1EWXhOVEUyTlRVd05Gb3dKREVpTUNBR0ExVUVBeE1aVTNSbGNDQkRaWEowYVdacFkyRjBaWE1nClVtOXZkQ0JEUVRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQlAvQkdPYVJsWUxsbkcyMGt3cHkKdUxuS0FYalJXbFFZemhTSjVPM1BzT2lsRGJFbDlraFBZZFBIWnhLWHBUQ0VobTMrM3BPOVZ2UHgzZThrdW9ScAoreEdqUlRCRE1BNEdBMVVkRHdFQi93UUVBd0lCQmpBU0JnTlZIUk1CQWY4RUNEQUdBUUgvQWdFQk1CMEdBMVVkCkRnUVdCQlErcnB5eXd6NUh5Zzg2UWhWUkRTd2EzUmErcXpBS0JnZ3Foa2pPUFFRREFnTklBREJGQWlFQXdEeWEKdG1lWWJtSzFPZGxtaTZocDF6bG1jNjFoUGsybzdnbGRWQUVmMlNnQ0lIY2ptOE04YVBOQ0U1NVllM3lTZ2w2NAorYWJPTkdQdWpaVXNMaWl4Z2syaQotLS0tLUVORCBDRVJUSUZJQ0FURS0tLS0tCg==
       provisioner:
         name: admin
         kid: 3z16SrqPaBTNntB0xY0Y3qPg27Rm2EAYrucoVsZxfhk
         passwordRef:
           name: provisioner-secret
           key: password


Once we have provisioned the Issuer we can use it to obtain a certificate:

.. code-block:: yaml

    apiVersion: certmanager.k8s.io/v1alpha1
    kind: Certificate
    metadata:
      name: example-com
      namespace: default
    spec:
      secretName: example-com-tls
      issuerRef:
        name: step-issuer
      commonName: example.com
      dnsNames:
      - www.example.com

Please see the :doc:`Issuing Certificates <../issuing-certificates/index>` document
for more information on how to create Certificate resources.