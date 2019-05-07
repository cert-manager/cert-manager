=========================
ACME-DNS
=========================

.. code-block:: yaml
   :emphasize-lines: 10-14

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Issuer
   metadata:
     name: example-issuer
   spec:
     acme:
       ...
       solvers:
       - dns01:
           acmedns:
             host: https://acme.example.com
             accountSecretRef:
               name: acme-dns
               key: acmedns.json

In general, clients to acme-dns perform registration on the users behalf and inform
them of the CNAME entries they must create. This is not possible in cert-manager, it
is a non-interactive system. Registration must be carried out beforehand and the resulting
credentials JSON uploaded to the cluster as a secret. In this example, we use ``curl`` and the
API endpoints directly. Information about setting up and configuring acme-dns is available on
the `acme-dns project page <https://github.com/joohoi/acme-dns>`_.

1. First, register with the acme-dns server, in this example, there is one running at "auth.example.com"

  ``curl -X POST http://auth.example.com/register`` will return a JSON with credentials for your registration:

  .. code-block :: json

    {
      "username":"eabcdb41-d89f-4580-826f-3e62e9755ef2",
      "password":"pbAXVjlIOE01xbut7YnAbkhMQIkcwoHO0ek2j4Q0",
      "fulldomain":"d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.example.com",
      "subdomain":"d420c923-bbd7-4056-ab64-c3ca54c9b3cf",
      "allowfrom":[]
    }

  It is strongly recommended to restrict the update endpoint to the IP range of your pods.
  This is done at registration time as follows:

  ``curl -X POST http://auth.example.com/register -H "Content-Type: application/json" --data '{"allowfrom": ["10.244.0.0/16"]}'``

  Make sure to update the ``allowfrom`` field to match your cluster configuration. The JSON will now look like

  .. code-block :: json

    {
      "username":"eabcdb41-d89f-4580-826f-3e62e9755ef2",
      "password":"pbAXVjlIOE01xbut7YnAbkhMQIkcwoHO0ek2j4Q0",
      "fulldomain":"d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.example.com",
      "subdomain":"d420c923-bbd7-4056-ab64-c3ca54c9b3cf",
      "allowfrom":["10.244.0.0/16"]
    }

2. Save this JSON to a file with the key as your domain. You can specify multiple domains with the same credentials
   if you like. In our example, the returned credentials can be used to verify ownership of "example.com" and
   and "example.org".

  .. code-block :: json

    {
      "example.com": {
        "username":"eabcdb41-d89f-4580-826f-3e62e9755ef2",
        "password":"pbAXVjlIOE01xbut7YnAbkhMQIkcwoHO0ek2j4Q0",
        "fulldomain":"d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.example.com",
        "subdomain":"d420c923-bbd7-4056-ab64-c3ca54c9b3cf",
        "allowfrom":["10.244.0.0/16"]
      },
      "example.org": {
        "username":"eabcdb41-d89f-4580-826f-3e62e9755ef2",
        "password":"pbAXVjlIOE01xbut7YnAbkhMQIkcwoHO0ek2j4Q0",
        "fulldomain":"d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.example.com",
        "subdomain":"d420c923-bbd7-4056-ab64-c3ca54c9b3cf",
        "allowfrom":["10.244.0.0/16"]
      }
    }

3. Next update your primary DNS server with CNAME record that will tell the verifier how to locate the challenge TXT
   record. This is obtained from the "fulldomain" field in the registration:

  ``_acme-challenge.example.com CNAME d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.example.com``
  ``_acme-challenge.example.org CNAME d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.example.com``

  Note that the "name" of the record is always the "_acme-challenge" subdomain, and the "value" of the record matches
  exactly the "fulldomain" field from registration.

  At verification time, the domain name ``d420c923-bbd7-4056-ab64-c3ca54c9b3cf.auth.example.com`` will be a TXT
  record that is set to your validation token. When the verifier queries ``_acme-challenge.example.com``, it will
  be directed to the correct location by this CNAME record. This proves that you control "example.com"

4. Create a secret from the credentials json that was saved in step 2, this secret is referenced
   in the ``accountSecretRef`` field of your dns01 issuer settings.

   ``kubectl create secret generic acme-dns --from-file acmedns.json``


.. _`Let's Encrypt`: https://letsencrypt.org
