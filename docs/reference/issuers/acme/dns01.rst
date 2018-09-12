========================
DNS01 Challenge Provider
========================

The ACME issuer can also contain DNS provider configuration, which can be used
by Certificates using this Issuer in order to validate DNS01 challenge
requests:

.. code-block:: yaml
   :linenos:
   :emphasize-lines: 7

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Issuer
   metadata:
     name: example-issuer
   spec:
     acme:
       email: user@example.com
       server: https://acme-staging-v02.api.letsencrypt.org/directory
       privateKeySecretRef:
         name: example-issuer-account-key
       dns01:
         providers:
         - name: prod-clouddns
           clouddns:
             project: my-project
             serviceAccountSecretRef:
               name: prod-clouddns-svc-acct-secret
               key: service-account.json

Each issuer can specify multiple different DNS01 challenge providers, and
it is also possible to have multiple instances of the same DNS provider on a
single Issuer (e.g. two clouddns accounts could be set, each with their own
name).

Setting nameservers for DNS01 self check
========================================

Cert-manager will check the correct DNS records exist before attempting a DNS01
challenge.  By default, the DNS servers for this check will be taken from
``/etc/resolv.conf``.  If this is not desired (for example with multiple
authoritative nameservers or split-horizon DNS), the cert-manager controller
provides the ``--dns01-self-check-nameservers`` flag, which allows overriding the default
nameservers with a comma seperated list of custom nameservers.

Example usage::

    --dns01-self-check-nameservers "8.8.8.8:53,1.1.1.1:53"


.. _supported-dns01-providers:

*************************
Supported DNS01 providers
*************************

A number of different DNS providers are supported for the ACME issuer. Below is
a listing of them all, with an example block of configuration:

Google CloudDNS
===============

.. code-block:: yaml

   clouddns:
     project: my-project
     serviceAccountSecretRef:
       name: prod-clouddns-svc-acct-secret
       key: service-account.json

Amazon Route53
==============

.. code-block:: yaml

   route53:
     region: eu-west-1

     # optional if ambient credentials are available; see ambient credentials documentation
     accessKeyID: AKIAIOSFODNN7EXAMPLE
     secretAccessKeySecretRef:
       name: prod-route53-credentials-secret
       key: secret-access-key

Cert-manager requires the following IAM policy.

.. code-block:: json

   {
       "Version": "2012-10-17",
       "Statement": [
           {
               "Effect": "Allow",
               "Action": "route53:GetChange",
               "Resource": "arn:aws:route53:::change/*"
           },
           {
               "Effect": "Allow",
               "Action": "route53:ChangeResourceRecordSets",
               "Resource": "arn:aws:route53:::hostedzone/*"
           },
           {
               "Effect": "Allow",
               "Action": "route53:ListHostedZonesByName",
               "Resource": "*"
           }
       ]
   }

The ``route53:ListHostedZonesByName`` statement can be removed if you specify
the optional hosted zone ID (``spec.acme.dns01.providers[].route53.hostedZoneID``) on
the Issuer resource. You can further tighten this policy by limiting the hosted
zone that cert-manager has access to (replace ``arn:aws:route53:::hostedzone/*``
with ``arn:aws:route53:::hostedzone/DIKER8JPL21PSA``, for instance).

Cloudflare
==========

.. code-block:: yaml

   cloudflare:
     email: my-cloudflare-acc@example.com
     apiKeySecretRef:
       name: cloudflare-api-key-secret
       key: api-key

Akamai FastDNS
==============

.. code-block:: yaml

    akamai:
      serviceConsumerDomain: akab-tho6xie2aiteip8p-poith5aej0ughaba.luna.akamaiapis.net
      clientTokenSecretRef:
        name: akamai-dns
        key: clientToken
      clientSecretSecretRef:
        name: akamai-dns
        key: clientSecret
      accessTokenSecretRef:
        name: akamai-dns
        key: accessToken

RFC2136
========

.. code-block:: yaml

    rfc2136:
      nameserver: 192.168.0.1
      tsigKeyName: myzone-tsig
      tsigAlgorithm: HMACMD5
      tsigSecretSecretRef:
        name: my-secret
        key: tsigkey

ACME-DNS
========

.. code-block:: yaml

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
