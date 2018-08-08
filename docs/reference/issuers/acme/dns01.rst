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
the optional hosted zone ID (``spec.acme.dns01.providers[].hostedZoneID``) on
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

.. _`Let's Encrypt`: https://letsencrypt.org
