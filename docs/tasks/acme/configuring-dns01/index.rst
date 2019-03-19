========================
DNS01 Challenge Provider
========================

The ACME issuer can also contain DNS provider configuration, which can be used
by Certificates using this Issuer in order to validate DNS01 challenge
requests:

You can read about how the DNS01 challenge type works on the
`Let's Encrypt challenge types page`_.

.. _`Let's Encrypt challenge types page`: https://letsencrypt.org/docs/challenge-types/#dns-01-challenge


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
a listing of available providers, their `.yaml` configurations, along with additional Kubernetes
and provider specific notes regarding their usage.

.. toctree::
   :maxdepth: 1

   acme-dns
   akamai
   azuredns
   cloudflare
   google
   route53
   digitalocean
   rfc2136
