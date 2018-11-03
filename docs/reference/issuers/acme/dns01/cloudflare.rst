=========================
Cloudflare
=========================

.. code-block:: yaml

   cloudflare:
     email: my-cloudflare-acc@example.com
     apiKeySecretRef:
       name: cloudflare-api-key-secret
       key: api-key