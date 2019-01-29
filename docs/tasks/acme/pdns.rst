=========================
PowerDNS
=========================

This provider uses a Kubernetes ``Secret`` Resource to work. In the
following example, the secret will have to be named ``pdns-dns``
and have a subkey ``api-key`` with the API key in it.

See `PowerDNS HTTP API documentation <https://doc.powerdns.com/authoritative/http-api/index.html>`
for more information about the API.

.. code-block:: yaml

   pdns:
     host: http://pdns.example.com:8080
     tokenSecretRef:
       name: pdns-dns
       key: api-key

     # The following values are options
     # Record TTL (in seconds)
     ttl: 60

     # API timeout (in seconds)
     timeout: 30

     # Record propagation timeout (in seconds)
     propagationTimeout: 120

     # Record propagation polling interval (in seconds)
     pollingInterval: 2
