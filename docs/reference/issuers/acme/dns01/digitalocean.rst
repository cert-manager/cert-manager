=========================
DigitalOcean
=========================

This provider uses a Kubernetes ``Secret`` Resource to work. In the
following example, the secret will have to be named ``digitalocean-dns``
and have a subkey ``access-token`` with the token in it.

.. code-block:: yaml

   digitalocean:
     tokenSecretRef:
       name: digitalocean-dns
       key: access-token