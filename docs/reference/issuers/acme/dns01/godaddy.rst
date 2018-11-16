=========================
Godaddy
=========================

This provider uses a Kubernetes ``Secret`` Resource to work. In the
following example, the secret will have to be named ``godaddy-dns``
and have a subkey ``access-token`` with the token in it.

To create a Personnal Access Token, see `Godaddy documentation <https://developer.godaddy.com/getstarted/>`_. 
Handy direct link: https://developer.godaddy.com/keys


.. code-block:: yaml

   godaddy:
     apiKey: ZZZXXXSAMPLEKEY
     tokenSecretRef:
       name: godaddy-dns
       key: apiSecret
