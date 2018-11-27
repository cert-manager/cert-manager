=========================
Selectel
=========================

This provider uses a Kubernetes ``Secret`` Resource to work. In the
following example, the secret will have to be named ``selectel-dns``
and have a sub-key ``api-token`` with the token in it.

To create an API Token you have sign in, see `Selectel sign in page <https://my.selectel.ru/login/>`_.
Handy direct links:
- https://my.selectel.ru/profile/apikeys
- https://kb.selectel.com


.. code-block:: yaml

   selectel:
     apiTokenSecretRef:
       name: selectel-api-token
       key: api-token
