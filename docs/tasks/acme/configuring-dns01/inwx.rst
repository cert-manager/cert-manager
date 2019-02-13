=========================
Inwx
=========================

This provider uses a Kubernetes ``Secret`` Resource to work. In the
following example, the secret will have to be named ``inwx-credentials``
and have the subkeys ``username`` and ``password`` with username and password in it.

The credentials are the same as to log in at `Website <https://inwx.de>`. You may write their support
for distinguished credentials.


.. code-block:: yaml

   inwx:
     credentialSecretRef:
       name: inwx-credentials
       # optional
       # usernameKey: otherUsernameKey
       # passwordKey: otherPasswordKey