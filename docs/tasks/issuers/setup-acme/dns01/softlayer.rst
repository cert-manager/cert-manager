=========================
Softlayer
=========================

This provider uses a Kubernetes ``Secret`` Resource to work. In the
following example, the secret will have to be named ``softlayer-api-key``
and have a subkey ``apikey`` with the api-key in it.

To create an Softlayer API Key, see `IBM Cloud documentation <https://cloud.ibm.com/docs/iam?topic=iam-classic_keys#classic_keys/>`_.


.. code-block:: yaml

    softlayer:
      username: softlayer-username
      apiKeySecretRef:
        name: softlayer-api-key
        key: apikey
