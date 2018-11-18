=========================
DNSPod
=========================

This provider uses a Kubernetes ``Secret`` Resource to work. In the
following example, the secret will have to be named ``dnspod-api-key-secret``
and have a subkey ``api-key`` with the token in it.

To create a token, see `DNSPod Document <https://support.dnspod.cn/Kb/showarticle/tsid/227/>`_.


.. code-block:: yaml

    dnspod:
     apiKeySecretRef:
       name: dnspod-api-key-secret
       key: api-key
