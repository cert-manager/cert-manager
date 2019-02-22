=========================
Alibaba Cloud DNS
=========================

.. code-block:: yaml

   alibabacloud:
     regionId: "cn-beijing"
     accessTokenSecretRef:
       name: alibabacloud-secret
       key: access-token
     secretKeySecretRef:
       name: alibabacloud-secret
       key: secret-key