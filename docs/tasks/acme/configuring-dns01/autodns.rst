=========================
AutoDNS
=========================

.. code-block:: yaml

    autodns:
      usernameSecretRef:
        name: autodns
        key: username
      passwordSecretRef:
        name: autodns
        key: password
      contextSecretRef:
        name: autodns
        key: context
