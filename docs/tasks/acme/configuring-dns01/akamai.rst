=========================
Akamai FastDNS
=========================

.. code-block:: yaml

    akamai:
      serviceConsumerDomain: akab-tho6xie2aiteip8p-poith5aej0ughaba.luna.akamaiapis.net
      clientTokenSecretRef:
        name: akamai-dns
        key: clientToken
      clientSecretSecretRef:
        name: akamai-dns
        key: clientSecret
      accessTokenSecretRef:
        name: akamai-dns
        key: accessToken