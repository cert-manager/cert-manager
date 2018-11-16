=========================
OVH
=========================

- To create an ``applicationKey`` and ``applicationSecret``, see OVH documentation at <https://docs.ovh.com/gb/en/customer/first-steps-with-ovh-api/>
- To get a ``consumerKey``, request an authentication token as describe in <https://docs.ovh.com/gb/en/customer/first-steps-with-ovh-api/#requesting-an-authentication-token-from-ovh>
This token must have sufficient permissions to GET/POST/PUT/DELETE to ``/domain`` API endpoint, see <https://eu.api.ovh.com/console/#/domain>



``applicationKey`` is configured directly in the issuer resource manifest whereas ``applicationSecret`` and ``consumerKey`` are supposed
to be stored in a Kubernetes Secret called ``ovh-credentials``.


.. code-block:: yaml

    ovh:
      endpoint: ovh-eu
      applicationKey: tf128Wv3U9hBj0FU
      applicationSecretSecretRef:
        name: ovh-credentials
        key: application-secret
      consumerKeySecretRef:
        name: ovh-credentials
        key: consumer-key