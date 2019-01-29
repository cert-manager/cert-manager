===============================
Issuing Certificates using ACME
===============================

ACME certificates currently require additional configuration on the Certificate
resource that you create in order to determine how to solve the
`ACME challenges`_ that the ACME protocol requires.

In future releases of cert-manager, this configuration is likely to move off of
the Certificate resource and onto the Issuer resource in order to create a
better separation of concerns. More info can be found on issue `#XXX`_.

.. todo:: write guide explaining how to configure certificate.spec.acme

.. _`ACME challenges`:
.. _`#XXX`:
