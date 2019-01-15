======
Orders
======

Order resources are used by the ACME issuer to manage the lifecycle of an ACME
'order' for a signed TLS certificate.

When a Certificate resource is created that references an ACME issuer,
cert-manager will create an Order resource in order to obtain a signed
certificate.

As an end-user, you will never need to manually create an Order resource.
Once created, an Order cannot be changed. Instead, a new Order resource must be
created.

Debugging Order resources
=========================

In order to debug why a Certificate isn't being issued, we can first run
``kubectl describe`` on the Certificate resource we're having issues with:

.. code-block:: shell

    $ kubectl describe certificate example-com

    ...
    Events:
      Type    Reason        Age   From          Message
      ----    ------        ----  ----          -------
      Normal  Generated     1m    cert-manager  Generated new private key
      Normal  OrderCreated  1m    cert-manager  Created Order resource "example-com-1217431265"

We can see here that Certificate controller has created an Order resource to
request a new certificate from the ACME server.

Orders are a useful source of information when debugging failures issuing ACME
certificates. By running ``kubectl describe order`` on a particular order,
information can be gleaned about failures in the process:

.. code-block:: shell

    $ kubectl describe order example-com-1248919344

    ...
    Reason:
    State:         pending
    URL:           https://acme-v02.api.letsencrypt.org/acme/order/41123272/265506123
    Events:
      Type    Reason   Age   From          Message
      ----    ------   ----  ----          -------
      Normal  Created  1m    cert-manager  Created Challenge resource "example-com-1217431265-0" for domain "test1.example.com"
      Normal  Created  1m    cert-manager  Created Challenge resource "example-com-1217431265-1" for domain "test2.example.com"

Here we can see that cert-manager has created two Challenge resources in order
to fulfil the requirements of the ACME order to obtain a signed certificate.

You can then go on to run
``kubectl describe challenge example-com-1217431265-0`` to further debug the
progress of the Order.

Once an Order is successful, you should see an event like the following:

.. code-block:: shell

    $ kubectl describe order example-com-1248919344

    ...
    Reason:
    State:         valid
    URL:           https://acme-v02.api.letsencrypt.org/acme/order/41123272/265506123
    Events:
      Type    Reason      Age   From          Message
      ----    ------      ----  ----          -------
      Normal  Created     72s   cert-manager  Created Challenge resource "example-com-1217431265-0" for domain "test1.example.com"
      Normal  Created     72s   cert-manager  Created Challenge resource "example-com-1217431265-1" for domain "test2.example.com"
      Normal  OrderValid  4s    cert-manager  Order completed successfully

If the Order is not completing successfully, you can debug the challenges
for the Order by running ``kubectl describe`` on the Challenge resource.

For more information on debugging Challenge resources, read the
:doc:`challenge reference docs </reference/challenges>`.
