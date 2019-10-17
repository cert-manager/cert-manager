=========================
Webhook
=========================

The webhook issuer is a generic acme solver. The actual work is done by an external service. Look at the respective documentation of the `solver`.

Existing webhook solvers:

* `alidns-webhook <https://github.com/pragkent/alidns-webhook>`_
* `cert-manager-webhook-dnspod <https://github.com/qqshfox/cert-manager-webhook-dnspod>`_
* `cert-manager-webhook-selectel <https://github.com/selectel/cert-manager-webhook-selectel>`_
* `cert-manager-webhook-softlayer <https://github.com/cgroschupp/cert-manager-webhook-softlayer>`_

See more webhook solver on: https://github.com/topics/cert-manager-webhook

.. code-block:: yaml
   :emphasize-lines: 10-14

   apiVersion: cert-manager.io/v1alpha2
   kind: Issuer
   metadata:
     name: example-issuer
   spec:
     acme:
      ...
       solvers:
       - dns01:
           webhook:
             groupName: <webhook-group-name>
             solverName: <webhook-solver-name>
             config:
               ...
               <webhook-specific-configuration>
