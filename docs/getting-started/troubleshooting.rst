============================
Troubleshooting installation
============================

Internal error occurred: failed calling admission webhook ... the server is currently unable to handle the request
==================================================================================================================

When installing or upgrading cert-manager, you may run into issues when going
through the Validation Steps in the install guide which relate to the admission
webhook.

If you see an error like the above, this guide will talk you through a few
checks that can pick up common installation problems.

1. Check the namespace cert-manager is running in
-------------------------------------------------

As described in the :doc:`webhook` documentation, the webhook component
requires TLS certificates in order to start and communicate securely with the
Kubernetes API server.

In order for cert-manager to be able to issue certificates for the webhook
before it has started, we must **disable** resource validation on the namespace
that cert-manager is running in.

Assuming you have deployed into the ``cert-manager`` namespace, run the
following command to verify that your cert-manager namespace has the necessary
label:

.. code-block:: shell
   :emphasize-lines: 4

   kubectl get namespace

   Name:         cert-manager
   Labels:       certmanager.k8s.io/disable-validation=true
   ...

If you cannot see the ``certmanager.k8s.io/disable-validation=true`` label on
your namespace, you should add it with:

.. code-block:: shell

   kubectl label namespace cert-manager certmanager.k8s.io/disable-validation=true

Please continue reading this guide once you have added the label.

2. Verify that the webhook Issuer and Certificate resources exist
-----------------------------------------------------------------

If you had any issues upgrading, especially if you install cert-manager using
Helm, you may run into an issue where either:

* the CustomResourceDefinition resources do not exist
* the webhook's Issuer and Certificate resources do not exist

We can first check for the existence of the CustomResourceDefinition resources:

.. code-block:: shell

   kubectl get crd | grep certmanager

   NAME                                          CREATED AT
   certificates.certmanager.k8s.io               2018-08-17T20:12:26Z
   challenges.certmanager.k8s.io                 2018-08-02T15:33:02Z
   clusterissuers.certmanager.k8s.io             2018-08-17T20:12:26Z
   issuers.certmanager.k8s.io                    2018-08-17T20:12:26Z
   orders.certmanager.k8s.io                     2018-08-02T14:40:11Z

We should then also check for that the webhook's Issuer and Certificate
resources exist and have been issued correctly:

.. code-block:: shell

   kubectl get issuer,certificate

   NAME                                                      AGE
   issuer.certmanager.k8s.io/cert-manager-webhook-ca         22d
   issuer.certmanager.k8s.io/cert-manager-webhook-selfsign   22d

   NAME                                                              READY   SECRET                             AGE
   certificate.certmanager.k8s.io/cert-manager-webhook-ca            True    cert-manager-webhook-ca            22d
   certificate.certmanager.k8s.io/cert-manager-webhook-webhook-tls   True    cert-manager-webhook-webhook-tls   22d

If you do not see the CustomResourceDefinitions installed, or cannot see the
webhook's Issuer and Certificate resources, please go back to the install guide
and ensure you've followed every step closely.

Take particular care to install the CRD manifest **before** installing
cert-manager itself.

3. Verify all cert-manager pods are running successfully
--------------------------------------------------------

You can verify that cert-manager has managed to start successfully by checking
the state of the pods that have been deployed:

.. code-block:: shell

   # Get all pods, including Completed and Errored pods
   kubectl get pods --show-all --namespace cert-manager

   NAME                                            READY   STATUS      RESTARTS   AGE
   cert-manager-7cbdc48784-rpgnt                   1/1     Running     0          3m
   cert-manager-webhook-5b5dd6999-kst4x            1/1     Running     0          3m
   cert-manager-webhook-ca-sync-1547942400-g6985   0/1     Completed   0          3m

If the 'webhook' pod (2nd line) is in a ContainerCreating state, it may still
be waiting for the Secret in step 2 to be mounted into the pod.

Provided the Secret resource **does** now exist, Waiting a few minutes, or
deleting the pod and allowing it to be recreated should get things moving
again.

.. note::
   Check if the Secret exists by running::

     kubectl get secret cert-manager-webhook-webhook-tls


If the ``ca-sync`` pod has not reached a Completed state, or has not been run,
you may need to manually re-trigger it to run. You can read more on how to do
this below.

4. Manually trigger the ca-sync CronJob to run
----------------------------------------------

If the 'ca-sync' pod above does not show Completed, you may need to re-start
the Job using the ``kubectl create job`` command:

.. code-block:: shell

   # Find the name of the CronJob resource
   kubectl get cronjob --namespace cert-manager
   NAME                           SCHEDULE   SUSPEND   ACTIVE   LAST SCHEDULE   AGE
   cert-manager-webhook-ca-sync   @weekly    False     0                        3m

   # Trigger the CronJob to run immediately
   kubectl create job \
        --namespace cert-manager \
        --from cronjob/cert-manager-webhook-ca-sync \
        ca-sync-manually-triggered

This will trigger the cert-manager job to run again.

.. note::
   The ``--from`` flag was only introduced in kubectl v1.11

.. note::
   If the job continues to fail, please read the :doc:`Webhook <./webhook>`
   docs for additional information.
