============================
Troubleshooting installation
============================

During installation, a number of operations including a Kubernetes 'Job' will
be created.
These resources **must** complete successfully in order for cert-manager to
run.

To verify your installation has completed, you should check the Status of all
pods in your cert-manager namespace:

.. code-block:: shell

   # Get all pods, including Completed and Errored pods
   kubectl get pods --show-all --namespace cert-manager
   NAME                                            READY   STATUS      RESTARTS   AGE
   cert-manager-7cbdc48784-rpgnt                   1/1     Running     0          3m
   cert-manager-webhook-5b5dd6999-kst4x            1/1     Running     0          3m
   cert-manager-webhook-ca-sync-1547942400-g6985   0/1     Completed   0          3m

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
   If the job continues to fail, please read the :doc:`Webhook <./webhook>`
   docs for additional information.
