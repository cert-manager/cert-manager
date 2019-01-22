==========================
2. Installing cert-manager
==========================

With Helm
==========

Using Helm is the recommended way to deploy cert-manager. We publish a stable
version of the chart to the public `charts repository`_.

Before installing the cert-manager Helm chart, you will need to install the
CustomResourceDefinition resources that it uses.

You can perform these two steps with the following commands:

.. code-block:: shell

    # Install the cert-manager CRDs
    $ kubectl apply \
        -f https://raw.githubusercontent.com/jetstack/cert-manager/release-0.6/deploy/manifests/00-crds.yaml

    # Update helm repository cache
    $ helm repo update

    # Install cert-manager
    $ helm install \
        --name cert-manager \
        --namespace cert-manager \
        --version v0.6.0 \
        stable/cert-manager

Each time you upgrade, you will need to re-apply the ``00-crds.yaml`` manifest
above (updating the version number, in this case ``v0.6.0``, accordingly).

The default cert-manager configuration is good for the majority of users, but a
full list of the available options can be found in the `Helm chart README`_.

.. note::
   If your cluster does not use RBAC (Role Based Access Control), you
   will need to disable creation of RBAC resources by adding
   ``--set rbac.create=false`` to your ``helm install`` command above.

.. note::
   If you are upgrading from a previous release, please check the :doc:`upgrading guide </admin/upgrading>`
   for special considerations.

With static manifests
=====================

As some users may not want to use Helm, or would prefer to use a more
traditional deployment management mechanism, we also provide 'static manifests'
which can be installed with ``kubectl apply -f``.

To install cert-manager using the static manifests, you should run:

.. code-block:: shell

   # Install cert-manager
   $ kubectl apply \
        -f https://raw.githubusercontent.com/jetstack/cert-manager/release-0.6/deploy/manifests/cert-manager.yaml

.. note::
   If you are running kubectl v1.12 or below, you will need to add the
   ``--validate=false`` flag to your ``kubectl apply`` command above else you
   will receive a validation error relating to the ``caBundle`` field of the
   ``ValidatingWebhookConfiguration`` resource.
   This issue is resolved in Kubernetes 1.13 onwards. More details can be found
   in `kubernetes/kubernetes#69590`_.

Verifying your installation
===========================

During installation, a number of operations including a Kubernetes 'Job' will
be created.
These resources **must** complete successfully in order for cert-manager to
run.

To verify your installation has completed, you should check the Status of all
pods in your cert-manager namespace:

.. code-block:: shell

   # Get all pods, including Completed and Errored pods
   $ kubectl get pods --show-all --namespace cert-manager
   NAME                                            READY   STATUS      RESTARTS   AGE
   cert-manager-7cbdc48784-rpgnt                   1/1     Running     0          3m
   cert-manager-webhook-5b5dd6999-kst4x            1/1     Running     0          3m
   cert-manager-webhook-ca-sync-1547942400-g6985   0/1     Completed   0          3m

If the 'ca-sync' pod above does not show Completed, you may need to re-start
the Job using the ``kubectl create job`` command:

.. code-block:: shell

   # Find the name of the CronJob resource
   $ kubectl get cronjob --namespace cert-manager
   NAME                           SCHEDULE   SUSPEND   ACTIVE   LAST SCHEDULE   AGE
   cert-manager-webhook-ca-sync   @weekly    False     0                        3m

   # Trigger the CronJob to run immediately
   $ kubectl create job \
        --namespace cert-manager \
        --from cronjob/cert-manager-webhook-ca-sync \
        ca-sync-manually-triggered

This will trigger the cert-manager job to run again.

.. note::
   If the job continues to fail, please read the
   :doc:`Resource Validating Webhook </admin/resource-validation-webhook>` docs
   for additional information.

Once all the pods are 'Ready', you should be good to go. To confirm, attempt
to create a basic 'selfsigned' ClusterIssuer. If you do not receive any errors
when creating the resource, the deployment should be good to go!

.. code-block:: shell

   # Create a ClusterIssuer to test the webhook works okay
   $ cat <<EOF > test-clusterissuer.yaml
   apiVersion: certmanager.k8s.io/v1alpha1
   kind: ClusterIssuer
   metadata:
     name: test-selfsigned
   spec:
     selfSigned: {}

   # Create the new ClusterIssuer (if this step fails, please read the resource
   # validation webhook doc linked in the note above)
   $ kubectl apply -f test-clusterissuer.yaml

   # Delete the newly created test ClusterIssuer
   $ kubectl delete -f test-clusterissuer.yaml

If all the above steps have completed with error, you are good to go!

Next steps
==========

You'll need to set yourself at least one Issuer or ClusterIssuer resource in
order to begin issuing certificates. Take a look at the next page,
:doc:`Configuring your first Issuer or ClusterIssuer
</getting-started/3-configuring-first-issuer>`
for more information.

.. _`charts repository`: https://github.com/kubernetes/charts
.. _`Helm chart README`: https://github.com/kubernetes/charts/blob/master/stable/cert-manager/README.md
.. _`deploy directory`: https://github.com/jetstack/cert-manager/blob/master/contrib/manifests/cert-manager
.. _`kubernetes/kubernetes#69590`: https://github.com/kubernetes/kubernetes/issues/69590
