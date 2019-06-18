=================
Webhook component
=================

In order to provide advanced resource validation, cert-manager includes a
ValidatingWebhookConfiguration_ resource which is deployed into the cluster.

This allows cert-manager to validate that Issuer, ClusterIssuer and Certificate
resources that are submitted to the apiserver are syntactically valid, and
catch issues with your resources early on.

If you disable the webhook component, cert-manager will still perform the
same resource validation however it will not reject 'create' events when the
resources are submitted to the apiserver if they are invalid.
This means it may be possible for a user to submit a resource that renders
the controller inoperable.
For this reason, it is strongly advised to keep the webhook **enabled**.

.. note::
   This feature requires Kubernetes v1.9 or greater.

How it works
============

This sections walks through how the resource validation webhook is configured
and explains the process required for it to provision.

The webhook is a ValidatingWebhookConfiguration_ resource combined with an
extra pod that is deployed alongside the cert-manager-controller.

The ValidatingWebhookConfiguration instructs the Kubernetes apiserver to
POST the contents of any Create or Update operations performed on cert-manager
resource types in order to validate that they are setting valid configurations.

This allows us to ensure mis-configurations are caught early on and communicated
to you.

In order for this to work, the webhook requires a TLS certificate that the
apiserver is configured to trust.

The cert-manager deployment manifests define two Issuer resources, and two
Certificate resources:

* issuer/cert-manager-webhook-selfsign - A self signing Issuer that is used
  to issue a self signed root CA certificate.
* certificate/cert-manager-webhook-ca - A self-signed root CA certificate
  which is used to sign certificates for the webhook pod.
* issue/cert-manager-webhook-ca - A CA Issuer that is used to issue
  certificates used by the webhook pod to serve with.
* certificate/cert-manager-webhook-webhook-tls - A TLS certificate issued by the
  root CA above, served by the webhook.

You can check the status of these resources to ensure they're functioning
correctly by running:

.. code-block:: shell

   kubectl get issuer --namespace cert-manager
   NAME                            AGE
   cert-manager-webhook-ca         10m
   cert-manager-webhook-selfsign   10m

   kubectl get certificate -o wide --namespace cert-manager
   NAME                               READY   SECRET                             ISSUER                          STATUS                                          AGE
   cert-manager-webhook-ca            True    cert-manager-webhook-ca            cert-manager-webhook-selfsign   Certificate is up to date and has not expired   10m
   cert-manager-webhook-webhook-tls   True    cert-manager-webhook-webhook-tls   cert-manager-webhook-ca         Certificate is up to date and has not expired   10m

If the certificates or issuer are not Ready or you cannot see them, you should
check the :doc:`troubleshooting <./troubleshooting>` guide for help.

.. note::
   If you are running Kubernetes v1.10 or earlier, you may need to run
   ``kubectl describe`` instead of ``kubectl get`` as the
   'additionalPrinterColumns' functionality only moved to beta in v1.11.

cainjector
----------

The :doc:`cert-manager CA injector </reference/cainjector>` is responsible for
injecting the two CA bundles above into the webhook's
ValidatingWebhookConfiguration and APIService resource in order to allow the
Kubernetes apiserver to 'trust' the webhook apiserver.

This component is configured using the ``certmanager.k8s.io/inject-apiserver-ca: "true"``
and ``certmanager.k8s.io/inject-apiserver-ca: "true"`` annotations on the
APIService and ValidatingWebhookConfiguration resources.

It copies across the CA defined in the 'cert-manager-webhook-ca' Secret
generated above to the ``caBundle`` field on the APIService resource.
It also sets the webhook's ``clientConfig.caBundle`` field on the
``cert-manager-webhook`` ValidatingWebhookConfiguration resource to that of
your Kubernetes API server in order to support Kubernetes versions earlier than
v1.11.

Known issues
------------

This section contains known issues with the webhook component.

If you're having problems, or receiving errors when creating cert-manager
resources, please read through this section for help.

Disabling validation on the cert-manager namespace
--------------------------------------------------

If you've installed cert-manager with custom manifests, or have performed an
upgrade from an earlier version, it's important to make sure that the namespace
that the webhook is running in has an additional label applied to it in order
to disable resource validation on the namespace that the webhook runs in.

If this step is not completed, cert-manager will not be able to provision
certificates for the webhook correctly, causing a chicken-egg situation.

To apply the label, run:

.. code-block:: shell

   kubectl label namespace cert-manager certmanager.k8s.io/disable-validation=true

You may need to wait a little while before cert-manager retries issuing the
certificates if they have been failing for a while due to cert-manager's built
in back-offs.


Running on private GKE clusters
-------------------------------

When Google configure the control plane for private clusters, they
automatically configure VPC peering between your Kubernetes cluster's network
and a separate Google managed project.

In order to restrict what Google are able to access within your cluster, the
firewall rules configured restrict access to your Kubernetes pods.

This means that in order to use the webhook component with a GKE private
cluster, you must configure an additional firewall rule to allow the GKE
control plane access to your webhook pod.

You can read more information on how to add firewall rules for the GKE control
plane nodes in the `GKE docs`_.

Alternatively, you can read how to `disable the webhook component`_ below.

.. todo:: add an example command for how to do this here & explain any security
   implications

Disable the webhook component
==============================

If you are having issues with the webhook and cannot use it at this time,
you can optionally disable the webhook altogether.

Doing this may expose your cluster to mis-configuration problems that in some
cases could cause cert-manager to stop working altogether (i.e. if invalid
types are set for fields on cert-manager resources).

How you disable the webhook depends on your deployment method.

With Helm
---------

The Helm chart exposes an option that can be used to disable the webhook.

To do so with an existing installation, you can run:

.. code-block:: shell

   helm upgrade cert-manager \
      --reuse-values \
      --set webhook.enabled=false

If you have not installed cert-manager yet, you can add the
``--set webhook.enabled=false`` to the ``helm install`` command used to install
cert-manager.

With static manifests
---------------------

Because we cannot specify options when installing the static manifests to
conditionally disable different components, we also ship a copy of the
deployment files that do not include the webhook.

Instead of installing with `cert-manager.yaml`_ file, you should instead use
the `cert-manager-no-webhook.yaml`_ file located in the deploy directory.

This is a destructive operation, as it will remove the CustomResourceDefinition
resources, causing your configured Issuers, Certificates etc to be deleted.

You should first :doc:`backup your configuration </tasks/backup-restore-crds>`
before running the following commands.

To re-install cert-manager without the webhook, run:

.. code-block:: shell

   kubectl delete -f https://github.com/jetstack/cert-manager/releases/download/v0.8.1/cert-manager.yaml

   kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v0.8.1/cert-manager-no-webhook.yaml

Once you have re-installed cert-manager, you should then
:doc:`restore your configuration </tasks/backup-restore-crds>`.

.. _`deploy directory`: https://github.com/jetstack/cert-manager/blob/release-0.8/deploy/manifests
.. _`cert-manager.yaml`: https://github.com/jetstack/cert-manager/releases/download/v0.8.1/cert-manager.yaml
.. _`cert-manager-no-webhook.yaml`: https://github.com/jetstack/cert-manager/releases/download/v0.8.1/cert-manager-no-webhook.yaml
.. _`GKE docs`: https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters#add_firewall_rules
.. _`ValidatingWebhookConfiguration`: https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/
