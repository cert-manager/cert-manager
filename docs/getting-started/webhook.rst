=================
Webhook component
=================

In order to provide advanced resource validation, cert-manager includes a
ValidatingWebhookConfiguration_ resource which is deployed into the cluster.

This allows cert-manager to validate that cert-manager API resources that are
submitted to the apiserver are syntactically valid, and catch issues with your
resources early on.

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

This allows us to ensure mis-configurations are caught early on and
communicated to you.

In order for this to work, the webhook requires a TLS certificate that the
apiserver is configured to trust. This is created by the webhook itself and is
implemented by the following two Secrets:

* secret/cert-manager-webhook-ca - A self-signed root CA certificate
  which is used to sign certificates for the webhook pod.
* secret/cert-manager-webhook-tls - A TLS certificate issued by the
  root CA above, served by the webhook.

The webhook's 'webhookbootstrap' controller is responsible for creating these
secrets with no manual intervention needed.

If errors occur around the webhook but the webhook is running then the webhook
is most likely not reachable from the API server. In this case, ensure that the
API server can communicate with the webhook by following the GKE private cluster
explanation below.

cainjector
----------

The :doc:`cert-manager CA injector </reference/cainjector>` is responsible for
injecting the two CA bundles above into the webhook's
ValidatingWebhookConfiguration and APIService resource in order to allow the
Kubernetes apiserver to 'trust' the webhook apiserver.

This component is configured using the ``cert-manager.io/inject-apiserver-ca: "true"``
and ``cert-manager.io/inject-apiserver-ca: "true"`` annotations on the
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

Running on private GKE clusters
-------------------------------

When Google configure the control plane for private clusters, they
automatically configure VPC peering between your Kubernetes cluster's network
and a separate Google managed project.

In order to restrict what Google are able to access within your cluster, the
firewall rules configured restrict access to your Kubernetes pods. This will
mean that you will experience the webhook to not work and expierence errors such
as `Internal error occurred: failed calling admission webhook ... the server is
currently unable to handle the request`.

In order to use the webhook component with a GKE private
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
cases could cause cert-manager to stop working altogether (i.e. if invalid types
are set for fields on cert-manager resources).

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

   kubectl delete -f https://github.com/jetstack/cert-manager/releases/download/v0.11.1/cert-manager.yaml

   kubectl apply -f https://github.com/jetstack/cert-manager/releases/download/v0.11.1/cert-manager-no-webhook.yaml

Once you have re-installed cert-manager, you should then
:doc:`restore your configuration </tasks/backup-restore-crds>`.

.. _`cert-manager.yaml`: https://github.com/jetstack/cert-manager/releases/download/v0.11.1/cert-manager.yaml
.. _`cert-manager-no-webhook.yaml`: https://github.com/jetstack/cert-manager/releases/download/v0.11.1/cert-manager-no-webhook.yaml
.. _`GKE docs`: https://cloud.google.com/kubernetes-engine/docs/how-to/private-clusters#add_firewall_rules
.. _`ValidatingWebhookConfiguration`: https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/
