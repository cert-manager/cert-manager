=======================
Installing on OpenShift
=======================

cert-manager supports running on OpenShift in a similar manner to :doc:`Running on Kubernetes <./kubernetes>`.
It runs within your OpenShift cluster as a series of deployment
resources.
It utilises `CustomResourceDefinitions`_ to configure Certificate
Authorities and request certificates.

It is deployed using regular YAML manifests, like any other application on
OpenShift.

Once cert-manager has been deployed, you must configure Issuer or ClusterIssuer
resources which represent certificate authorities.
More information on configuring different Issuer types can be found in the
:doc:`respective setup guides </tasks/issuers/index>`.

Login to your OpenShift cluster
===============================

Before you can install cert-manager, you must first ensure your local machine
is configured to talk to your OpenShift cluster using the ``oc`` tool.

.. code-block:: shell

    # Login to the OpenShift cluster as the system:admin user
    oc login -u system:admin

Installing with regular manifests
=================================

In order to install cert-manager, we must first create a namespace to run it
within. This guide will install cert-manager into the ``cert-manager``
namespace. It is possible to run cert-manager in a different namespace,
although you will need to make modifications to the deployment manifests.

.. code-block:: shell

   # Create a namespace to run cert-manager in
   oc create namespace cert-manager

As part of the installation, cert-manager also deploys a
`ValidatingWebhookConfiguration`_ resource in order to validate that the
Issuer, ClusterIssuer and Certificate resources we will create after
installation are valid.

In order to deploy the ValidatingWebhookConfiguration, cert-manager creates
a number of 'internal' Issuer and Certificate resources in its own namespace.

This creates a chicken-and-egg problem, where cert-manager requires the
webhook in order to create the resources, and the webhook requires cert-manager
in order to run.

We avoid this problem by disabling resource validation on the namespace that
cert-manager runs in:

.. code-block:: shell

   # Disable resource validation on the cert-manager namespace
   oc label namespace cert-manager certmanager.k8s.io/disable-validation=true

You can read more about the webhook on the :doc:`webhook document <../webhook>`.

We can now go ahead and install cert-manager. All resources
(the CustomResourceDefinitions, cert-manager, and the webhook component)
are included in a single YAML manifest file:

.. code-block:: shell

   # Install the CustomResourceDefinitions and cert-manager itself
   oc apply --validate=false -f https://github.com/jetstack/cert-manager/releases/download/v0.8.0/cert-manager-openshift.yaml

.. note::
   The ``--validate=false`` flag is added to the ``oc apply`` command above
   else you will receive a validation error relating to the ``caBundle`` field
   of the ``ValidatingWebhookConfiguration`` resource.


Configuring your first Issuer
=============================

Before you can begin issuing certificates, you must configure at least one
Issuer or ClusterIssuer resource in your cluster.

You should read the :doc:`Setting up Issuers </tasks/issuers/index>` guide to
learn how to configure cert-manager to issue certificates from one of the
supported backends.

Debugging installation issues
=============================

If you have any issues with your installation, please refer to the
:doc:`troubleshooting guide <../troubleshooting>`.

.. _`CustomResourceDefinitions`: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/
.. _`Helm chart README`: https://github.com/jetstack/cert-manager/blob/release-0.8/deploy/charts/cert-manager/README.md
.. _`kubernetes/kubernetes#69590`: https://github.com/kubernetes/kubernetes/issues/69590
.. _`ValidatingWebhookConfiguration`: https://kubernetes.io/docs/reference/access-authn-authz/extensible-admission-controllers/
