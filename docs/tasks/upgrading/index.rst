======================
Upgrading cert-manager
======================

This section contains information on upgrading cert-manager.
It also contains documents detailing breaking changes between cert-manager
versions, and information on things to look out for when upgrading.

.. note::
   Before performing upgrades of cert-manager, it is advised to take a backup
   of all your cert-manager resources just in case an issue occurs whilst
   upgrading. You can read how to backup and restore cert-manager in the
   :doc:`../backup-restore-crds` guide.

Upgrading with Helm
===================

If you installed cert-manager using Helm, you can easily upgrade using the Helm
CLI.

.. note::
   Before upgrading, please read the relevant instructions at the links below
   for your from and to version.

Once you have read the relevant upgrading notes and taken any appropriate
actions, you can begin the upgrade process like so - replacing
``<release_name>`` with the name of your Helm release for cert-manager (usually
this is ``cert-manager``) and replacing ``<version>`` with the
version number you want to install:

.. code:: shell

   # Install the cert-manager CustomResourceDefinition resources before
   # upgrading the Helm chart
   kubectl apply \
        -f https://raw.githubusercontent.com/jetstack/cert-manager/<version>/deploy/manifests/00-crds.yaml

   # Ensure the local Helm chart repository cache is up to date
   helm repo update

   # If you are upgrading from v0.5 or below, you should manually add this
   # label to your cert-manager namespace to ensure the `webhook component`_
   # can provision correctly.
   kubectl label namespace cert-manager certmanager.k8s.io/disable-validation=true

   helm upgrade --version <version> <release_name> jetstack/cert-manager

This will upgrade you to the latest version of cert-manager, as listed in the
`Jetstack Helm chart repository`_.

.. note::
   You can find out your release name using ``helm list | grep cert-manager``.

Upgrading using static manifests
================================

If you installed cert-manager using the `static deployment manifests`_, you
can upgrade them in a similar way to how you first installed them.

.. note::
   Before upgrading, please read the relevant instructions at the links below
   for your from and to version.

Once you have read the relevant notes and taken any appropriate actions, you
can begin the upgrade process like so - replacing ``<version>`` with the
version number you want to install:

.. code:: shell

   # If you are upgrading from v0.5 or below, you should manually add this
   # label to your cert-manager namespace to ensure the `webhook component`_
   # can provision correctly.
   kubectl label namespace cert-manager certmanager.k8s.io/disable-validation=true

   kubectl apply \
        -f https://github.com/jetstack/cert-manager/releases/download/<version>/cert-manager.yaml

.. note::
   If you are running kubectl v1.12 or below, you will need to add the
   ``--validate=false`` flag to your ``kubectl apply`` command above else you
   will receive a validation error relating to the ``caBundle`` field of the
   ``ValidatingWebhookConfiguration`` resource.
   This issue is resolved in Kubernetes 1.13 onwards. More details can be found
   in `kubernetes/kubernetes#69590`_.

.. toctree::
   :maxdepth: 1

   upgrading-0.2-0.3
   upgrading-0.3-0.4
   upgrading-0.4-0.5
   upgrading-0.5-0.6
   upgrading-0.6-0.7
   upgrading-0.7-0.8

.. _`official Helm charts repository`: https://hub.helm.sh/charts/jetstack
.. _`static deployment manifests`: https://github.com/jetstack/cert-manager/blob/release-0.8/deploy/manifests
.. _`kubernetes/kubernetes#69590`: https://github.com/kubernetes/kubernetes/issues/69590
