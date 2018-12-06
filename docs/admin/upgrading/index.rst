======================
Upgrading cert-manager
======================

This section contains information on upgrading cert-manager.
It also contains documents detailing breaking changes between cert-manager
versions, and information on things to look out for when upgrading.

Upgrading with Helm
===================

If you installed cert-manager using Helm, you can easily upgrade using the Helm
CLI.

.. note::
   Before upgrading, please read the relevant instructions at the links below
   for your from and to version.

Once you have read the relevant notes and taken any appropriate actions, you
can begin the upgrade process like so - replacing ``<release_name>`` with the
name of your Helm release for cert-manager (usually this is ``cert-manager``):

.. code:: shell

   $ helm repo update

   $ kubectl apply \
        -f https://raw.githubusercontent.com/jetstack/cert-manager/${VERSION}/deploy/manifests/00-crds.yaml

   $ kubectl label namespace cert-manager certmanager.k8s.io/disable-validation=true

   $ helm upgrade --version ${VERSION} <release_name> stable/cert-manager

This will upgrade you to the latest version of cert-manager, as listed in the
`official Helm charts repository`_.

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
can begin the upgrade process like so - replacing ``${VERSION}`` with the
version number you want to install:

.. code:: shell

   $ kubectl apply \
        -f https://raw.githubusercontent.com/jetstack/cert-manager/${VERSION}/deploy/manifests/00-crds.yaml

   # Ensure resource validation is disabled on the cert-manager namespace
   $ kubectl label namespace cert-manager certmanager.k8s.io/disable-validation=true

   $ kubectl apply \
        -f https://raw.githubusercontent.com/jetstack/cert-manager/${VERSION}/deploy/manifests/cert-manager.yaml

.. toctree::
   :maxdepth: 1

   upgrading-0.2-0.3
   upgrading-0.3-0.4
   upgrading-0.4-0.5
   upgrading-0.5-0.6

.. _`official Helm charts repository`: https://github.com/helm/charts
.. _`static deployment manifests`: https://github.com/jetstack/cert-manager/blob/master/contrib/manifests/cert-manager
