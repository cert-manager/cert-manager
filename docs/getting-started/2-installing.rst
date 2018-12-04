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
        -f https://raw.githubusercontent.com/jetstack/cert-manager/v0.6.0/deploy/manifests/00-crds.yaml

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

   # Install the cert-manager CRDs
   $ kubectl apply \
        -f https://raw.githubusercontent.com/jetstack/cert-manager/v0.6.0/deploy/manifests/00-crds.yaml

   # Install cert-manager
   $ kubectl apply \
        -f https://raw.githubusercontent.com/jetstack/cert-manager/v0.6.0/deploy/manifests/cert-manager.yaml

.. _`charts repository`: https://github.com/kubernetes/charts
.. _`Helm chart README`: https://github.com/kubernetes/charts/blob/master/stable/cert-manager/README.md
.. _`deploy directory`: https://github.com/jetstack/cert-manager/blob/master/contrib/manifests/cert-manager
