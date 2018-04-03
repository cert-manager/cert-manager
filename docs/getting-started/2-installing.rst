==========================
2. Installing cert-manager
==========================

With Helm
==========

Using Helm is the recommended way to deploy cert-manager. We publish a stable
version of the chart to the public `charts repository`_.

You can install the chart with the following command:

.. code-block:: none

    $ helm install \
        --name cert-manager \
        --namespace kube-system \
        stable/cert-manager

**NOTE**: if your cluster does not use RBAC (Role Based Access Control), you
will need to disable creation of RBAC resources by adding
``--set rbac.create=false`` to your ``helm install`` command above.

The default cert-manager configuration is good for the majority of users, but a
full list of the available options can be found in the `Helm chart README`_.

With static manifests
=====================

As some users may not be able to run Tiller in their own environment, static
Kubernetes deployment manifests are provided which can be used to install
cert-manager.

You can get a copy of the static manifests from the `deploy directory`_.

.. TODO: expand this to include a 'kubectl apply' example

.. _`charts repository`: https://github.com/kubernetes/charts
.. _`Helm chart README`: https://github.com/kubernetes/charts/blob/master/stable/cert-manager/README.md
.. _`deploy directory`: https://github.com/jetstack/cert-manager/blob/master/contrib/manifests/cert-manager
