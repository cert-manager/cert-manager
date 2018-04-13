==============================
1. Configuring Helm and Tiller
==============================

Before deploying cert-manager, you must ensure Tiller_ is up and running in
your cluster. Tiller is the server side component to Helm.

Your cluster administrator may have already setup and configured Helm for you,
in which case you can skip this step.

Full documentation on installing Helm can be found in the `Installing helm docs`_.

If your cluster has RBAC (Role Based Access Control) enabled (default in GKE
v1.7+), you will need to take special care when deploying Tiller, to ensure
Tiller has permission to create resources as a cluster administrator. More
information on deploying Helm with RBAC can be found in the `Helm RBAC docs`_.

.. _`helm RBAC docs`: https://github.com/kubernetes/helm/blob/master/docs/rbac.md
.. _`installing helm docs`: https://github.com/kubernetes/helm/blob/master/docs/install.md
.. _Tiller: https://github.com/kubernetes/helm
