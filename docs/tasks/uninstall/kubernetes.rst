==========================
Uninstalling on Kubernetes
==========================

Below is the processes for uninstalling cert-manager on Kubernetes. There are
two processes to chose depending on which method you used to install
cert-manager - static manifests or ``helm``.

.. warning::

   To uninstall cert-manger you should always use the same process for installing
   but in reverse. Deviating from the following process whether cert-manager has
   been installed from static manifests or helm can cause issues and
   potentially broken states. Please ensure you follow the below steps when
   uninstalling to prevent this happening.

Before continuing, ensure that all cert-manager resources that have been created
by users have been deleted. You can check for any existing resources with the
following command:

.. code-block:: shell

   kubectl get Issuers,ClusterIssuers,Certificates,CertificateRequests,Orders,Challenges --all-namespaces

O nce all these resources have been deleted you are ready to uninstall
cert-manager using the procedure determined by how you installed.

Uninstalling with regular manifests
===================================

Uninstalling from an installation with regular manifests is a case of running
the installation process, *in reverse*, using the delete command of ``kubectl``.

Delete the installation manifests using a link to your currently running
version vX.Y.Z like so:

.. code-block:: shell

   kubectl delete -f https://github.com/jetstack/cert-manager/releases/download/vX.Y.Z/cert-manager.yaml

Uninstalling with Helm
======================

Uninstalling cert-manager from a ``helm`` installation is a case of running the
installation process, *in reverse*, using the delete command on both ``kubectl``
and ``helm``.

Firstly, delete the cert-manager installation using ``helm``. Ensure the
``--purge`` flag is applied.

.. code-block:: shell

   helm delete cert-manager --purge

Next, delete the cert-manager namespace:

.. code-block:: shell

   kubectl delete namespace cert-manager

Finally, delete the cert-manger `CustomResourceDefinitions`_ using the link to
the version vX.Y you installed:

.. code-block:: shell

   kubectl delete -f https://raw.githubusercontent.com/jetstack/cert-manager/release-X.Y/deploy/manifests/00-crds.yaml

Namespace Stuck in Terminating State
====================================

If the namespace has been marked for deletion without deleting the cert-manager
installation first, the namespace may become stuck in a terminating state. This
is typically due to the fact that the `APIService`_ resource still exists
however the webhook is no longer running so is no longer reachable. To resolve
this, ensure you have run the above commands correctly, and if you're still
experiencing issues then run ``kubectl delete apiservice v1beta1.webhook.cert-manager.io``.

.. _`CustomResourceDefinitions`: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/
.. _`APIService`: https://kubernetes.io/docs/tasks/access-kubernetes-api/setup-extension-api-server
