===========================
Upgrading from v0.5 to v0.6
===========================

.. warning::
   If you are upgrading from a release older than v0.5, please read the
   `Upgrading from older versions using Helm`_ note at the bottom of this
   document!

The upgrade process from v0.5 to v0.6 should be fairly seamless for most users.
As part of the new release, we have changed how we ship the
CustomResourceDefinition resources that cert-manager needs in order to operate
(as well as introducing two **new** CRD types).

Depending on the way you have installed cert-manager in the past, your upgrade
process will slightly vary:

Upgrading with the Helm chart
=============================

If you have previously deployed cert-manager v0.5 using the Helm installation
method, you will now need to perform one extra step before upgrading.

Due to issues with the way Helm handles CRD resources in Helm charts, we have
now moved the installation of these resources into a separate YAML manifest
that must be installed with ``kubectl apply`` before upgrading the chart.

You can follow the :doc:`regular upgrade guide <./index>` as
usual in order to upgrade from v0.5 to v0.6.

Upgrading with static manifests
===============================

The static manifests have moved into the ``deploy/manifests`` directory for
this release.

We now also no longer ship different manifests for different configurations, in
favour of a single ``cert-manager.yaml`` file which should work for all
Kubernetes clusters from Kubernetes v1.9 onwards.

You can follow the :doc:`regular upgrade guide <./index>` as
usual in order to upgrade from v0.5 to v0.6.

Upgrading from older versions using Helm
========================================

If you are upgrading from a version **older than v0.5** and
**have installed with Helm**, you will need to perform a fresh installation of
cert-manager due to issues with the Helm upgrade process.
This will involve the **removal of all cert-manager custom resources**.
This **will not** delete the Secret resources being used by your apps.

Before upgrading you will need to:

1. Read and follow the :doc:`backup guide <../backup-restore-crds>` to create a
   backup of your configuration.

2. Delete the existing cert-manager Helm release (replacing 'cert-manager' with
   the name of your Helm release):

.. code-block:: shell

   # Uninstall the Helm chart
   $ helm delete --purge cert-manager

   # Ensure the cert-manager CustomResourceDefinition resources do not exist:
   $ kubectl delete crd \
       certificates.certmanager.k8s.io \
       issuers.certmanager.k8s.io \
       clusterissuers.certmanager.k8s.io

3. Perform a fresh install (as per the
   :doc:`installation guide </getting-started/index>`):

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
        --version v0.6.6 \
        stable/cert-manager

4. Follow the steps in the :doc:`restore guide <../backup-restore-crds>` to
   restore your configuration.

5. Verify that your Issuers and Certificate resources are 'Ready':

.. code-block:: shell

   $ kubectl get clusterissuer,issuer,certificates --all-namespaces
   NAMESPACE      NAME                               READY   SECRET                             AGE
   cert-manager   cert-manager-webhook-ca            True    cert-manager-webhook-ca            1m
   cert-manager   cert-manager-webhook-webhook-tls   True    cert-manager-webhook-webhook-tls   1m
   example-com    example-com-tls                    True    example-com-tls                    11s
