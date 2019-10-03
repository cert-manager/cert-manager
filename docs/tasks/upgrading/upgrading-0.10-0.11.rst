=============================
Upgrading from v0.10 to v0.11
=============================

** NOTE: THIS UPGRADE GUIDE IS PROVISIONAL AND MAY NOT BE COMPLETE WHILST THE v0.11 RELEASE SERIES IS IN ALPHA**

The v0.11 release marks the removal of the v1alpha1 API that was used in
previous versions of cert-manager, as well as our API group changing to be
``cert-manager.io`` instead of ``certmanager.k8s.io``.

We have also removed support for the **old style config format** that was
deprecated in the v0.8 release. This means you **must** transition to using the
new ``solvers`` style configuration format for your ACME issuers **before**
upgrading to v0.11. For more information, see the
:doc:`upgrading to v0.8 </tasks/upgrading/upgrading-0.7-0.8>` guide.

This makes for a fairly significant breaking change for users, as **all**
cert-manager resources, or even Ingresses that reference cert-manager
resources, will need to be updated to reflect these changes.

This upgrade should be performed in a few steps:

1) Back up existing cert-manager resources, as per the
   :doc:`backup and restore guide <../backup-restore-crds>`.

2) Uninstall cert-manager (by running ``kubectl delete -f`` or ``helm delete --purge``)

3) Ensure the old cert-manager CRD resources have also been deleted: ``kubectl get crd | grep certmanager.k8s.io``

4) Update the apiVersion on all your backed up resources from
   ``certmanager.k8s.io/v1alpha1`` to ``cert-manager.io/v1alpha2``.

5) Re-install cert-manager from scratch according to the :doc:`getting started guide </getting-started/index>`.

You must be sure to properly **backup**, **uninstall**, **re-install** and
**restore** your installation in order to ensure the upgrade is successful.

Additional annotation changes
=============================

As well as changing the API group used by our CRDs, we have also changed the
annotation-based configuration key to **also** reflect the new API group.

This means that if you use any cert-manager annotations on any of your other
resources (such as Ingresses, {Validating,Mutating}WebhookConfiguration, etc)
you will need to update them to reflect the new API group.

A full table of annotations, including the old and new equivalents:

.. TODO: create a table mapping old annotations to new

You can use the following bash magic to print a list of Ingress resources that
still contain an old annotation:

.. code-block:: shell

   kubectl get ingress \
        --all-namespaces \
        -o json | \
        jq '.items[] | select(.metadata.annotations| to_entries | map(.key)[] | test("certmanager")) | "Ingress resource \(.metadata.namespace)/\(.metadata.name) contains old annotations: (\( .metadata.annotations | to_entries | map(.key)[] | select( . | test("certmanager") )  ))"'

   Ingress resource "demo/testcrt contains old annotations: (certmanager.k8s.io/cluster-issuer)"
   Ingress resource "example/ingress-resource contains old annotations: (certmanager.k8s.io/cluster-issuer)"

You should make sure to update _all_ Ingress resources to ensure that your
certificates continue to be kept up to date.
