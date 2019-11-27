=============================
Upgrading from v0.10 to v0.11
=============================

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

2) :doc: `Uninstall cert-manager`<../uninstalling/index>`.

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

+----------------------------------------------+-------------------------------------------+
| Old Annotation                               | New Annotation                            |
+----------------------------------------------+-------------------------------------------+
| certmanager.k8s.io/acme-http01-edit-in-place | acme.cert-manager.io/http01-edit-in-place |
+----------------------------------------------+-------------------------------------------+
| certmanager.k8s.io/acme-http01-ingress-class | acme.cert-manager.io/http01-ingress-class |
+----------------------------------------------+-------------------------------------------+
| certmanager.k8s.io/issuer                    | cert-manager.io/issuer                    |
+----------------------------------------------+-------------------------------------------+
| certmanager.k8s.io/cluster-issuer            | cert-manager.io/cluster-issuer            |
+----------------------------------------------+-------------------------------------------+
| certmanager.k8s.io/acme-challenge-type       | DEPRECIATED                               |
+----------------------------------------------+-------------------------------------------+
| certmanager.k8s.io/acme-dns01-provider       | DEPRECIATED                               |
+----------------------------------------------+-------------------------------------------+
| certmanager.k8s.io/alt-names                 | cert-manager.io/alt-names                 |
+----------------------------------------------+-------------------------------------------+
| certmanager.k8s.io/ip-sans                   | cert-manager.io/ip-sans                   |
+----------------------------------------------+-------------------------------------------+
| certmanager.k8s.io/common-name               | cert-manager.io/common-name               |
+----------------------------------------------+-------------------------------------------+
| certmanager.k8s.io/issuer-name               | cert-manager.io/issuer-name               |
+----------------------------------------------+-------------------------------------------+
| certmanager.k8s.io/issuer-kind               | cert-manager.io/issuer-kind               |
+----------------------------------------------+-------------------------------------------+

You can use the following bash magic to print a list of Ingress resources that
still contain an old annotation:

.. code-block:: shell

   kubectl get ingress \
        --all-namespaces \
        -o json | \
        jq '.items[] | select(.metadata.annotations| to_entries | map(.key)[] | test("certmanager")) | "Ingress resource \(.metadata.namespace)/\(.metadata.name) contains old annotations: (\( .metadata.annotations | to_entries | map(.key)[] | select( . | test("certmanager") )  ))"'

   Ingress resource "demo/testcrt contains old annotations: (certmanager.k8s.io/cluster-issuer)"
   Ingress resource "example/ingress-resource contains old annotations: (certmanager.k8s.io/cluster-issuer)"

In order to help with this migration, the following CLI tool will automatically
migrate these annotations for you. Note that it *will not* make any changes to
your cluster for you.

.. code-block:: shell

   # Firstly, download the binary for your given platform
   $ wget -O api-migration https://github.com/jetstack/cert-manager/releases/download/v0.11.1/api-migration-linux
   # or for Darwin
   $ wget -O api-migration https://github.com/jetstack/cert-manager/releases/download/v0.11.1/api-migration-darwin

   # Mark the binary as executable and run the binary against your cluster
   $ chmod +x api-migration && ./api-migration --kubeconfig /path/to/my/kubeconfig.yaml

   # Follow the CLI ouput and check for the difference that has been made in files
   $ diff ingress.yaml ingress-migrated.yaml

   # Finally, once the new ingress resources have been reviewed, apply the manifests
   $ kubectl apply -f ingress-migrated.yaml --kubeconfig /path/to/my/kubeconfig.yaml

You should make sure to update _all_ Ingress resources to ensure that your
certificates continue to be kept up to date.
