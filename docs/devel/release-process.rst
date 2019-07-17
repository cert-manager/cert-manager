===============
Release process
===============

This document aims to outline the process that should be followed for cutting a
new release of cert-manager.

Minor releases
==============

A minor release is a backwards-compatible 'feature' release.
It can contain new features and bugfixes.

Release schedule
----------------

We aim to cut a new minor release once per month.
The rough goals for each release are outlined as part of a GitHub milestone.
We cut a release even if some of these goals are missed, in order to keep up
release velocity.

Process
-------

.. note::
   This process document is WIP and may be incomplete

The process for cutting a minor release is as follows:

#. Ensure upgrading document exists in docs/tasks/upgrading

#. Ensure all strings of versions have been updated:

   * deploy/charts/cert-manager/README.md
   * docs/getting-started/install/kubernetes.rst
   * docs/getting-started/install/openshift.rst
   * docs/getting-started/webhook.rst
   * docs/tutorials/acme/quick-start/index.rst
#. Create a new release branch (e.g. ```release-0.5```)

#. Push it to the ```jetstack/cert-manager`` repository

#. Gather release notes since the previous release:

   * Download, install and run the latest version of release-notes:

.. code::

     * $ go get k8s.io/release; go install $GOPATH/src/k8s.io/release/cmd/release-notes/.
     * $ mkdir -p design/release-notes/release-*X.Y*
     * $ export GITHUB_TOKEN=*your-token*
     * $ $GOPATH/bin/release-notes -release-version v*X.Y* -github-repo cert-manager -github-org jetstack -requiredAuthor "" -start-sha=$(git rev-parse *X.Y-1.0*) -end-sha=$(git rev-parse HEAD) -output design/release-notes/release-*X.Y*/draft-release-notes.md
     * # Add additional blurb, notable items and characterise Changelog.

Finally, create a new tag taken from the release branch, e.g. ```v0.5.0```.

Patch releases
==============

A patch release contains critical bugfixes for the project.
They are managed on an ad-hoc basis, and should only be required when critical
bugs/regressions are found in the release.

We will only perform patch release for the **current** version of cert-manager.

Once a new minor release has been cut, we will stop providing patches for the
version before it.

Release schedule
----------------

Patch releases are cut on an ad-hoc basis, depending on recent activity on the
release branch.

Process
-------

.. note::
   This process document is WIP and may be incomplete

Bugs that need to be fixed in a patch release should be cherry picked into the
appropriate release branch using the ```./hack/cherry-pick-pr.sh``` script in
this repository.

The process for cutting a patch release is as follows:

#. Ensure all strings of versions have been updated:

   * deploy/charts/cert-manager/README.md
   * docs/getting-started/install/kubernetes.rst
   * docs/getting-started/install/openshift.rst
   * docs/getting-started/webhook.rst
   * docs/tutorials/acme/quick-start/index.rst
#. Iterate on review feedback (hopefully this will be minimal) and submit
   changes to ```master``` of cert-manager, performing a rebase of release-x.y.

#. Gather release notes since the previous release:

.. code::

     * $ go get k8s.io/release; go install $GOPATH/src/k8s.io/release/cmd/release-notes/.
     * $ mkdir -p design/release-notes/release-*X.Y*
     * $ export GITHUB_TOKEN=*your-token*
     * $ $GOPATH/bin/release-notes -release-version v*X.Y* -github-repo cert-manager -github-org jetstack -requiredAuthor "" -start-sha=$(git rev-parse *X.Y.Z-1*) -end-sha=$(git rev-parse release-*X.Y*) -output design/release-notes/release-*X.Y*/draft-release-notes-*Z*.md
     * # Add additional blurb, notable items and characterise Changelog.

Finally, create a new tag taken from the release branch, e.g. ```v0.5.1```.
