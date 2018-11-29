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

#. Ensure upgrading document exists in docs/admin/upgrading

#. Create a new release branch (e.g. ```release-0.5```)

#. Push it to the ```jetstack/cert-manager`` repository

#. Create a pull-request updating the Helm chart version and merge it:

   * Update contrib/charts/cert-manager/README.md
   * Update contrib/charts/cert-manager/Chart.yaml
   * Update contrib/charts/cert-manager/values.yaml
   * Update contrib/charts/cert-manager/requirements.yaml
   * Update contrib/charts/cert-manager/webhook/Chart.yaml
   * Update contrib/charts/cert-manager/webhook/values.yaml
   * Run ```helm dep update``` in the contrib/charts/cert-manager directory
   * Run ```./hack/update-deploy-gen.sh``` in the root of the repository
#. Gather release notes since the previous release:

   * Run ```relnotes -repo cert-manager -owner jetstack release-0.5```
   * Write up appropriate notes, similar to previous releases

#. Submit the Helm chart changes to the upstream ```helm/charts``` repo:

   .. code:: shell

      TARGET_REPO_REMOTE=upstream \
      SOURCE_REPO_REMOTE=upstream \
      SOURCE_REPO_REF=release-0.5 \
      GITHUB_USER=munnerz \
      ./hack/create-chart-pr.sh

#. Iterate on review feedback (hopefully this will be minimal) and submit
   changes to ```master``` of cert-manager, performing a rebase of release-x.y
   and re-run of the ```create-chart-pr.sh``` script after each cycle to gather
   more feedback.

#. Create a new tag taken from the release branch, e.g. ```v0.5.0```.

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

#. Create a PR against the **release branch** to bump the chart version:

   * Update contrib/charts/cert-manager/README.md
   * Update contrib/charts/cert-manager/Chart.yaml
   * Update contrib/charts/cert-manager/values.yaml
   * Update contrib/charts/cert-manager/requirements.yaml
   * Update contrib/charts/cert-manager/webhook/Chart.yaml
   * Update contrib/charts/cert-manager/webhook/values.yaml
   * Run ```helm dep update``` in the contrib/charts/cert-manager directory
   * Run ```./hack/update-deploy-gen.sh``` in the root of the repository

#. Submit the Helm chart changes to the upstream ```helm/charts``` repo:

   .. code:: shell

      TARGET_REPO_REMOTE=upstream \
      SOURCE_REPO_REMOTE=upstream \
      SOURCE_REPO_REF=release-0.5 \
      GITHUB_USER=munnerz \
      ./hack/create-chart-pr.sh

#. Iterate on review feedback (hopefully this will be minimal) and submit
   changes to ```master``` of cert-manager, performing a rebase of release-x.y
   and re-run of the ```create-chart-pr.sh``` script after each cycle to gather
   more feedback.

#. Gather release notes since the previous release:

   * Run ```relnotes -repo cert-manager -owner jetstack release-0.5```
   * Write up appropriate notes, similar to previous patch releases

#. Create a new tag taken from the release branch, e.g. ```v0.5.1```.
