.. cert-manager documentation master file, created by
   sphinx-quickstart on Sat Mar 24 10:03:16 2018.
   You can adapt this file completely to your liking, but it should at least
   contain the root `toctree` directive.

========================================
Welcome to cert-manager's documentation!
========================================

cert-manager is a native Kubernetes_ certificate management controller.
It can help with issuing certificates from a variety of sources, such as
`Let's Encrypt`_, `HashiCorp Vault`_ or a simple signing keypair.

It will ensure certificates are valid and up to date, and attempt to renew
certificates at a configured time before expiry.

It is loosely based upon the work of kube-lego_ and has borrowed some wisdom
from other similar projects e.g. kube-cert-manager_.

.. image:: images/high-level-overview.png
   :align: center

This is the full technical documentation for the project, and should be used as
a source of references when seeking help with the project.

.. toctree::
   :maxdepth: 5
   :titlesonly:
   :caption: Contents:

   getting-started/index
   tutorials/index
   admin/index
   reference/index
   devel/index

.. _Kubernetes: https://kubernetes.io
.. _kube-lego: https://github.com/jetstack/kube-lego
.. _kube-cert-manager: https://github.com/PalmStoneGames/kube-cert-manager
.. _`Let's Encrypt`: https://letsencrypt.org
.. _`HashiCorp Vault`: https://www.vaultproject.io
