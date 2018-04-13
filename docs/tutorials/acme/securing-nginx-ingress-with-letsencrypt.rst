=========================================
Securing nginx-ingress with Let's Encrypt
=========================================

This guide talks you through securing a website exposed with `nginx-ingress`_
using a Certificate issued by `Let's Encrypt`_.

Prerequisites
=============

First, you should make sure you have properly configured and deployed
`nginx-ingress`_ and at least one service is available **publicly** via the
ingress controllers external IP address.

There's official deployment documentation in the `official repository`__, or you
can alternatively use Helm_ to deploy and manage your nginx-ingress_
installation.

.. __:
.. _nginx-ingress: https://github.com/kubernetes/ingress-nginx
.. _`Let's Encrypt`: https://letsencrypt.org
.. _Helm: https://helm.sh
