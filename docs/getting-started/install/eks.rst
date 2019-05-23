=======================
Installing on EKS
=======================

Create an EKS cluster
=====================

The easiest way to deploy and interact with an EKS cluster is to install `eksctl <https://eksctl.io/>`_. 

This allows you to create an EKS cluster using CLI flags:

.. code-block:: shell

    eksctl create cluster --name ekscluster \
     --region eu-west-1 --version 1.12 \
      --nodegroup-name standard-workers \
       --node-type t3.medium \
        --nodes 2 --nodes-min 1 --nodes-max 3 --node-ami auto

Alternatively, an `eksctl config file <https://github.com/weaveworks/eksctl#using-config-files>`_ can be written in YAML and passed to eksctl.

Before you can install cert-manager, you must first ensure your local machine
is configured to talk to your EKS cluster using the ``eksctl`` tool.

=======================
Installing on EKS
=======================

EKS is designed to allow applications to be fully compatible with applications running on any standard Kubernetes environment, no deviation from the :doc:`Running on Kubernetes <./kubernetes>` installation guide should be necessary to install cert-manager.