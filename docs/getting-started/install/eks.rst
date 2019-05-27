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
      --nodegroup-name ng-1 \
       --node-type t3.medium \
        --nodes 2 --nodes-min 1 --nodes-max 3 --node-ami auto

Alternatively, an `eksctl config file <https://github.com/weaveworks/eksctl#using-config-files>`_ can be written in YAML and passed to eksctl.

Before you can install cert-manager, you should first ensure that your local ``kubectl``
is configured to talk to your EKS cluster.

=================
Installing on EKS
=================

EKS is designed to allow applications to be fully compatible with any standard Kubernetes environment. Therefore, installing cert-manager on an EKS doesn't require any deviation from the :doc:`Running on Kubernetes <./kubernetes>` installation guide.

====================
Issues unique to AWS
====================

When a Kubernetes Service with LoadBalancer type is created in an EKS cluster, the default behaviour of EKS is to provision an Elastic Load Balancer (ELB). Unfortunately, this comes with a number of limitations, one of which is cost (ELBs are charged hourly). In order to prevent EKS from creating a number of ELBs (one for each LoadBalancer Service), we can expose a single nginx LoadBalancer Service to the outside world, and have this Service forward requests to our cluster's applications.

NOTE: A more recent, and more capable, load balancer is the AWS Application Load Balancer (ALB), which can be provisioned from within EKS using the `alb-ingress-controller <https://github.com/kubernetes-sigs/aws-alb-ingress-controller>`_. Currently this controller requires `an annotation <https://kubernetes-sigs.github.io/aws-alb-ingress-controller/guide/ingress/annotation/#ssl>`_ for specifying a certificate stored in AWS Certificate Manager (ACM). Additionally, the AWS ALB controller currently requires granting the cluster a number of IAM permissions/roles. Version 1.15 of Kubernetes should address multiple bug fixes for this controller and allow for TLS termination support.

=======
Example
=======



.. code-block:: yaml
   :linenos:

   apiVersion: extensions/v1beta1
   kind: Ingress
   metadata:
     name: frontend-ing
     namespace: hello-kubernetes-ns
     annotations:
       kubernetes.io/ingress.class: "nginx"
       certmanager.k8s.io/cluster-issuer:    "letsencrypt-staging"
   spec:
     tls:
     - hosts:
       - www.<host-name>
       secretName: certsecret-tls
     rules:
     - host: www.<host-name>
       http:
         paths:
         - path: /
           backend:
             serviceName: hello-kubernetes
             servicePort: 80

======================
Register a certificate
======================

For this tutorial we'll use Venafi Cloud as a `ClusterIssuer` resource.

Signing up to Venafi is straightforward - follow the guide.

Cert-manager is able to request a certificate, but requires an apikey to authenticate itself with the Venafi Cloud account. This API key should be stored as a Kubernetes Secret.

##### Notes

Had some issues with the using Venafi: specifically getting 404s when trying to register a ClusterIssuer resource.

Have tested it using a LetsEncrypt certificate and it works fine. Think this example would be more useful with an example of a different issuer e.g. Venafi

TLS certificate auto-discovery / multiple TLS certificate support not there yet
