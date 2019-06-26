=======================
Installing on EKS
=======================

Create an EKS cluster
=====================

The easiest way to deploy and interact with an EKS cluster is to install
 `eksctl <https://eksctl.io/>`_. This allows you to create an EKS cluster using 
CLI flags. Alternatively, an `eksctl config file <https://github.com/weaveworks/eksctl#using-config-files>`_ 
can be written in YAML and passed to eksctl.

Before you can install cert-manager, you should first ensure that your local
 ``kubectl`` is configured to talk to your EKS cluster.

=================
Installing on EKS
=================

EKS is designed to allow applications to be fully compatible with any standard 
Kubernetes environment. Therefore, installing cert-manager on an EKS cluster doesn't  require any deviation from the
 :doc:`Running on Kubernetes <./kubernetes>` installation guide.

====================
Issues unique to AWS
====================

When a Kubernetes Service with LoadBalancer type is created in an EKS cluster, 
the default behaviour of EKS is to provision an Elastic Load Balancer (ELB). 
Unfortunately, this comes with a number of limitations, one of which is cost 
(ELBs are charged hourly). In order to prevent EKS from creating a number of 
LoadBalancers, we can expose a single LoadBalancer Service to the outside world,
 and have this Service forward requests to our cluster's applications.

This demonstration uses the NGINX Ingress Controller (installation guide 
`here<https://kubernetes.github.io/ingress-nginx/deploy/>`_;), which can be 
`configured to provision a Network Load Balancer (NLB)
 <https://raw.githubusercontent.com/kubernetes/ingress-nginx/master/deploy/static/provider/aws/service-nlb.yaml>`_; 
as opposed to an Elastic Load Balancer (ELB). Therefore, the first hop from the
 end user is to the NLB, which then does a passthrough to the NGINX Ingress 
Controller.

.. note:: 
   Although the AWS Application Load Balancer (ALB) is a modern load balancer 
   offered by AWS that can can be be provisioned from within EKS, at the time 
   of writing, the `alb-ingress-controller <https://github.com/kubernetes-sigs/aws-alb-ingress-controller>`_; 
   is only capable of serving sites using certificates stored in AWS Certificate 
   Manager (ACM). Version 1.15 of Kubernetes should address multiple bug fixes 
   for this controller and allow for TLS termination support.

==========================
Configure your DNS records
==========================

Once AWS has provisioned a Network Load Balancer, you're provided with an IPv4 
address to which you can point a CNAME DNS record:

.. code-block:: shell
   kubectl -n ingress-nginx get svc

It will take several minutes for the Load Balancer to be provisioned and for 
the DNS records to propagate.

===================================
Creating the cert-manager resources
===================================

Signing up to Venafi is straightforward - follow the guide provided 
:doc:`here <../../tasks/issuers/setup-venafi.rst>`.

For this tutorial we'll use Venafi Cloud as a `ClusterIssuer` resource.

In order for cert-manager to be able to authenticate with your Venafi Cloud 
account and set up a ClusterIssuer resource, you'll need to create a Kubernetes 
Secret containing your API key:

.. code-block:: secret
   kubectl create secret generic \
     venafi-cloud-secret \
     --namespace=cert-manager \
     --from-literal=apikey=<API_KEY>

.. code-block:: yaml
   :linenos:

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: ClusterIssuer
   metadata:
     name: cloud-venafi-issuer
   spec:
     venafi:
       zone: "Default" # Set this to the Venafi policy zone you want to use
       cloud:
         url: "https://api.venafi.cloud/v1"
         apiTokenSecretRef:
           name: venafi-cloud-secret
           key: apikey

When you run the following command, you should see that the Status stanza of 
the output shows that the Issuer is Ready (i.e. has successfully validated 
itself with the Venafi Cloud service).

.. code-block:: shell
   kubectl describe clusterissuer cloud-venafi-issuer

.. code-block:: yaml
   Status:
     Conditions:
       Last Transition Time:  2019-06-07T09:33:35Z
       Message:               Venafi issuer started
       Reason:                Venafi issuer started
       Status:                True
       Type:                  Ready

The ClusterIssuer is referenced in the ``spec.issuerRef`` field of the example
Certificate resource below:

.. code-block:: yaml
   :linenos:

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Certificate
   metadata:
     name: venafi-cert
   spec:
     secretName: venafi-cert-tls
     duration: 2160h # 90d
     renewBefore: 360h # 15d
     commonName: <host-name>
     dnsNames:
     - <host-name>
     issuerRef:
       name: cloud-venafi-issuer
       kind: ClusterIssuer

As long as you've ensured that the zone of your Venafi Cloud account (in our 
example, we use the "Default" zone) has been configured with a CA or contains a 
custom certificate, cert-manager can now take steps to populate the 
``venafi-cert-tls`` Secret with a certificate. It does this by identifying 
itself with Venafi Cloud using the API key, then requesting a certificate to 
match the specifications of the Certificate resource that we've created.

==================
Example Deployment
==================

Below is a demo deployment that serves a simple "hello world" website. The 
Service is of type ClusterIP, not LoadBalancer, as we only wish to provision a 
Network Load Balancer for the NGINX Ingress Controller.

.. code-block:: yaml
   :linenos:

   ---
   apiVersion: v1
   kind: Service
   metadata:
     name: hello-kubernetes
   spec:
     type: ClusterIP
     ports:
     - port: 80
       targetPort: 8080
     selector:
       app: hello-kubernetes
   ---
   apiVersion: apps/v1
   kind: Deployment
   metadata:
     name: hello-kubernetes
   spec:
     replicas: 2
     selector:
       matchLabels:
         app: hello-kubernetes
     template:
       metadata:
         labels:
           app: hello-kubernetes
       spec:
         containers:
         - name: hello-kubernetes
           image: paulbouwer/hello-kubernetes:1.5
           resources:
             requests:
               cpu: 100m
               memory: 100Mi
           ports:
           - containerPort: 8080

===============
Example Ingress
===============

You will also need to configure the NGINX Deployment to ensure that it is 
correctly labelled to perform routing to this service.

.. code-block:: yaml
   :linenos:

   apiVersion: extensions/v1beta1
   kind: Ingress
   metadata:
     name: frontend-ingress
     namespace: hello-kubernetes-ns
     annotations:
       kubernetes.io/ingress.class: "nginx"
   spec:
     tls:
     - hosts:
       - <host-name>
       secretName: venafi-cert-tls
     rules:
     - host: <host-name>
       http:
         paths:
         - path: /
           backend:
             serviceName: hello-kubernetes
             servicePort: 80
