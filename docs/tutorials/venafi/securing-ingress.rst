==============================
Securing Ingresses with Venafi
==============================

This guide walks you through how to secure a Kubernetes `Ingress`_ resource
using the Venafi Issuer type.

Whilst stepping through, you will learn how to:

* Create an EKS cluster using `eksctl`_.
* Install cert-manager into the EKS cluster
* Deploy `nginx-ingress`_ to expose applications running in the cluster
* Configure a Venafi Cloud issuer
* Configure cert-manager to secure your application traffic

While this guide focuses on EKS as a Kubernetes provisioner and Venafi
as a Certificate issuer, the steps here should be generally re-usable for other
Issuer types.

Prerequisites
=============

* An AWS account
* kubectl installed
* Access to a publicly registered DNS zone
* A Venafi Cloud account and API credentials

Create an EKS cluster
=====================

If you already have a running EKS cluster you can skip this step and move onto
deploying cert-manager.

eksctl_ is a tool that makes it easier to deploy and manage an EKS cluster.

Installation instructions for various platforms can be found in the
`eksctl installation instructions`_.

Once installed, you can create a basic cluster by running:

.. code-block:: shell

   eksctl create cluster

This process may take up to 20 minutes to complete.
Complete instructions on using eksctl can be found in the `eksctl usage section`_

Once your cluster has been created, you should verify that your cluster is
running correctly by running the following command:

.. code-block:: shell

   kubectl get pods --all-namespaces
   NAME                      READY   STATUS    RESTARTS   AGE
   aws-node-8xpkp            1/1     Running   0          115s
   aws-node-tflxs            1/1     Running   0          118s
   coredns-694d9447b-66vlp   1/1     Running   0          23s
   coredns-694d9447b-w5bg8   1/1     Running   0          23s
   kube-proxy-4dvpj          1/1     Running   0          115s
   kube-proxy-tpvht          1/1     Running   0          118s

You should see output similar to the above, with all pods in a Running state.

.. _eksctl: https://github.com/weaveworks/eksctl
.. _eksctl installation instructions: https://eksctl.io/introduction/installation/
.. _eksctl usage section: https://eksctl.io/usage/creating-and-managing-clusters/

Installing cert-manager
=======================

There are no special requirements to note when installing cert-manager on EKS,
so the regular
:doc:`Running on Kubernetes </getting-started/install/kubernetes>` guide can
be used to install cert-manager.

Please walk through the installation guide and return to this step once you
have validated cert-manager is deployed correctly.

Installing ingress-nginx
========================

A `Kubernetes ingress controller`_ is designed to be the access point for
HTTP and HTTPS traffic to the software running within your cluster. The
ingress-nginx_ controller does this by providing an HTTP proxy service
supported by your cloud provider's load balancer (in this case, a
`Network Load Balancer (NLB)`_.

You can get more details about nginx-ingress and how it works from the
`documentation for nginx-ingress`_.

To deploy ingress-nginx using an ELB to expose the service, run the following:

.. code-block:: shell

   # Deploy the AWS specific pre-requisite manifest
   kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/master/deploy/static/provider/aws/service-nlb.yaml

   # Deploy the 'generic' ingress-nginx manifest
   kubectl apply -f https://raw.githubusercontent.com/kubernetes/ingress-nginx/master/deploy/static/mandatory.yaml

You may have to wait up to 5 minutes for all the required components in your
cluster and AWS account to become ready.

You can run the following command to determine the address that Amazon has
assigned to your NLB:

.. code-block:: shell

   kubectl get service -n ingress-nginx
   NAME            TYPE           CLUSTER-IP      EXTERNAL-IP                                                                     PORT(S)                      AGE
   ingress-nginx   LoadBalancer   10.100.52.175   a8c2870a5a8a311e9a9a10a2e7af57d7-6c2ec8ede48726ab.elb.eu-west-1.amazonaws.com   80:31649/TCP,443:30567/TCP   4m10s

The *EXTERNAL-IP* field may say ``<pending>`` for a while. This indicates the
NLB is still being created. Retry the command until an *EXTERNAL-IP* has been
provisioned.

Once the *EXTERNAL-IP* is available, you should run the following command to
verify that traffic is being correctly routed to ingress-nginx:

.. code-block:: shell

   curl http://a8c2870a5a8a311e9a9a10a2e7af57d7-6c2ec8ede48726ab.elb.eu-west-1.amazonaws.com/

   <html>
   <head><title>404 Not Found</title></head>
   <body>
   <center><h1>404 Not Found</h1></center>
   <hr><center>openresty/1.15.8.1</center>
   </body>
   </html>

Whilst the above message would normally indicate an error (the page not being
found), in this instance it indicates that traffic is being correctly routed to
the ingress-nginx service.

.. note::
   Although the AWS Application Load Balancer (ALB) is a modern load balancer
   offered by AWS that can can be be provisioned from within EKS, at the time
   of writing, the `alb-ingress-controller <https://github.com/kubernetes-sigs/aws-alb-ingress-controller>`_;
   is only capable of serving sites using certificates stored in AWS Certificate
   Manager (ACM). Version 1.15 of Kubernetes should address multiple bug fixes
   for this controller and allow for TLS termination support.

.. _`kubernetes ingress controller`: https://kubernetes.io/docs/concepts/services-networking/ingress/
.. _`documentation for nginx-ingress`: https://kubernetes.github.io/ingress-nginx/
.. _Network Load Balancer (NLB): https://docs.aws.amazon.com/elasticloadbalancing/latest/network/introduction.html

==========================
Configure your DNS records
==========================

Now that our NLB has been provisioned, we should point our application's DNS
records at the NLBs address.

Go into your DNS provider's console and set a CNAME record pointing to your
NLB.

For the purposes of demonstration, we will assume in this guide you have
created the following DNS entries:

.. code-block::

   www.example.com CNAME a8c2870a5a8a311e9a9a10a2e7af57d7-6c2ec8ede48726ab.elb.eu-west-1.amazonaws.com
   example.com CNAME a8c2870a5a8a311e9a9a10a2e7af57d7-6c2ec8ede48726ab.elb.eu-west-1.amazonaws.com

As you progress through the rest of this tutorial, please replace these
domain names with your own registered domain.

============================
Deploying a demo application
============================

For the purposes of this demo, we provide an example deployment which is a
simple "hello world" website.

First, create a new namespace that will contain your application:

.. code-block:: shell

   kubectl create namespace demo
   namespace/demo created

Save the following YAML into a file named ``demo-deployment.yaml``:

.. code-block:: yaml
   :linenos:

   ---
   apiVersion: v1
   kind: Service
   metadata:
     name: hello-kubernetes
     namespace: demo
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
     namespace: demo
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

Then run:

.. code-block:: shell

   kubectl apply -n demo -f demo-deployment.yaml

Note that the Service resource we deploy is of type ClusterIP and not
LoadBalancer, as we will expose and secure traffic for this service using
ingress-nginx that we deployed earlier.

You should be able to see two Pods and one Service in the ``demo`` namespace:

.. code-block:: shell

   kubectl get po,svc
   NAME                                READY   STATUS    RESTARTS   AGE
   hello-kubernetes-66d45d6dff-m2lnr   1/1     Running   0          7s
   hello-kubernetes-66d45d6dff-qt2kb   1/1     Running   0          7s

   NAME                       TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE
   service/hello-kubernetes   ClusterIP   10.100.164.58   <none>        80/TCP    7s

Note that we have not yet exposed this application to be accessible over the
internet. We will expose the demo application to the internet in later steps.

=================================
Creating a Venafi Issuer resource
=================================

You can sign up for a Venafi Cloud account by visiting the `enroll page`_.

Once registered, you should fetch your API key by clicking your name in the top
right of the control panel interface.

In order for cert-manager to be able to authenticate with your Venafi Cloud
account and set up a ClusterIssuer resource, you'll need to create a Kubernetes
Secret containing your API key:

.. code-block:: secret
   kubectl create secret generic \
     venafi-cloud-secret \
     --namespace=demo \
     --from-literal=apikey=<API_KEY>

We must then create a Venafi Issuer resource, which represents a certificate
authority within Kubernetes.

Save the following YAML into a file named ``venafi-issuer.yaml``:

.. code-block:: yaml
   :linenos:

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Issuer
   metadata:
     name: cloud-venafi-issuer
     namespace: demo
   spec:
     venafi:
       zone: "Default" # Set this to the Venafi policy zone you want to use
       cloud:
         url: "https://api.venafi.cloud/v1"
         apiTokenSecretRef:
           name: venafi-cloud-secret
           key: apikey

Then run:

.. code-block:: shell

   kubectl apply -f venafi-issuer.yaml

When you run the following command, you should see that the Status stanza of
the output shows that the Issuer is Ready (i.e. has successfully validated
itself with the Venafi Cloud service).

.. code-block:: shell

   kubectl describe issuer -n demo cloud-venafi-issuer

   Status:
     Conditions:
       Last Transition Time:  2019-07-17T15:46:00Z
       Message:               Venafi issuer started
       Reason:                Venafi issuer started
       Status:                True
       Type:                  Ready
   Events:
     Type    Reason  Age   From          Message
     ----    ------  ----  ----          -------
     Normal  Ready   14s   cert-manager  Verified issuer with Venafi server


.. _enroll page: https://ui.venafi.cloud/enroll

=====================
Request a Certificate
=====================

Now that the Issuer is configured and we have confirmed it has been set up
correctly, we can begin requesting certificates which can be used by Kubernetes
applications.

Full information on how to specify and request Certificate resources can be
found in the :doc:`Issuing certificates </tasks/issuing-certificates/index>`
guide.

For now, we will create a basic x509 Certificate that is valid for our two
domains, ``example.com`` and ``www.example.com``:

.. code-block:: yaml
   :linenos:

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Certificate
   metadata:
     name: example-com-tls
     namespace: demo
   spec:
     secretName: example-com-tls
     dnsNames:
     - example.com
     - www.example.com
     issuerRef:
       name: cloud-venafi-issuer

Save this YAML into a file named ``example-com-tls.yaml`` and run:

.. code-block:: shell

   kubectl apply -f example-com-tls.yaml

======================================
Exposing and securing your application
======================================

Now that we have configured an Issuer resource for Venafi Cloud,

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

As long as you've ensured that the zone of your Venafi Cloud account (in our
example, we use the "Default" zone) has been configured with a CA or contains a
custom certificate, cert-manager can now take steps to populate the
``venafi-cert-tls`` Secret with a certificate. It does this by identifying
itself with Venafi Cloud using the API key, then requesting a certificate to
match the specifications of the Certificate resource that we've created.