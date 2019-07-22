==============================
Securing Ingresses with Venafi
==============================

This guide walks you through how to secure a Kubernetes `Ingress`_ resource
using the Venafi Issuer type.

Whilst stepping through, you will learn how to:

* Create an EKS cluster using `eksctl`_
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
   offered by AWS that can can be provisioned from within EKS, at the time of
   writing, the `alb-ingress-controller <https://github.com/kubernetes-sigs/aws-alb-ingress-controller>`_;
   is only capable of serving sites using certificates stored in AWS Certificate
   Manager (ACM). Version 1.15 of Kubernetes should address multiple bug fixes
   for this controller and allow for TLS termination support.

.. _`kubernetes ingress controller`: https://kubernetes.io/docs/concepts/services-networking/ingress/
.. _`documentation for nginx-ingress`: https://kubernetes.github.io/ingress-nginx/
.. _Network Load Balancer (NLB): https://docs.aws.amazon.com/elasticloadbalancing/latest/network/introduction.html

Configure your DNS records
==========================

Now that our NLB has been provisioned, we should point our application's DNS
records at the NLBs address.

Go into your DNS provider's console and set a CNAME record pointing to your
NLB.

For the purposes of demonstration, we will assume in this guide you have
created the following DNS entry:

.. code-block:: text

   example.com CNAME a8c2870a5a8a311e9a9a10a2e7af57d7-6c2ec8ede48726ab.elb.eu-west-1.amazonaws.com

As you progress through the rest of this tutorial, please replace
``example.com`` with your own registered domain.

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

   kubectl get po,svc -n demo
   NAME                                READY   STATUS    RESTARTS   AGE
   hello-kubernetes-66d45d6dff-m2lnr   1/1     Running   0          7s
   hello-kubernetes-66d45d6dff-qt2kb   1/1     Running   0          7s

   NAME                       TYPE        CLUSTER-IP      EXTERNAL-IP   PORT(S)   AGE
   service/hello-kubernetes   ClusterIP   10.100.164.58   <none>        80/TCP    7s

Note that we have not yet exposed this application to be accessible over the
internet. We will expose the demo application to the internet in later steps.

Creating a Venafi Issuer resource
=================================

cert-manager supports both Venafi TPP and Venafi Cloud.

Please only follow one of the below sections according to where you want to
retrieve your Certificates from.

Venafi TPP
----------

Assuming you already have a Venafi TPP server set up properly, you can create
a Venafi Issuer resource that can be used to issue certificates.

To do this, you need to make sure you have your TPP *username* and *password*.

In order for cert-manager to be able to authenticate with your Venafi TPP
server and set up an Issuer resource, you'll need to create a Kubernetes
Secret containing your username and password:

.. code-block:: shell

   kubectl create secret generic \
        venafi-tpp-secret \
        --namespace=demo \
        --from-literal=username='YOUR_TPP_USERNAME_HERE' \
        --from-literal=password='YOUR_TPP_PASSWORD_HERE'

We must then create a Venafi Issuer resource, which represents a certificate
authority within Kubernetes.

Save the following YAML into a file named ``venafi-issuer.yaml``:

.. code-block:: yaml
   :linenos:

   apiVersion: certmanager.k8s.io/v1alpha1
   kind: Issuer
   metadata:
     name: venafi-issuer
     namespace: demo
   spec:
     venafi:
       zone: "Default" # Set this to the Venafi policy zone you want to use
       tpp:
         url: https://venafi-tpp.example.com/vedsdk # Change this to the URL of your TPP instance
         caBundle: <base64 encoded string of caBundle PEM file, or empty to use system root CAs>
         credentialsRef:
           name: venafi-tpp-secret

Then run:

.. code-block:: shell

   kubectl apply -n demo -f venafi-issuer.yaml

When you run the following command, you should see that the Status stanza of
the output shows that the Issuer is Ready (i.e. has successfully validated
itself with the Venafi TPP server).

.. code-block:: shell

   kubectl describe issuer -n demo venafi-issuer

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

Venafi Cloud
------------

You can sign up for a Venafi Cloud account by visiting the `enroll page`_.

Once registered, you should fetch your API key by clicking your name in the top
right of the control panel interface.

In order for cert-manager to be able to authenticate with your Venafi Cloud
account and set up an Issuer resource, you'll need to create a Kubernetes
Secret containing your API key:

.. code-block:: shell

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
     name: venafi-issuer
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

   kubectl apply -n demo -f venafi-issuer.yaml

When you run the following command, you should see that the Status stanza of
the output shows that the Issuer is Ready (i.e. has successfully validated
itself with the Venafi Cloud service).

.. code-block:: shell

   kubectl describe issuer -n demo venafi-issuer

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

Request a Certificate
=====================

Now that the Issuer is configured and we have confirmed it has been set up
correctly, we can begin requesting certificates which can be used by Kubernetes
applications.

Full information on how to specify and request Certificate resources can be
found in the :doc:`Issuing certificates </tasks/issuing-certificates/index>`
guide.

For now, we will create a basic x509 Certificate that is valid for our domain,
``example.com``:

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
     issuerRef:
       name: venafi-issuer

Save this YAML into a file named ``example-com-tls.yaml`` and run:

.. code-block:: shell

   kubectl apply -n demo -f example-com-tls.yaml

As long as you've ensured that the zone of your Venafi Cloud account (in our
example, we use the "Default" zone) has been configured with a CA or contains a
custom certificate, cert-manager can now take steps to populate the
``example-com-tls`` Secret with a certificate. It does this by identifying
itself with Venafi Cloud using the API key, then requesting a certificate to
match the specifications of the Certificate resource that we've created.

You can run ``kubectl describe`` to check the progress of your Certificate:

.. code-block:: shell

   kubectl describe certificate -n demo example-com-tls

   ...
   Status:
     Conditions:
       Last Transition Time:  2019-07-17T17:43:01Z
       Message:               Certificate is up to date and has not expired
       Reason:                Ready
       Status:                True
       Type:                  Ready
     Not After:               2019-10-15T12:00:00Z
   Events:
     Type    Reason       Age   From          Message
     ----    ------       ----  ----          -------
     Normal  Issuing      33s   cert-manager  Requesting new certificate...
     Normal  GenerateKey  33s   cert-manager  Generated new private key
     Normal  Validate     33s   cert-manager  Validated certificate request against Venafi zone policy
     Normal  Requesting   33s   cert-manager  Requesting certificate from Venafi server...
     Normal  Retrieve     15s   cert-manager  Retrieved certificate from Venafi server
     Normal  CertIssued   15s   cert-manager  Certificate issued successfully

Once the Certificate has been issued, you should see events similar to above.

You should then be able to see the certificate has been successfully stored in
the Secret resource:

.. code-block:: shell

   kubectl get secret -n demo example-com-tls

   NAME              TYPE                DATA   AGE
   example-com-tls   kubernetes.io/tls   3      2m47s

   kubectl get secret example-com-tls -o 'go-template={{index .data "tls.crt"}}' | \
     base64 --decode | \
     openssl x509 -noout -text

   Certificate:
       Data:
           Version: 3 (0x2)
           Serial Number:
               0d:ce:bf:89:04:d4:41:83:f4:4c:32:66:64:fb:60:14
       Signature Algorithm: sha256WithRSAEncryption
           Issuer: C=US, O=DigiCert Inc, CN=DigiCert Test SHA2 Intermediate CA-1
           Validity
               Not Before: Jul 17 00:00:00 2019 GMT
               Not After : Oct 15 12:00:00 2019 GMT
           Subject: C=US, ST=California, L=Palo Alto, O=Venafi Cloud, OU=SerialNumber, CN=example.com
           Subject Public Key Info:
               Public Key Algorithm: rsaEncryption
                   Public-Key: (2048 bit)
                   Modulus:
                       00:ad:2e:66:02:20:c9:b1:6a:00:63:70:4e:22:3c:
                       45:63:6e:e7:fd:4c:94:7d:75:50:22:a2:01:72:99:
                       9c:23:04:90:51:85:4d:47:32:e4:8b:ee:b1:ea:09:
                       1a:de:97:5d:31:05:a2:73:73:4f:06:a3:b2:59:ee:
                       bc:30:f7:26:85:3d:b3:56:e4:c2:97:34:b6:ac:6d:
                       65:7e:a2:4e:b4:ce:f2:0a:0a:4c:d7:32:d7:5a:18:
                       e8:69:c6:34:28:26:36:ef:c5:bc:ae:ba:ca:d2:46:
                       3f:d4:61:39:66:8f:19:cc:d6:d6:10:77:af:51:93:
                       1b:4d:f8:d1:10:19:ab:ac:b3:7b:0b:98:58:29:e6:
                       a9:ac:9f:7a:dc:63:0d:51:f5:bd:9f:f3:03:2e:b3:
                       2d:2f:00:87:f4:e1:cd:5a:32:c6:d8:fb:49:c4:e7:
                       da:3f:0f:8f:bb:66:94:28:5d:99:fe:7c:f0:17:1b:
                       fd:3e:ed:dd:36:bf:8e:62:60:0c:85:7f:76:74:4b:
                       37:d9:c2:e8:74:49:04:bf:f1:83:81:cc:4f:9b:f3:
                       40:97:d4:dc:b6:d3:2d:dc:73:18:93:48:a5:8f:6c:
                       57:7f:ec:62:c0:bc:c2:b0:e9:0a:51:2d:c4:b6:87:
                       68:96:87:f8:9a:86:3c:6a:f1:01:ca:57:c4:07:e7:
                       b0:51
                   Exponent: 65537 (0x10001)
           X509v3 extensions:
               X509v3 Authority Key Identifier:
                   keyid:D6:4D:F9:39:60:6C:73:C3:22:F5:AD:30:0C:2F:A0:D5:CA:75:4A:2A

               X509v3 Subject Key Identifier:
                   A3:B3:47:2C:41:5E:9C:B2:27:97:57:14:A4:2E:BA:8C:93:E7:01:65
               X509v3 Subject Alternative Name:
                   DNS:example.com
               X509v3 Key Usage: critical
                   Digital Signature, Key Encipherment
               X509v3 Extended Key Usage:
                   TLS Web Server Authentication, TLS Web Client Authentication
               X509v3 CRL Distribution Points:

                   Full Name:
                     URI:http://crl3.digicert.com/DigiCertTestSHA2IntermediateCA1.crl

                   Full Name:
                     URI:http://crl4.digicert.com/DigiCertTestSHA2IntermediateCA1.crl

               X509v3 Certificate Policies:
                   Policy: 2.16.840.1.114412.1.1
                     CPS: https://www.digicert.com/CPS

               Authority Information Access:
                   OCSP - URI:http://ocsp.digicert.com
                   CA Issuers - URI:http://cacerts.test.digicert.com/DigiCertTestSHA2IntermediateCA1.crt

               X509v3 Basic Constraints: critical
                   CA:FALSE
       Signature Algorithm: sha256WithRSAEncryption
            ae:d4:9c:8a:66:19:9e:7d:12:b7:05:c2:b6:33:b3:9c:a5:40:
            47:ab:34:8d:1b:0f:51:96:de:e9:46:5a:e4:16:10:43:56:bf:
            fa:f8:64:f4:cb:53:39:5b:45:ca:7f:15:d9:59:25:21:23:c4:
            4d:dc:a7:f7:83:21:d2:3f:a8:0a:26:f4:ef:fa:1b:2b:7d:97:
            7e:28:f3:ca:cd:b2:c4:92:f3:92:27:7f:e0:f1:ac:d6:db:4c:
            10:8a:f8:6f:09:bb:b3:4f:19:06:aa:bb:74:1c:e0:51:42:f6:
            8c:7d:77:f7:80:a4:03:ab:a9:ae:ae:2b:89:17:af:2f:eb:f7:
            3d:61:7c:dd:e1:5d:d2:5a:c5:6a:f6:c8:92:4c:0a:b5:75:d1:
            dd:39:f2:a7:a2:10:8c:6d:bf:ca:08:ad:b9:a9:df:e3:59:8f:
            64:16:3c:7e:8a:6e:27:fc:49:d7:06:f0:bd:94:15:f2:fd:0f:
            94:8a:b8:73:67:73:53:22:df:9d:36:e9:34:f9:2a:68:00:59:
            78:6d:2d:8f:a0:0f:13:af:bd:b3:aa:8c:37:c4:22:cf:23:fb:
            56:bc:4e:55:ae:3a:0a:e6:3e:b1:1a:22:71:7b:08:b8:00:41:
            14:26:f6:9b:9b:72:3f:eb:dc:dd:1b:db:a8:20:fd:54:75:ae:
            25:7f:80:e6

In the next step, we'll configure your application to actually use this new
Certificate resource.

Exposing and securing your application
======================================

Now that we have issued a Certificate, we can expose our application using a
Kubernetes Ingress resource.

Create a file named ``application-ingress.yaml`` and save the following in it,
replacing ``example.com`` with your own domain name:

.. code-block:: yaml
   :linenos:

   apiVersion: extensions/v1beta1
   kind: Ingress
   metadata:
     name: frontend-ingress
     namespace: demo
     annotations:
       kubernetes.io/ingress.class: "nginx"
   spec:
     tls:
     - hosts:
       - example.com
       secretName: example-com-tls
     rules:
     - host: example.com
       http:
         paths:
         - path: /
           backend:
             serviceName: hello-kubernetes
             servicePort: 80

You can then apply this resource with:

.. code-block:: shell

   kubectl apply -n demo -f application-ingress.yaml

Once this has been created, you should be able to visit your application at
the configured hostname, here ``example.com``!

Navigate to the address in your web browser and you should see the certificate
obtained via Venafi being used to secure application traffic.
