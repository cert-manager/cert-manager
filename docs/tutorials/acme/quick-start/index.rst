=================================================
Quick-Start using Cert-Manager with NGINX Ingress
=================================================

Step 0 - Install Helm Client
=============================

**Skip this section if you have helm installed.**

The easiest way to install `cert-manager` is to use `Helm`_, a templating and
deployment tool for Kubernetes resources.

First, ensure the Helm client is installed following the
`Helm installation instructions`_.

For example, on macOS:

.. code-block:: shell

   $ brew install kubernetes-helm

.. _`Helm`: https://helm.sh
.. _`Helm installation instructions`: https://github.com/helm/helm/blob/master/docs/install.md

Step 1 - Installer Tiller
=========================

**Skip this section if you have Tiller set-up.**

Tiller is Helm's server-side component, which the ``helm`` client uses to
deploy resources.

Deploying resources is a privileged operation; in the general case requiring
arbitrary privileges. With this example, we give Tiller complete control
of the cluster. View the documentation on `securing helm`_ for details on
setting up appropriate permissions for your environment.

.. _`securing helm`: https://docs.helm.sh/using_helm/#securing-your-helm-installation

Create the a ServiceAccount for tiller:

.. code-block:: shell

  $ kubectl create serviceaccount tiller --namespace=kube-system
  serviceaccount "tiller" created

Grant the ``tiller`` service account cluster admin privileges:

.. code-block:: shell

  $ kubectl create clusterrolebinding tiller-admin --serviceaccount=kube-system:tiller --clusterrole=cluster-admin
  clusterrolebinding.rbac.authorization.k8s.io "tiller-admin" created

Install tiller with the ``tiller`` service account:

.. code-block:: shell

  $ helm init --service-account=tiller
  $HELM_HOME has been configured at /Users/myaccount/.helm.

  Tiller (the Helm server-side component) has been installed into your Kubernetes Cluster.

  Please note: by default, Tiller is deployed with an insecure 'allow unauthenticated users' policy.
  To prevent this, run `helm init` with the --tiller-tls-verify flag.
  For more information on securing your installation see: https://docs.helm.sh/using_helm/#securing-your-helm-installation
  Happy Helming!

Update the helm repository with the latest charts:

.. code-block:: shell

  $ helm repo update
  Hang tight while we grab the latest from your chart repositories...
  ...Skip local chart repository
  ...Successfully got an update from the "stable" chart repository
  ...Successfully got an update from the "coreos" chart repository
  Update Complete. ⎈ Happy Helming!⎈


Step 2 - Deploy the NGINX Ingress Controller
============================================

A `kubernetes ingress controller`_ is designed to be the access point for
HTTP and HTTPS traffic to the software running within your cluster. The
nginx-ingress controller does this by providing an HTTP proxy service
supported by your cloud provider's load balancer.

You can get more details about nginx-ingress and how it works from the
`documentation for nginx-ingress`_.

.. _`kubernetes ingress controller`: https://kubernetes.io/docs/concepts/services-networking/ingress/
.. _`documentation for nginx-ingress`: https://kubernetes.github.io/ingress-nginx/

Use ``helm`` to install an Nginx Ingress controller:

.. code-block:: shell

    $ helm install stable/nginx-ingress --name quickstart

    NAME:   quickstart
    LAST DEPLOYED: Sat Nov 10 10:25:06 2018
    NAMESPACE: default
    STATUS: DEPLOYED

    RESOURCES:
    ==> v1/ConfigMap
    NAME                                 AGE
    quickstart-nginx-ingress-controller  0s

    ==> v1beta1/ClusterRole
    quickstart-nginx-ingress  0s

    ==> v1beta1/Deployment
    quickstart-nginx-ingress-controller       0s
    quickstart-nginx-ingress-default-backend  0s

    ==> v1/Pod(related)

    NAME                                                      READY  STATUS             RESTARTS  AGE
    quickstart-nginx-ingress-controller-6cfc45747-wcxrg       0/1    ContainerCreating  0         0s
    quickstart-nginx-ingress-default-backend-bf9db5c67-dkg4l  0/1    ContainerCreating  0         0s

    ==> v1/ServiceAccount

    NAME                      AGE
    quickstart-nginx-ingress  0s

    ==> v1beta1/ClusterRoleBinding
    quickstart-nginx-ingress  0s

    ==> v1beta1/Role
    quickstart-nginx-ingress  0s

    ==> v1beta1/RoleBinding
    quickstart-nginx-ingress  0s

    ==> v1/Service
    quickstart-nginx-ingress-controller       0s
    quickstart-nginx-ingress-default-backend  0s


    NOTES:
    The nginx-ingress controller has been installed.
    It may take a few minutes for the LoadBalancer IP to be available.
    You can watch the status by running 'kubectl --namespace default get services -o wide -w quickstart-nginx-ingress-controller'

    An example Ingress that makes use of the controller:

      apiVersion: extensions/v1beta1
      kind: Ingress
      metadata:
        annotations:
          kubernetes.io/ingress.class: nginx
        name: example
        namespace: foo
      spec:
        rules:
          - host: www.example.com
            http:
              paths:
                - backend:
                    serviceName: exampleService
                    servicePort: 80
                  path: /
        # This section is only required if TLS is to be enabled for the Ingress
        tls:
            - hosts:
                - www.example.com
              secretName: example-tls

    If TLS is enabled for the Ingress, a Secret containing the certificate and key must also be provided:

      apiVersion: v1
      kind: Secret
      metadata:
        name: example-tls
        namespace: foo
      data:
        tls.crt: <base64 encoded cert>
        tls.key: <base64 encoded key>
      type: kubernetes.io/tls

It can take a minute or two for the cloud provider to provide and link a public
IP address. When it is complete, you can see the external IP address using the
``kubectl`` command:

.. code-block:: shell
   :emphasize-lines: 5

    $ kubectl get svc

    NAME                                       TYPE           CLUSTER-IP      EXTERNAL-IP      PORT(S)                      AGE
    kubernetes                                 ClusterIP      10.63.240.1     <none>           443/TCP                      23m
    quickstart-nginx-ingress-controller        LoadBalancer   10.63.248.177   35.233.154.161   80:31345/TCP,443:31376/TCP   16m
    quickstart-nginx-ingress-default-backend   ClusterIP      10.63.250.234   <none>           80/TCP                       16m

This command shows you all the services in your cluster (in the ``default``
namespace), and any external IP addresses they have. When you first create the
controller, your cloud provider won't have assigned and allocated an IP address
through the LoadBalancer yet. Until it does, the external IP address for the
service will be listed as ``<pending>``.

Your cloud provider may have options for reserving an IP address prior to
creating the ingress controller and using that IP address rather than assigning
an IP address from a pool. Read through the documentation from your cloud
provider on how to arrange that.

Step 3 - Assign a DNS name
==========================

The external IP that is allocated to the ingress-controller is the IP to which
all incoming traffic should be routed. To enable this, add it to a DNS zone you
control, for example as `example.your-domain.com`.

This quickstart assumes you know how to assign a DNS entry to an IP address and
will do so.

Step 4 - Deploy an Example Service
==================================

Your service may have its own chart, or you may be deploying it directly with
manifests. This quickstart uses manifests to create and expose a sample
service. The example service uses `kuard`_, a demo application which makes an
excellent back-end for examples.

The quickstart example uses three manifests for the sample. The first two are a
sample deployment and an associated service:

- deployment manifest: `deployment.yaml`_

.. literalinclude:: example/deployment.yaml
   :language: yaml

- service manifest: `service.yaml`_

.. literalinclude:: example/service.yaml
   :language: yaml

.. _`deployment.yaml`: https://raw.githubusercontent.com/jetstack/cert-manager/release-0.9/docs/tutorials/acme/quick-start/example/deployment.yaml
.. _`service.yaml`: https://raw.githubusercontent.com/jetstack/cert-manager/release-0.9/docs/tutorials/acme/quick-start/example/service.yaml
.. _`kuard`: https://github.com/kubernetes-up-and-running/kuard

You can create download and reference these files locally, or you can
reference them from the GitHub source repository for this documentation.
To install the example service from the tutorial files straight from GitHub,
you may use the commands:

.. code-block:: shell

   $ kubectl apply -f https://raw.githubusercontent.com/jetstack/cert-manager/release-0.9/docs/tutorials/acme/quick-start/example/deployment.yaml
   deployment.extensions "kuard" created

   $ kubectl apply -f https://raw.githubusercontent.com/jetstack/cert-manager/release-0.9/docs/tutorials/acme/quick-start/example/service.yaml
   service "kuard" created

An `ingress resource`_ is what Kubernetes uses to expose this example service
outside the cluster.  You will need to download and modify the example manifest
to reflect the domain that you own or  control to complete this example.


A sample ingress you can start with is:

- ingress manifest: `ingress.yaml`_

.. literalinclude:: example/ingress.yaml
   :language: yaml

.. _`ingress.yaml`: https://raw.githubusercontent.com/jetstack/cert-manager/release-0.9/docs/tutorials/acme/quick-start/example/ingress.yaml
.. _`ingress resource`: https://kubernetes.io/docs/concepts/services-networking/ingress/

You can download the sample manifest from github, edit it, and submit the manifest to Kubernetes with the command:

.. code-block:: shell

   $ kubectl create --edit -f https://raw.githubusercontent.com/jetstack/cert-manager/release-0.9/docs/tutorials/acme/quick-start/example/ingress.yaml

   # edit the file in your editor, and once it is saved:
   ingress.extensions "kuard" created

.. note::

    The ingress example we show above has a `host` definition within it. The
    nginx-ingress-controller will route traffic when the hostname requested matches the
    definition in the ingress. You *can* deploy an ingress without a `host` definition
    in the rule, but that pattern isn't usable with a TLS certificate, which expects a
    fully qualified domain name.

Once it is deployed, you can use the command `kubectl get ingress` to see the status
 of the ingress:

.. code-block:: shell

    NAME      HOSTS     ADDRESS   PORTS     AGE
    kuard     *                   80, 443   17s

It may take a few minutes, depending on your service provider, for the ingress
to be fully created. When it has been created and linked into place, the
ingress will show an address as well:

.. code-block:: shell

    NAME      HOSTS     ADDRESS         PORTS     AGE
    kuard     *         35.199.170.62   80        9m

.. note::

    The IP address on the ingress *may not* match the IP address that the
    nginx-ingress-controller. This is fine, and is a quirk/implementation detail
    of the service provider hosting your Kubernetes cluster. Since we are using
    the nginx-ingress-controller instead of any cloud-provider specific ingress
    backend, use the IP address that was defined and allocated for the
    nginx-ingress-service LoadBalancer resource as the primary  access point for
    your service.

Make sure the service is reachable at the domain name you added above, for
example `http://example.your-domain.com`. The simplest way is to open a browser
and enter the name that you set up in DNS, and for which we just added the
ingress.

You may also use a command line tool like `curl` to check the ingress.

.. code-block:: shell

    $ curl -kivL -H 'Host: example.your-domain.com' 'http://35.199.164.14'

The options on this curl command will provide verbose output, following any
redirects, show the TLS headers in the output,  and not error on insecure
certificates. With nginx-ingress-controller, the service will be available
with a TLS certificate, but it will be using a self-signed certificate
provided as a default from the nginx-ingress-controller. Browsers will show
a warning that this is an invalid certificate. This is expected and normal,
as we have not yet used cert-manager to get a fully trusted certificate
for our site.

.. warning::

    It is critical to make sure that your ingress is available and responding correctly
    on the internet. This quickstart example uses Let's Encypt to provide the certificates,
    which expects and validates both that the service is available and that during the
    process of issuing a certificate uses that valdiation as proof that the request for
    the domain belongs to someone with sufficient control over the domain.

Step 5 - Deploy Cert Manager
============================

We need to install cert-manager to do the work with kubernetes to request a
certificate and respond to the challenge to validate it. We can use helm to
install cert-manager. This example installed cert-manager into the
`kube-system` namespace from the public helm charts.

.. code-block:: shell

    # Install the cert-manager CRDs. We must do this before installing the Helm
    # chart in the next step for `release-0.9` of cert-manager:
    $ kubectl apply -f https://raw.githubusercontent.com/jetstack/cert-manager/release-0.9/deploy/manifests/00-crds.yaml

    # Create the namespace for cert-manager
    $ kubectl create namespace cert-manager

    # Label the cert-manager namespace to disable resource validation
    $ kubectl label namespace cert-manager certmanager.k8s.io/disable-validation=true

    ## Add the Jetstack Helm repository
    $ helm repo add jetstack https://charts.jetstack.io

    ## Updating the repo just incase it already existed
    $ helm repo update

    ## Install the cert-manager helm chart
    $ helm install \
      --name cert-manager \
      --namespace cert-manager \
      --version v0.9.1 \
      jetstack/cert-manager

    NAME:   cert-manager
    LAST DEPLOYED: Wed Jan  9 13:36:13 2019
    NAMESPACE: cert-manager
    STATUS: DEPLOYED

    RESOURCES:
    ==> v1beta1/ClusterRoleBinding
    NAME                                 AGE
    cert-manager-webhook-ca-sync         2s
    cert-manager-webhook:auth-delegator  2s
    cert-manager                         2s

    ==> v1beta1/APIService
    NAME                                  AGE
    v1beta1.admission.certmanager.k8s.io  2s

    ==> v1alpha1/Certificate
    cert-manager-webhook-webhook-tls  1s
    cert-manager-webhook-ca           1s

    ==> v1beta1/ValidatingWebhookConfiguration
    cert-manager-webhook  1s

    ==> v1/ServiceAccount
    NAME                          SECRETS  AGE
    cert-manager-webhook-ca-sync  1        2s
    cert-manager-webhook          1        2s
    cert-manager                  1        2s

    ==> v1beta1/RoleBinding
    NAME                                                AGE
    cert-manager-webhook:webhook-authentication-reader  2s

    ==> v1beta1/Deployment
    NAME                  DESIRED  CURRENT  UP-TO-DATE  AVAILABLE  AGE
    cert-manager-webhook  1        1        1           0          2s
    cert-manager          1        1        1           0          2s

    ==> v1/Job
    NAME                          DESIRED  SUCCESSFUL  AGE
    cert-manager-webhook-ca-sync  1        0           2s

    ==> v1beta1/CronJob
    NAME                          SCHEDULE      SUSPEND  ACTIVE  LAST SCHEDULE  AGE
    cert-manager-webhook-ca-sync  * * */24 * *  False    0       <none>         2s

    ==> v1beta1/ClusterRole
    NAME                          AGE
    cert-manager-webhook-ca-sync  2s
    cert-manager                  2s

    ==> v1/ClusterRole
    cert-manager-webhook:webhook-requester  2s
    cert-manager-view                       2s
    cert-manager-edit                       2s

    ==> v1/Service
    NAME                  TYPE       CLUSTER-IP    EXTERNAL-IP  PORT(S)  AGE
    cert-manager-webhook  ClusterIP  10.3.244.237  <none>       443/TCP  2s

    ==> v1/ConfigMap
    NAME                          DATA  AGE
    cert-manager-webhook-ca-sync  1     2s

    ==> v1alpha1/Issuer
    NAME                           AGE
    cert-manager-webhook-ca        1s
    cert-manager-webhook-selfsign  1s

    ==> v1/Pod(related)
    NAME                                   READY  STATUS             RESTARTS  AGE
    cert-manager-webhook-745b49d445-rnxm2  0/1    ContainerCreating  0         2s
    cert-manager-9cdd9f774-t856z           0/1    ContainerCreating  0         2s
    cert-manager-webhook-ca-sync-ddf4b     0/1    ContainerCreating  0         2s

    NOTES:
    cert-manager has been deployed successfully!

    In order to begin issuing certificates, you will need to set up a ClusterIssuer
    or Issuer resource (for example, by creating a 'letsencrypt-staging' issuer).

    More information on the different types of issuers and how to configure them
    can be found in our documentation:

    https://docs.cert-manager.io/en/latest/reference/issuers.html

    For information on how to configure cert-manager to automatically provision
    Certificates for Ingress resources, take a look at the `ingress-shim`
    documentation:

    https://docs.cert-manager.io/en/latest/reference/ingress-shim.html

Cert-manager uses two different custom resources, also known as `CRD`_'s,
to configure and control how it operates, as well as share status of its
operation. These two resources are:

:doc:`Issuers </reference/issuers>` (or :doc:`ClusterIssuers </reference/clusterissuers>`)

    An Issuer is the definition for where cert-manager will get request TLS
    certificates. An Issuer is specific to a single namespace in Kubernetes,
    and a ClusterIssuer is meant to be a cluster-wide definition for the same
    purpose.
    
    Note that if you're using this document as a guide to configure cert-manager
    for your own Issuer, you must create the Issuers in the same namespace
    as your Ingress resouces by adding '-n my-namespace' to your 'kubectl create'
    commands. Your other option is to replace your Issuers with ClusterIssuers.
    ClusterIssuer resources apply across all Ingress resources in your cluster
    and don't have this namespace-matching requirement.
    
    More information on the differences between Issuers and ClusterIssuers and
    when you might choose to use each can be found at:
    
    https://docs.cert-manager.io/en/latest/tasks/issuers/index.html#difference-between-issuers-and-clusterissuers

:doc:`Certificate </reference/certificates>`

    A certificate is the resource that cert-manager uses to expose the state
    of a request as well as track upcoming expirations.

.. _`CRD`: https://kubernetes.io/docs/concepts/extend-kubernetes/api-extension/custom-resources/


Step 6 - Configure Let's Encrypt Issuer
=======================================

We will set up two issuers for Let's Encrypt in this example. The Let's Encrypt
production issuer has `very strict rate limits`_. When you are experimenting
and learning, it is very easy to  hit those limits, and confuse rate limiting
with errors in configuration or operation.

.. _`very strict rate limits`: https://letsencrypt.org/docs/rate-limits/

Because of this, we will start with the Let's Encrypt staging issuer, and once
that is working switch to a production issuer.

Create this definition locally and update the email address to your own. This
email required by Let's Encrypt and used to notify you of certificate
expirations and updates.

- staging issuer: `staging-issuer.yaml`_

.. literalinclude:: example/staging-issuer.yaml
   :language: yaml

.. _`staging-issuer.yaml`: https://raw.githubusercontent.com/jetstack/cert-manager/release-0.9/docs/tutorials/acme/quick-start/example/staging-issuer.yaml

Once edited, apply the custom resource:

.. code-block:: shell

    $ kubectl create --edit -f https://raw.githubusercontent.com/jetstack/cert-manager/release-0.9/docs/tutorials/acme/quick-start/example/staging-issuer.yaml
    issuer.certmanager.k8s.io "letsencrypt-staging" created

Also create a production issuer and deploy it. As with the staging issuer, you
will need to update this example and add in your own email address.

- production issuer: `production-issuer.yaml`_

.. literalinclude:: example/production-issuer.yaml
   :language: yaml
   :emphasize-lines: 10

.. _`production-issuer.yaml`: https://raw.githubusercontent.com/jetstack/cert-manager/release-0.9/docs/tutorials/acme/quick-start/example/production-issuer.yaml

.. code-block:: shell

    $ kubectl create --edit -f https://raw.githubusercontent.com/jetstack/cert-manager/release-0.9/docs/tutorials/acme/quick-start/example/production-issuer.yaml
    issuer.certmanager.k8s.io "letsencrypt-prod" created

Both of these issuers are configured to use the
:doc:`HTTP01 </tasks/issuers/setup-acme/http01/index>` challenge provider.

Check on the status of the issuer after you create it:

.. code-block:: shell
   :emphasize-lines: 28-32

    $ kubectl describe issuer letsencrypt-staging

    Name:         letsencrypt-staging
    Namespace:    default
    Labels:       <none>
    Annotations:  kubectl.kubernetes.io/last-applied-configuration={"apiVersion":"certmanager.k8s.io/v1alpha1","kind":"Issuer","metadata":{"annotations":{},"name":"letsencrypt-staging","namespace":"default"},"spec":{"a...
    API Version:  certmanager.k8s.io/v1alpha1
    Kind:         Issuer
    Metadata:
      Cluster Name:
      Creation Timestamp:  2018-11-17T18:03:54Z
      Generation:          0
      Resource Version:    9092
      Self Link:           /apis/certmanager.k8s.io/v1alpha1/namespaces/default/issuers/letsencrypt-staging
      UID:                 25b7ae77-ea93-11e8-82f8-42010a8a00b5
    Spec:
      Acme:
        Email:  your.email@your-domain.com
        Private Key Secret Ref:
          Key:
          Name:  letsencrypt-staging
        Server:  https://acme-staging-v02.api.letsencrypt.org/directory
        Solvers:
          Http 01:
            Ingress:
              Class:  nginx
    Status:
      Acme:
        Uri:  https://acme-staging-v02.api.letsencrypt.org/acme/acct/7374163
      Conditions:
        Last Transition Time:  2018-11-17T18:04:00Z
        Message:               The ACME account was registered with the ACME server
        Reason:                ACMEAccountRegistered
        Status:                True
        Type:                  Ready
    Events:                    <none>

You should see the issuer listed with a registered account.

Step 7 - Deploy a TLS Ingress Resource
======================================

With all the pre-requisite configuration in place, we can now do the pieces
to request the TLS certificate. There are two primary ways to do this: using
annotations on the ingress with
:doc:`ingress-shim </tasks/issuing-certificates/ingress-shim>` or directly
creating a certificate resource.

In this example, we will add annotations to the ingress, and take advantage
of ingress-shim to have it create the certificate resource on our behalf.
After creating a certificate, the cert-manager will update or create a ingress
resource and use that to validate the domain. Once verified and issued,
cert-manager will create or update the secret defined in the certificate.

.. note::

    The secret that is used in the ingress should match the secret defined in the certificate.
    There isn't any explicit checking, so a typo will resut in the nginx-ingress-controller
    falling back to its self-signed certificate. In our example, we are using annotations on
    the ingress (and ingress-shim) which will create the correct secrets on your behalf.

Edit the ingress add the annotations that were commented out in our earlier
example:

- ingress tls: `ingress-tls.yaml`_

.. literalinclude:: example/ingress-tls.yaml
   :language: yaml
   :emphasize-lines: 6-8

.. _`ingress-tls.yaml`: https://raw.githubusercontent.com/jetstack/cert-manager/release-0.9/docs/tutorials/acme/quick-start/example/ingress-tls.yaml

and apply it:

.. code-block:: shell

   $ kubectl create --edit -f https://raw.githubusercontent.com/jetstack/cert-manager/release-0.9/docs/tutorials/acme/quick-start/example/ingress-tls.yaml
   ingress.extensions "kuard" configured

Cert-manager will read these annotations and use them to create a certificate,
which you can request and see:

.. code-block:: shell

    $ kubectl get certificate
    NAME                     READY   SECRET                   AGE
    quickstart-example-tls   True    quickstart-example-tls   16m

Cert-manager reflects the state of the process for every request in the
certificate object. You can view this information using the
`kubectl describe` command:

.. code-block:: shell
   :emphasize-lines: 50-54

    $ kubectl describe certificate quickstart-example-tls

    Name:         quickstart-example-tls
    Namespace:    default
    Labels:       <none>
    Annotations:  <none>
    API Version:  certmanager.k8s.io/v1alpha1
    Kind:         Certificate
    Metadata:
      Cluster Name:
      Creation Timestamp:  2018-11-17T17:58:37Z
      Generation:          0
      Owner References:
        API Version:           extensions/v1beta1
        Block Owner Deletion:  true
        Controller:            true
        Kind:                  Ingress
        Name:                  kuard
        UID:                   a3e9f935-ea87-11e8-82f8-42010a8a00b5
      Resource Version:        9295
      Self Link:               /apis/certmanager.k8s.io/v1alpha1/namespaces/default/certificates/quickstart-example-tls
      UID:                     68d43400-ea92-11e8-82f8-42010a8a00b5
    Spec:
      Dns Names:
        example.your-domain.com
      Issuer Ref:
        Kind:       Issuer
        Name:       letsencrypt-staging
      Secret Name:  quickstart-example-tls
    Status:
      Acme:
        Order:
          URL:  https://acme-staging-v02.api.letsencrypt.org/acme/order/7374163/13665676
      Conditions:
        Last Transition Time:  2018-11-17T18:05:57Z
        Message:               Certificate issued successfully
        Reason:                CertIssued
        Status:                True
        Type:                  Ready
    Events:
      Type     Reason          Age                From          Message
      ----     ------          ----               ----          -------
      Normal   CreateOrder     9m                 cert-manager  Created new ACME order, attempting validation...
      Normal   DomainVerified  8m                 cert-manager  Domain "example.your-domain.com" verified with "http-01" validation
      Normal   IssueCert       8m                 cert-manager  Issuing certificate...
      Normal   CertObtained    7m                 cert-manager  Obtained certificate from ACME server
      Normal   CertIssued      7m                 cert-manager  Certificate issued Successfully

The events associated with this resource and listed at the bottom
of the `describe` results show the state of the request. In the above
example the certificate was validated and issued within a couple of minutes.

Once complete, cert-manager will have created a secret with the details of
the certificate based on the secret used in the ingress resource. You can
use the describe command as well to see some details:

.. code-block:: shell

    $ kubectl describe secret quickstart-example-tls

    Name:         quickstart-example-tls
    Namespace:    default
    Labels:       certmanager.k8s.io/certificate-name=quickstart-example-tls
    Annotations:  certmanager.k8s.io/alt-names=example.your-domain.com
                  certmanager.k8s.io/common-name=example.your-domain.com
                  certmanager.k8s.io/issuer-kind=Issuer
                  certmanager.k8s.io/issuer-name=letsencrypt-staging

    Type:  kubernetes.io/tls

    Data
    ====
    tls.crt:  3566 bytes
    tls.key:  1675 bytes


Now that we have confidence that everything is configured correctly, you
can update the annotations in the ingress to specify the production issuer:

- ingress tls final: `ingress-tls-final.yaml`_

.. literalinclude:: example/ingress-tls-final.yaml
   :language: yaml

.. _`ingress-tls-final.yaml`: https://raw.githubusercontent.com/jetstack/cert-manager/release-0.9/docs/tutorials/acme/quick-start/example/ingress-tls-final.yaml

.. code-block:: shell

   $ kubectl create --edit -f https://raw.githubusercontent.com/jetstack/cert-manager/release-0.9/docs/tutorials/acme/quick-start/example/ingress-tls-final.yaml

   ingress.extensions "kuard" configured

You will also need to delete the existing secret, which cert-manager is watching
and will cause it to reprocess the request with the updated issuer.

.. code-block:: shell

   $ kubectl delete secret quickstart-example-tls

   secret "quickstart-example-tls" deleted

This will start the process to get a new certificate, and using describe
you can see the status. Once the production certificate has been updated,
you should see the example KUARD running at your domain with a signed TLS
certificate.

.. code-block:: shell
   :emphasize-lines: 47-48

    $ kubectl describe certificate

    Name:         quickstart-example-tls
    Namespace:    default
    Labels:       <none>
    Annotations:  <none>
    API Version:  certmanager.k8s.io/v1alpha1
    Kind:         Certificate
    Metadata:
      Cluster Name:
      Creation Timestamp:  2018-11-17T18:36:48Z
      Generation:          0
      Owner References:
        API Version:           extensions/v1beta1
        Block Owner Deletion:  true
        Controller:            true
        Kind:                  Ingress
        Name:                  kuard
        UID:                   a3e9f935-ea87-11e8-82f8-42010a8a00b5
      Resource Version:        283686
      Self Link:               /apis/certmanager.k8s.io/v1alpha1/namespaces/default/certificates/quickstart-example-tls
      UID:                     bdd93b32-ea97-11e8-82f8-42010a8a00b5
    Spec:
      Dns Names:
        example.your-domain.com
      Issuer Ref:
        Kind:       Issuer
        Name:       letsencrypt-prod
      Secret Name:  quickstart-example-tls
    Status:
      Conditions:
        Last Transition Time:  2019-01-09T13:52:05Z
        Message:               Certificate does not exist
        Reason:                NotFound
        Status:                False
        Type:                  Ready
    Events:
      Type    Reason        Age   From          Message
   kubectl describe certificate quickstart-example-tls   ----    ------        ----  ----          -------
      Normal  Generated     18s   cert-manager  Generated new private key
      Normal  OrderCreated  18s   cert-manager  Created Order resource "quickstart-example-tls-889745041"

You can see the current state of the ACME Order by running ``kubectl describe``
on the Order resource that cert-manager has created for your Certificate:

.. code-block:: shell

    $ kubectl describe order quickstart-example-tls-889745041
    ...
    Events:
      Type    Reason      Age   From          Message
      ----    ------      ----  ----          -------
      Normal  Created     90s   cert-manager  Created Challenge resource "quickstart-example-tls-889745041-0" for domain "example.your-domain.com"

Here, we can see that cert-manager has created 1 'Challenge' resource to fulfil
the Order. You can dig into the state of the current ACME challenge by running
``kubectl describe`` on the automatically created Challenge resource:

.. code-block:: shell

    $ kubectl describe challenge quickstart-example-tls-889745041-0
    ...

    Status:
      Presented:   true
      Processing:  true
      Reason:      Waiting for http-01 challenge propagation
      State:       pending
    Events:
      Type    Reason     Age   From          Message
      ----    ------     ----  ----          -------
      Normal  Started    15s   cert-manager  Challenge scheduled for processing
      Normal  Presented  14s   cert-manager  Presented challenge using http-01 challenge mechanism

From above, we can see that the challenge has been 'presented' and cert-manager
is waiting for the challenge record to propagate to the ingress controller.
You should keep an eye out for new events on the challenge resource, as a
'success' event should be printed after a minute or so (depending on how fast
your ingress controller is at updating rules):

.. code-block:: shell

    $ kubectl describe challenge quickstart-example-tls-889745041-0
    ...

    Status:
      Presented:   false
      Processing:  false
      Reason:      Successfully authorized domain
      State:       valid
    Events:
      Type    Reason          Age   From          Message
      ----    ------          ----  ----          -------
      Normal  Started         71s   cert-manager  Challenge scheduled for processing
      Normal  Presented       70s   cert-manager  Presented challenge using http-01 challenge mechanism
      Normal  DomainVerified  2s    cert-manager  Domain "example.your-domain.com" verified with "http-01" validation

.. note::
   If your challenges are not becoming 'valid' and remain in the 'pending'
   state (or enter into a 'failed' state), it is likely there is some kind of
   configuration error.
   Read the :doc:`Challenge resource reference docs </reference/challenges>`
   for more information on debugging failing challenges.

Once the challenge(s) have been completed, their corresponding challenge
resources will be *deleted*, and the 'Order' will be updated to reflect the
new state of the Order:

.. code-block:: shell

    $ kubectl describe order quickstart-example-tls-889745041
    ...
    Events:
      Type    Reason      Age   From          Message
      ----    ------      ----  ----          -------
      Normal  Created     90s   cert-manager  Created Challenge resource "quickstart-example-tls-889745041-0" for domain "example.your-domain.com"
      Normal  OrderValid  16s   cert-manager  Order completed successfully

Finally, the 'Certificate' resource will be updated to reflect the state of the
issuance process. If all is well, you should be able to 'describe' the Certificate
and see something like the below:

.. code-block:: shell

    $ kubectl describe certificate quickstart-example-tls

    Status:
      Conditions:
        Last Transition Time:  2019-01-09T13:57:52Z
        Message:               Certificate is up to date and has not expired
        Reason:                Ready
        Status:                True
        Type:                  Ready
      Not After:               2019-04-09T12:57:50Z
    Events:
      Type    Reason         Age                  From          Message
      ----    ------         ----                 ----          -------
      Normal  Generated      11m                  cert-manager  Generated new private key
      Normal  OrderCreated   11m                  cert-manager  Created Order resource "quickstart-example-tls-889745041"
      Normal  OrderComplete  10m                  cert-manager  Order "quickstart-example-tls-889745041" completed successfully
