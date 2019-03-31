========================
Running on OpenShift
========================

OpenShift is a PaaS built upon Kubernetes. Running on OpenShift is quite similar to Kubernetes where the `oc` binary
is used to create Kubernetes objects.

Step 0 - Login to your OpenShift Cluster
=============================

.. code-block:: shell

   $ oc Login

Step 1 - Create objects using manifests
=============================

.. code-block:: shell

   $ cd deploy/manifests/
   $ oc create -f 00-crds.yaml
   $ oc create -f 01-namespace.yaml
   $ oc create -f cert-manager.yaml

Step 2 - Verify cert-manager is running
=============================

.. code-block:: shell

   $ oc get pods -n cert-manager
   NAME                                      READY     STATUS             RESTARTS   AGE
   cert-manager-589678351-vd599              1/1       Running            0          1h

Step 3 - Ingress
=============================

OpenShift comes with HA Proxy out of the box which creates the `Route` object for accessing application endpoints.
There is no support for `Route` objects [yet](https://github.com/jetstack/cert-manager/issues/1064). As an alternate, a reverse proxy which supports
ingress objects is to be used for cert-manager. There is a really good doc written for installing NGINX reverse proxy on OpenShift [here](https://github.com/nginxinc/kubernetes-ingress/blob/master/docs/installation.md).
There is also a blog from Red Hat [here](https://blog.openshift.com/introducing-nginx-and-nginx-plus-routers-for-openshift/).

Step 4 - Create objects for cert-manager
=============================

Follow the quick start [tutorial](https://docs.cert-manager.io/en/latest/tutorials/acme/quick-start/index.html) for using cert-manager on OpenShift.
