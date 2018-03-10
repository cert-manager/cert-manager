# Develop with minikube

## Start minikube

First, run minikube, and configure your local kubectl command to work with minikube; minikube typically does this automatically.


```shell
$ minikube version
minikube version: v0.25.0

$ minikube start --extra-config=apiserver.Authorization.Mode=RBAC
# Verify it works
$ kubectl cluster-info
# Should output a local master ip

$ kubectl create clusterrolebinding default-admin --clusterrole=cluster-admin --serviceaccount=kube-system:default
$ helm init
```

## Build a dev version of cert-manager for minikube

```shell
$ eval "$(minikube docker-env)"
$ make build
# ....
Successfully tagged quay.io/jetstack/cert-manager-controller:build
```

## Deploy that version with helm

```shell
$ helm install --set image.tag=build --name cert-manager ./contrib/charts/cert-manager
```

From here, you should be able to do whatever manual testing or development you wish to.

## Deploy a new version

In general, upgrading can be done simply by running `make build`, and then deleting the deployed pod using `kubectl delete pod`.

However, if you make changes to the helm chart or wish to change the controller's arguments, such as to change the logging level, you may also update it with the following:

```shell
$ helm upgrade  --set extraArgs="{-v=5}" --set image.tag=build cert-manager ./contrib/charts/cert-manager
```
