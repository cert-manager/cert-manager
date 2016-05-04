# kube-lego example

# Create a default http backend

```
kubectl create -f default-http-backend-deployment.yaml
kubectl create -f default-http-backend-svc.yaml
```

# Create nginx ingress

```
kubectl create -f nginx-configmap.yaml
kubectl create -f nginx-svc.yaml
kubectl create -f nginx-deployment.yaml
```

- The nginx service uses a LoadBalancer to publish the service 

# Create an example app (echoserver)

```
kubectl create -f echoserver-deployment.yaml
kubectl create -f echoserver-ingress-notls.yaml
kubectl create -f echoserver-svc.yaml
```

- Make sure the echo service is reachable through http://echo.example.com

# Enable kube-lego

```
kubectl create -f kube-lego-configmap.yaml
kubectl create -f kube-lego-svc.yaml
kubectl create -f kube-lego-deployment.yaml
```
- Change the email address in `kube-lego-configmap.yaml` before creating the
  kubernetes resource


# Enable tls for echoserver ingress

```
kubectl apply -f echoserver-ingress-notls.yaml
```

# Get debug information

- Look at the log output of the nginx pod
- Look at the log output of the ingress pods
- Sometimes after acquiring a new certifiacte nginx needs to be restarted (as
  it's not watching change events for secrets)

