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

The nginx service uses a LoadBalancer to publish the service. A few minutes after you have added the nginx service, you will get it's public IP address or domain via kubectl:

```
kubectl describe svc nginx
[...]
LoadBalancer Ingress:   1.2.3.4
[...]
```

This is the IP address where you have to point your domains to. IN AWS you will get a domain, use a CNAME record in this case.

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
kubectl apply -f echoserver-ingress-tls.yaml
```

# Get debug information

- Look at the log output of the nginx pod
- Look at the log output of the ingress pods
- Sometimes after acquiring a new certifiacte nginx needs to be restarted (as
  it's not watching change events for secrets)
