# Deploying cert-manager using Helm

To deploy the latest version of cert-manager using Helm:

1. [Install Helm client](https://docs.helm.sh/using_helm/#installing-the-helm-client)

2. Clone this repository:

       git clone https://github.com/jetstack/cert-manager
       cd cert-manager
       
3. Run `helm init`. This will install Helm server-side
   components to your cluster.
   
4. Install latest version of cert-manager:


       helm install --name cert-manager --namespace kube-system contrib/charts/cert-manager

By default, it will be configured to fulfil `Certificate` resources in all namespaces. There are a number of options you can customise when deploying, as detailed in [the chart itself](../../contrib/charts/cert-manager).
