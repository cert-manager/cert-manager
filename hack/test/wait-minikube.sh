#!/bin/bash

set -o errexit
set -o nounset
set -o pipefail

while true; do if kubectl get nodes; then break; fi; echo "Waiting 5s for kubernetes to be ready..."; sleep 5; done

echo "Installing helm..."
cat <<EOF | kubectl apply -f -
apiVersion: v1
kind: List
items:

### Tiller ###
# Create a ServiceAccount for tiller to use
- apiVersion: v1
  kind: ServiceAccount
  metadata:
    name: tiller
    namespace: kube-system
# Bind tiller to the cluster-admin role
- apiVersion: rbac.authorization.k8s.io/v1beta1
  kind: ClusterRoleBinding
  metadata:
    name: "tiller"
  roleRef:
    apiGroup: rbac.authorization.k8s.io
    kind: ClusterRole
    name: "cluster-admin"
  subjects:
  - apiGroup: ""
    kind: ServiceAccount
    name: tiller
    namespace: kube-system
EOF
helm init --service-account=tiller
