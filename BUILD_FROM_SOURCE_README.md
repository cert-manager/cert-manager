# Build Instructions

The base tag this release is branched from is `v0.13.1`


## Requirements
**bazel : any version >= 0.22.0**

[Install Bazel - macOS](https://docs.bazel.build/versions/master/install-os-x.html)  

[GitHub Releases](https://github.com/bazelbuild/bazel/releases)  

Verify Build and Generate Images Locally 
 
```  
export APP_VERSION=<Image Tag>
export DOCKER_REPO=<Docker Repository>
make generate 
make controller 
make images  
```  

Build and Push Images

```
# Build and publish cert-manager-controller
export DOCKER_REPO=<Docker Repository>
export DOCKER_NAMESPACE=<Docker Namespace>
export DOCKER_TAG=<Image Tag>

docker build --file dockerfiles/controller/Dockerfile --tag ${DOCKER_REPO}/${DOCKER_NAMESPACE}/cert-manager-controller:${DOCKER_TAG} .
docker push ${DOCKER_REPO}/${DOCKER_NAMESPACE}/cert-manager-controller:${DOCKER_TAG}

# Build and publish cert-manager-acmesolver 
docker build --file dockerfiles/solver/Dockerfile --tag ${DOCKER_REPO}/${DOCKER_NAMESPACE}/cert-manager-acmesolver:${DOCKER_TAG} .
docker push ${DOCKER_REPO}/${DOCKER_NAMESPACE}/cert-manager-acmesolver:${DOCKER_TAG}
```

## How to Run local unit tests  

### Run OCI DNS tests
Note: this will add an _acme-challenge to the OCI Dns Zone of your choice. 

```
export OCI_ZONE_NAME=< your test zone >
export OCI_KEYPATH=< Path to your OCI key >
export OCI_FINGERPRINT=< fingerprint >
export OCI_USER_ID=ocid1.user.oc1..aXxxxx...
export OCI_TENANCY_ID=ocid1.tenancy.oc1..XxXxx...
export OCI_REGION=< region name >
export OCI_COMPARTMENT_ID=ocid1.compartment.oc1..XXXXXXX...

cd  pkg/issuer/acme/dns/ocidns

go test -v
```
