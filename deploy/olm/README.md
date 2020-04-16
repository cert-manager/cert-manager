# cert-manager operator deployment

This directory cotnains all files that are used to build the [operator](https://operatorhub.io/what-is-an-operator) to deploy cert-manager.
This includes the operator itself, based on the Helm operator as well as Dockerfiles to build [UBI](https://connect.redhat.com/about/faq/what-red-hat-universal-base-image-ubi-0) based images.

Unlike the rest of the project these are not built using Bazel but are used as input to the RedHat image builder.