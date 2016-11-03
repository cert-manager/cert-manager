# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).

## [0.1.3] - 2016-11-03

### Fixed

- Workaround for GLBC health check detection bug
- Raise resync period to 60 seconds
- Use correct minimum validity config (used the `LEGO_CHECK_INTERVAL` before)

### Added

* Replace lego with the acme library
* Increase tests coverage and automation
* Improved log output, no secrets default log level is debug
* Upgrade dependencies
* Upgrade to go 1.7.3
* Possibility to change api server url [Pavel Sorejs]

## [0.1.2] - 2016-08-19

### Fixed

- Better error output for failing validations
- Fix problems with updating ingress objects

## [0.1.1] - 2016-08-16

### Fixed

- Fix version output of kube-lego
- Fix image version in the docs

## [0.1.0] - 2016-08-10

### Added

- Support for GCE load balancer ingress controller
- E2E automation scripts for GCE/NGINX ingress controllers on GKE
- Support for ingress-class annotations to distinguish between GCE/NGINX ingress
- Abstracted the ingress controller specific code into separate packages
- Deployment of kube-lego uses readiness checks

### Fixed

- Handle failed certificate request without exiting kube-lego


## [0.0.4] - 2016-07-11
### Added
- Check for expired certificates periodically (default config every 8 hours)
- Use upstream nginx-ingress-controller (from k8s-contrib)

### Fixed
- Fix bug for empty kube-lego ingress resource

## [0.0.3] - 2016-05-27
### Added
- E2E test for receiving a cert from Let's Encrypt Staging
- Updating docs/examples to use latest nginx-ingress release

## [0.0.2] - 2016-05-03
### Added
- Documentation
- Versioned docker images
- Jenkins builds using pipelines/workflow plugin

## [0.0.1] - 2016-05-03 - MVP release
### Added
- Recognizes the need of a new certificate (domain name missing, certificate expired, certificate unparseable)
- Obtains certificates per TLS object in ingress resources and stores it in Kubernetes secrets using `HTTP-01` challenge
- Creates a user account (incl. private key) for Let's Encrypt and stores it in Kubernetes secrets
- Watches changes of ingress resources and reevaluate certificates
- Configures endpoints for `HTTP-01` challenge in a separate ingress resource
