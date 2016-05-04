# Change Log
All notable changes to this project will be documented in this file.
This project adheres to [Semantic Versioning](http://semver.org/).


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
