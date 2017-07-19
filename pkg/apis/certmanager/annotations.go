package certmanager

var (
	// AnnotationIngressACMETLS is an annotation that can be added to an
	// ingress resource that signals the resource should have an automatically
	// provisioned TLS certificate
	AnnotationIngressACMETLS = "kubernetes.io/tls-acme"
)
