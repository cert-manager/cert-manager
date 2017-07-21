package v1alpha1

const (
	// AnnotationIngressACMETLS is an annotation that can be added to an
	// ingress resource that signals the resource should have an automatically
	// provisioned TLS certificate
	AnnotationIngressACMETLS = "certmanager.kubernetes.io/enabled"
)
