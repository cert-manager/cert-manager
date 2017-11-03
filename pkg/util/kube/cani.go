package kube

import (
	authz "k8s.io/api/authorization/v1beta1"
	"k8s.io/client-go/kubernetes"
)

func CanI(cl kubernetes.Interface, namespace, verb, group, resource, name string) (ok bool, reason string, err error) {
	review := &authz.SelfSubjectAccessReview{
		Spec: authz.SelfSubjectAccessReviewSpec{
			ResourceAttributes: &authz.ResourceAttributes{
				Namespace: namespace,
				Verb:      verb,
				Group:     group,
				Resource:  resource,
				Name:      name,
			},
		},
	}
	review, err = cl.AuthorizationV1beta1().SelfSubjectAccessReviews().Create(review)
	if err != nil {
		return
	}
	ok = review.Status.Allowed
	reason = review.Status.Reason
	return
}
