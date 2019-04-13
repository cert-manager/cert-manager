package admissionreview

import (
	"context"

	admissionv1beta1 "k8s.io/api/admission/v1beta1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apiserver/pkg/registry/rest"
)

type AdmissionHookFunc func(admissionSpec *admissionv1beta1.AdmissionRequest) *admissionv1beta1.AdmissionResponse

type REST struct {
	hookFn AdmissionHookFunc
}

var _ rest.Creater = &REST{}
var _ rest.Scoper = &REST{}
var _ rest.GroupVersionKindProvider = &REST{}

func NewREST(hookFn AdmissionHookFunc) *REST {
	return &REST{
		hookFn: hookFn,
	}
}

func (r *REST) New() runtime.Object {
	return &admissionv1beta1.AdmissionReview{}
}

func (r *REST) GroupVersionKind(containingGV schema.GroupVersion) schema.GroupVersionKind {
	return admissionv1beta1.SchemeGroupVersion.WithKind("AdmissionReview")
}

func (r *REST) NamespaceScoped() bool {
	return false
}

func (r *REST) Create(ctx context.Context, obj runtime.Object, _ rest.ValidateObjectFunc, _ *metav1.CreateOptions) (runtime.Object, error) {
	admissionReview := obj.(*admissionv1beta1.AdmissionReview)
	admissionReview.Response = r.hookFn(admissionReview.Request)
	return admissionReview, nil
}
