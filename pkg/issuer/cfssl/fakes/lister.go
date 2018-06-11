package fakes

import (
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
	listersv1 "k8s.io/client-go/listers/core/v1"
)

// Lister is a struct that implements kubernetes api secrets.SecretLister interface
// It is used solely for testing to mock calls to list secrets
type Lister struct {
	NamespaceLister *NamespaceLister
}

func NewLister() *Lister {
	return &Lister{
		NamespaceLister: NewNamespaceLister(),
	}
}

// List is set to return error as this function does not get called by test code.
func (l *Lister) List(selector labels.Selector) ([]*v1.Secret, error) {
	return []*v1.Secret{}, errors.NewNotFound(schema.GroupResource{}, selector.String())
}

func (l *Lister) Secrets(namespace string) listersv1.SecretNamespaceLister {
	return l.NamespaceLister
}

func (l *Lister) Set(name string, secret *v1.Secret) {
	l.NamespaceLister.Set(name, secret)
}
