package fakes

import (
	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/api/errors"
	"k8s.io/apimachinery/pkg/labels"
	"k8s.io/apimachinery/pkg/runtime/schema"
)

// NamespaceLister is a struct that implements kubernetes api secrets.SecretNamespaceLister interface
// It is used solely for testing to mock calls to list secrets in a namespace
type NamespaceLister struct {
	retVals map[string]*v1.Secret
}

func NewNamespaceLister() *NamespaceLister {
	return &NamespaceLister{
		retVals: make(map[string]*v1.Secret),
	}
}

// List is set to return error as this function does not get called by test code.
func (nl *NamespaceLister) List(selector labels.Selector) ([]*v1.Secret, error) {
	return []*v1.Secret{}, errors.NewNotFound(schema.GroupResource{}, selector.String())
}

func (nl *NamespaceLister) Get(name string) (*v1.Secret, error) {
	secret, ok := nl.retVals[name]
	if !ok {
		return nil, errors.NewNotFound(schema.GroupResource{}, name)
	}

	return secret, nil
}

func (nl *NamespaceLister) Set(name string, secret *v1.Secret) {
	nl.retVals[name] = secret
}
