package fakes

import "k8s.io/api/core/v1"

func NewSecret(key, value string) *v1.Secret {
	data := make(map[string][]byte)
	data[key] = []byte(value)

	return &v1.Secret{Data: data}
}
