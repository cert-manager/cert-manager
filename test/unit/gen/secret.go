/*
Copyright 2020 The cert-manager Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package gen

import (
	corev1 "k8s.io/api/core/v1"
)

type SecretModifier func(*corev1.Secret)

func Secret(name string, mods ...SecretModifier) *corev1.Secret {
	c := &corev1.Secret{
		ObjectMeta: ObjectMeta(name),
	}
	for _, mod := range mods {
		mod(c)
	}
	return c
}

func SecretFrom(sec *corev1.Secret, mods ...SecretModifier) *corev1.Secret {
	sec = sec.DeepCopy()
	for _, mod := range mods {
		mod(sec)
	}
	return sec
}

func SetSecretNamespace(namespace string) SecretModifier {
	return func(sec *corev1.Secret) {
		sec.ObjectMeta.Namespace = namespace
	}
}

func SetSecretAnnotations(an map[string]string) SecretModifier {
	return func(sec *corev1.Secret) {
		sec.Annotations = make(map[string]string)
		for k, v := range an {
			sec.Annotations[k] = v
		}
	}
}

func SetSecretData(data map[string][]byte) SecretModifier {
	return func(sec *corev1.Secret) {
		sec.Data = make(map[string][]byte)
		for k, v := range data {
			sec.Data[k] = v
		}
	}
}
