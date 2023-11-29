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

package helper

import (
	"context"
	"fmt"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/wait"

	"github.com/cert-manager/cert-manager/e2e-tests/framework/log"
)

// WaitForSecretCertificateData waits for the certificate data to be ready
// inside a Secret created by cert-manager.
func (h *Helper) WaitForSecretCertificateData(ns, name string, timeout time.Duration) (*corev1.Secret, error) {
	var secret *corev1.Secret
	logf, done := log.LogBackoff()
	defer done()
	err := wait.PollUntilContextTimeout(context.TODO(), time.Second, timeout, true, func(ctx context.Context) (bool, error) {
		var err error
		logf("Waiting for Secret %s:%s to contain a certificate", ns, name)
		secret, err = h.KubeClient.CoreV1().Secrets(ns).Get(context.TODO(), name, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("error getting secret %s: %s", name, err)
		}

		if len(secret.Data[corev1.TLSCertKey]) > 0 {
			return true, nil
		}

		logf("Secret still does not contain certificate data %s/%s",
			secret.Namespace, secret.Name)
		return false, nil
	})

	if err != nil {
		return nil, err
	}

	return secret, nil
}
