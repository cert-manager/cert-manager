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

package issuers

import (
	"context"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/errors"

	cmapi "github.com/jetstack/cert-manager/pkg/apis/certmanager/v1"
	logf "github.com/jetstack/cert-manager/pkg/logs"
)

const (
	errorInitIssuer = "ErrInitIssuer"

	messageErrorInitIssuer = "Error initializing issuer: "
)

func (c *controller) Sync(ctx context.Context, iss *cmapi.Issuer) (err error) {
	log := logf.FromContext(ctx)

	issuerCopy := iss.DeepCopy()
	defer func() {
		if _, saveErr := c.updateIssuerStatus(iss, issuerCopy); saveErr != nil {
			err = errors.NewAggregate([]error{saveErr, err})
		}
	}()

	i, err := c.issuerFactory.IssuerFor(issuerCopy)
	if err != nil {
		return err
	}

	// allow a maximum of 10s
	ctx, cancel := context.WithTimeout(ctx, time.Second*10)
	defer cancel()
	err = i.Setup(ctx)
	if err != nil {
		s := messageErrorInitIssuer + err.Error()
		log.V(logf.WarnLevel).Info(s)
		c.recorder.Event(issuerCopy, corev1.EventTypeWarning, errorInitIssuer, s)
		return err
	}

	return nil
}

func (c *controller) updateIssuerStatus(old, new *cmapi.Issuer) (*cmapi.Issuer, error) {
	if reflect.DeepEqual(old.Status, new.Status) {
		return nil, nil
	}
	return c.cmClient.CertmanagerV1().Issuers(new.Namespace).UpdateStatus(context.TODO(), new, metav1.UpdateOptions{})
}
