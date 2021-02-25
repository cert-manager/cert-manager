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
	"fmt"
	"reflect"
	"time"

	corev1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/errors"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	internalapi "github.com/cert-manager/cert-manager/pkg/internal/apis/certmanager"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
	"github.com/cert-manager/cert-manager/pkg/webhook"
)

const (
	errorInitIssuer = "ErrInitIssuer"
	errorConfig     = "ConfigError"

	messageErrorInitIssuer = "Error initializing issuer: "
)

func (c *controller) Sync(ctx context.Context, iss *v1.Issuer) (err error) {
	log := logf.FromContext(ctx)

	issuerCopy := iss.DeepCopy()
	defer func() {
		if _, saveErr := c.updateIssuerStatus(iss, issuerCopy); saveErr != nil {
			err = errors.NewAggregate([]error{saveErr, err})
		}
	}()

	el := webhook.ValidationRegistry.Validate(issuerCopy, internalapi.SchemeGroupVersion.WithKind("Issuer"))
	if len(el) > 0 {
		msg := fmt.Sprintf("Resource validation failed: %v", el.ToAggregate())
		apiutil.SetIssuerCondition(issuerCopy, v1.IssuerConditionReady, cmmeta.ConditionFalse, errorConfig, msg)
		return
	}

	// Remove existing ErrorConfig condition if it exists
	for i, c := range issuerCopy.Status.Conditions {
		if c.Type == v1.IssuerConditionReady {
			if c.Reason == errorConfig && c.Status == cmmeta.ConditionFalse {
				issuerCopy.Status.Conditions = append(issuerCopy.Status.Conditions[:i], issuerCopy.Status.Conditions[i+1:]...)
				break
			}
		}
	}

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

func (c *controller) updateIssuerStatus(old, new *v1.Issuer) (*v1.Issuer, error) {
	if reflect.DeepEqual(old.Status, new.Status) {
		return nil, nil
	}
	return c.cmClient.CertmanagerV1().Issuers(new.Namespace).UpdateStatus(context.TODO(), new, metav1.UpdateOptions{})
}
