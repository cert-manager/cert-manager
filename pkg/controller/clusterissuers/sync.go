/*
Copyright 2019 The Jetstack cert-manager contributors.

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

package clusterissuers

import (
	"context"
	"fmt"
	"reflect"

	"k8s.io/api/core/v1"
	"k8s.io/apimachinery/pkg/util/errors"
	"k8s.io/klog"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/validation"
)

const (
	errorInitIssuer = "ErrInitIssuer"
	errorConfig     = "ConfigError"

	messageErrorInitIssuer = "Error initializing issuer: "
)

func (c *Controller) Sync(ctx context.Context, iss *v1alpha1.ClusterIssuer) (err error) {
	issuerCopy := iss.DeepCopy()
	defer func() {
		if _, saveErr := c.updateIssuerStatus(iss, issuerCopy); saveErr != nil {
			err = errors.NewAggregate([]error{saveErr, err})
		}
	}()

	el := validation.ValidateClusterIssuer(issuerCopy)
	if len(el) > 0 {
		msg := fmt.Sprintf("Resource validation failed: %v", el.ToAggregate())
		apiutil.SetIssuerCondition(issuerCopy, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse, errorConfig, msg)
		return
	}

	// Remove existing ErrorConfig condition if it exists
	for i, c := range issuerCopy.Status.Conditions {
		if c.Type == v1alpha1.IssuerConditionReady {
			if c.Reason == errorConfig && c.Status == v1alpha1.ConditionFalse {
				issuerCopy.Status.Conditions = append(issuerCopy.Status.Conditions[:i], issuerCopy.Status.Conditions[i+1:]...)
				break
			}
		}
	}

	i, err := c.issuerFactory.IssuerFor(issuerCopy)

	if err != nil {
		return err
	}

	err = i.Setup(ctx)
	if err != nil {
		s := messageErrorInitIssuer + err.Error()
		klog.Info(s)
		c.Recorder.Event(issuerCopy, v1.EventTypeWarning, errorInitIssuer, s)
		return err
	}

	return nil
}

func (c *Controller) updateIssuerStatus(old, new *v1alpha1.ClusterIssuer) (*v1alpha1.ClusterIssuer, error) {
	if reflect.DeepEqual(old.Status, new.Status) {
		return nil, nil
	}
	// TODO: replace Update call with UpdateStatus. This requires a custom API
	// server with the /status subresource enabled and/or subresource support
	// for CRDs (https://github.com/kubernetes/kubernetes/issues/38113)
	return c.CMClient.CertmanagerV1alpha1().ClusterIssuers().Update(new)
}
