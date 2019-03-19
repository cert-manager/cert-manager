/*
Copyright 2018 The Jetstack cert-manager contributors.

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

package venafi

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"
	"k8s.io/klog"

	apiutil "github.com/jetstack/cert-manager/pkg/api/util"
	"github.com/jetstack/cert-manager/pkg/apis/certmanager/v1alpha1"
)

func (v *Venafi) Setup(ctx context.Context) error {
	err := v.client.Ping()
	if err != nil {
		klog.Infof("Issuer could not connect to endpoint with provided credentials. Issuer failed to connect to endpoint\n")
		apiutil.SetIssuerCondition(v.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionFalse,
			"ErrorPing", fmt.Sprintf("Failed to connect to Venafi endpoint"))
		return fmt.Errorf("error verifying Venafi client: %s", err.Error())
	}

	// If it does not already have a 'ready' condition, we'll also log an event
	// to make it really clear to users that this Issuer is ready.
	if !apiutil.IssuerHasCondition(v.issuer, v1alpha1.IssuerCondition{
		Type:   v1alpha1.IssuerConditionReady,
		Status: v1alpha1.ConditionTrue,
	}) {
		v.Recorder.Eventf(v.issuer, corev1.EventTypeNormal, "Ready", "Verified issuer with Venafi server")
	}

	klog.Info("Venafi issuer started")
	apiutil.SetIssuerCondition(v.issuer, v1alpha1.IssuerConditionReady, v1alpha1.ConditionTrue, "Venafi issuer started", "Venafi issuer started")

	return nil
}
