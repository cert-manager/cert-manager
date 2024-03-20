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

package venafi

import (
	"context"
	"fmt"

	corev1 "k8s.io/api/core/v1"

	apiutil "github.com/cert-manager/cert-manager/pkg/api/util"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	cmmeta "github.com/cert-manager/cert-manager/pkg/apis/meta/v1"
	logf "github.com/cert-manager/cert-manager/pkg/logs"
)

func (v *Venafi) Setup(ctx context.Context) (err error) {
	defer func() {
		if err != nil {
			errorMessage := "Failed to setup Venafi issuer"
			v.log.Error(err, errorMessage)
			apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), cmapi.IssuerConditionReady, cmmeta.ConditionFalse, "ErrorSetup", fmt.Sprintf("%s: %v", errorMessage, err))
			err = fmt.Errorf("%s: %v", errorMessage, err)
		}
	}()

	client, err := v.clientBuilder(v.resourceNamespace, v.secretsLister, v.issuer, v.Metrics, v.log, v.userAgent)
	if err != nil {
		return fmt.Errorf("error building client: %v", err)
	}
	err = client.Ping()
	if err != nil {
		return fmt.Errorf("error pinging Venafi API: %v", err)
	}

	err = client.VerifyCredentials()
	if err != nil {
		return fmt.Errorf("client.VerifyCredentials: %v", err)
	}

	// If it does not already have a 'ready' condition, we'll also log an event
	// to make it really clear to users that this Issuer is ready.
	if !apiutil.IssuerHasCondition(v.issuer, cmapi.IssuerCondition{
		Type:   cmapi.IssuerConditionReady,
		Status: cmmeta.ConditionTrue,
	}) {
		v.Recorder.Eventf(v.issuer, corev1.EventTypeNormal, "Ready", "Verified issuer with Venafi server")
	}
	v.log.V(logf.DebugLevel).Info("Venafi issuer started")
	apiutil.SetIssuerCondition(v.issuer, v.issuer.GetGeneration(), cmapi.IssuerConditionReady, cmmeta.ConditionTrue, "Venafi issuer started", "Venafi issuer started")

	return nil
}
