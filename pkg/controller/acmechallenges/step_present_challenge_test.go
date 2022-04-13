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

package acmechallenges

import (
	"context"
	"reflect"
	"testing"

	cmacme "github.com/cert-manager/cert-manager/pkg/apis/acme/v1"
	cmapi "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	v1 "github.com/cert-manager/cert-manager/pkg/apis/certmanager/v1"
	"github.com/cert-manager/cert-manager/pkg/controller/test"
	"k8s.io/client-go/tools/record"
)

func Test_presentChallenge_Initialize(t *testing.T) {
	type fields struct {
		solver   solver
		issuer   cmapi.GenericIssuer
		recorder record.EventRecorder
	}
	type args struct {
		ctx   context.Context
		state *syncState
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name:   "success",
			fields: fields{},
			args: args{
				state: &syncState{
					controller: &controller{},
				},
			},
			wantErr: false,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &presentChallenge{
				solver:   tt.fields.solver,
				issuer:   tt.fields.issuer,
				recorder: tt.fields.recorder,
			}
			if err := o.Initialize(tt.args.ctx, tt.args.state); (err != nil) != tt.wantErr {
				t.Errorf("presentChallenge.Initialize() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func Test_presentChallenge_Evaluate(t *testing.T) {
	type fields struct {
		solver   solver
		issuer   cmapi.GenericIssuer
		recorder record.EventRecorder
	}
	type args struct {
		ctx context.Context
		ch  *cmacme.Challenge
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		want    syncAction
		wantErr bool
	}{
		{
			name: "presented",
			args: args{
				ch: &cmacme.Challenge{
					Status: cmacme.ChallengeStatus{
						Presented: true,
					},
				},
			},
			want: nil,
		},
		{
			name: "not-presented",
			args: args{
				ch: &cmacme.Challenge{
					Status: cmacme.ChallengeStatus{
						Presented: false,
					},
				},
			},
			want: &presentChallenge{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &presentChallenge{
				solver:   tt.fields.solver,
				issuer:   tt.fields.issuer,
				recorder: tt.fields.recorder,
			}
			got, err := o.Evaluate(tt.args.ctx, tt.args.ch)
			if (err != nil) != tt.wantErr {
				t.Errorf("presentChallenge.Evaluate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("presentChallenge.Evaluate() = %v, want %v", got, tt.want)
			}
		})
	}
}

func Test_presentChallenge_Run(t *testing.T) {
	type fields struct {
		solver   solver
		issuer   cmapi.GenericIssuer
		recorder record.EventRecorder
	}
	type args struct {
		ctx context.Context
		ch  *cmacme.Challenge
	}
	tests := []struct {
		name    string
		fields  fields
		args    args
		wantErr bool
	}{
		{
			name: "success",
			fields: fields{
				solver: &fakeSolver{
					fakePresent: func(_ context.Context, _ v1.GenericIssuer, _ *cmacme.Challenge) error {
						return nil
					},
				},
				recorder: &test.FakeRecorder{},
			},
			args: args{
				ch: &cmacme.Challenge{
					Spec: cmacme.ChallengeSpec{
						Type: cmacme.ACMEChallengeTypeDNS01,
					},
				},
			},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			o := &presentChallenge{
				solver:   tt.fields.solver,
				issuer:   tt.fields.issuer,
				recorder: tt.fields.recorder,
			}
			if err := o.Run(tt.args.ctx, tt.args.ch); (err != nil) != tt.wantErr {
				t.Errorf("presentChallenge.Run() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}
