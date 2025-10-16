/*
Copyright 2025 The cert-manager Authors.

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

package azuredns

import (
	"context"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	dns "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
	privatedns "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/privatedns/armprivatedns"
)

// PrivateRecordsClient is an interface shim to make sure we can mock the clients since RecordSetsClient are structs and not interfaces.
type PrivateRecordsClient interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, privateZoneName string, recordType privatedns.RecordType, relativeRecordSetName string, parameters privatedns.RecordSet, options *privatedns.RecordSetsClientCreateOrUpdateOptions) (privatedns.RecordSetsClientCreateOrUpdateResponse, error)
	Get(ctx context.Context, resourceGroupName string, privateZoneName string, recordType privatedns.RecordType, relativeRecordSetName string, options *privatedns.RecordSetsClientGetOptions) (privatedns.RecordSetsClientGetResponse, error)
	Delete(ctx context.Context, resourceGroupName string, privateZoneName string, recordType privatedns.RecordType, relativeRecordSetName string, options *privatedns.RecordSetsClientDeleteOptions) (privatedns.RecordSetsClientDeleteResponse, error)
}

// PrivateZonesClient is an interface shim for mocking the PrivateZonesClient since they are structs and not interfaces.
type PrivateZonesClient interface {
	Get(ctx context.Context, resourceGroupName string, privateZoneName string, options *privatedns.PrivateZonesClientGetOptions) (privatedns.PrivateZonesClientGetResponse, error)
}

type TXTRecordSet interface {
	GetTXTRecords() [][]*string
	AppendTXTRecord(val string)
}

type PrivateTXTRecordSet struct {
	RS *privatedns.RecordSet
}

func (ps *PrivateTXTRecordSet) GetTXTRecords() [][]*string {
	if ps.RS == nil || ps.RS.Properties == nil {
		return nil
	}

	out := make([][]*string, 0, len(ps.RS.Properties.TxtRecords))
	for _, txtRec := range ps.RS.Properties.TxtRecords {
		out = append(out, txtRec.Value)
	}

	return out
}

func (ps *PrivateTXTRecordSet) AppendTXTRecord(value string) {
	if ps.RS == nil || ps.RS.Properties == nil {
		return
	}

	var found bool
	var records []*privatedns.TxtRecord
	for _, r := range ps.RS.Properties.TxtRecords {
		if len(r.Value) > 0 && *r.Value[0] == value {
			found = true
		} else {
			records = append(records, r)
		}
	}

	if !found {
		ps.RS.Properties.TxtRecords = append(ps.RS.Properties.TxtRecords, &privatedns.TxtRecord{
			Value: []*string{to.Ptr(value)},
		})
	} else {
		ps.RS.Properties.TxtRecords = records
	}
}

type PublicTXTRecordSet struct {
	RS *dns.RecordSet
}

func (ps *PublicTXTRecordSet) GetTXTRecords() [][]*string {
	if ps.RS == nil || ps.RS.Properties == nil {
		return nil
	}

	out := make([][]*string, 0, len(ps.RS.Properties.TxtRecords))
	for _, txtRec := range ps.RS.Properties.TxtRecords {
		out = append(out, txtRec.Value)
	}

	return out
}

func (ps *PublicTXTRecordSet) AppendTXTRecord(value string) {
	if ps.RS == nil || ps.RS.Properties == nil {
		return
	}

	var found bool
	var records []*dns.TxtRecord
	for _, r := range ps.RS.Properties.TxtRecords {
		if len(r.Value) > 0 && *r.Value[0] == value {
			found = true
		} else {
			records = append(records, r)
		}
	}

	if !found {
		ps.RS.Properties.TxtRecords = append(ps.RS.Properties.TxtRecords, &dns.TxtRecord{
			Value: []*string{to.Ptr(value)},
		})
	} else {
		ps.RS.Properties.TxtRecords = records
	}
}
