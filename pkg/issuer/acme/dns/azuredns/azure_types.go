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
	"errors"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/to"
	dns "github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/dns/armdns"
)

type ClientOptions struct {
	IfMatch     *string
	IfNoneMatch *string
}

// RecordSet represents an abstraction over both privatedns.RecordSet and dns.RecordSet.
type RecordSet interface {
	GetTXTRecords() [][]*string
	SetTXTRecords(records [][]*string)
	GetETag() *string
}

// RecordsClient is a wrapper interface around the Azure SDK RecordsClient. This interface should satisfy both public and
// private record clients and also allow us to implement mock testing.
type RecordsClient interface {
	CreateOrUpdate(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, set RecordSet, options *ClientOptions) (RecordSet, error)
	Get(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, options *ClientOptions) (RecordSet, error)
	Delete(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, options *ClientOptions) error
}

type ZonesClient interface {
	Get(ctx context.Context, resourceGroupName string, zoneName string, options *ClientOptions) error
}

// PublicRecordsClient is a wrapper around the Azure SDK RecordSetsClient for public DNS zones.
type PublicRecordsClient struct {
	client *dns.RecordSetsClient
}

func NewPublicRecordsClient(cl *dns.RecordSetsClient) RecordsClient {
	return &PublicRecordsClient{
		client: cl,
	}
}

func (ps *PublicRecordsClient) CreateOrUpdate(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, set RecordSet, options *ClientOptions) (RecordSet, error) {
	pubSet, ok := set.(*PublicTXTRecordSet)
	if !ok {
		return nil, errors.New("unable to type cast")
	}
	opt := new(dns.RecordSetsClientCreateOrUpdateOptions)
	opt.IfMatch = options.IfMatch
	opt.IfNoneMatch = options.IfNoneMatch

	resp, err := ps.client.CreateOrUpdate(ctx, resourceGroupName, zoneName, relativeRecordSetName, dns.RecordTypeTXT, *pubSet.RS, opt)
	if err != nil {
		return nil, err
	}

	return &PublicTXTRecordSet{RS: &resp.RecordSet}, nil
}

func (ps *PublicRecordsClient) Get(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, options *ClientOptions) (RecordSet, error) {
	opt := new(dns.RecordSetsClientGetOptions)
	resp, err := ps.client.Get(ctx, resourceGroupName, zoneName, relativeRecordSetName, dns.RecordTypeTXT, opt)
	if err != nil {
		return nil, err
	}

	return &PublicTXTRecordSet{RS: &resp.RecordSet}, nil
}

func (ps *PublicRecordsClient) Delete(ctx context.Context, resourceGroupName string, zoneName string, relativeRecordSetName string, options *ClientOptions) error {
	opt := new(dns.RecordSetsClientDeleteOptions)
	opt.IfMatch = options.IfMatch

	_, err := ps.client.Delete(ctx, resourceGroupName, zoneName, relativeRecordSetName, dns.RecordTypeTXT, opt)
	if err != nil {
		return err
	}

	return nil
}

type PublicZonesClient struct {
	client *dns.ZonesClient
}

func NewPublicZonesClient(cl *dns.ZonesClient) ZonesClient {
	return &PublicZonesClient{
		client: cl,
	}
}

func (pc *PublicZonesClient) Get(ctx context.Context, resourceGroupName string, zoneName string, options *ClientOptions) error {
	opt := new(dns.ZonesClientGetOptions)
	_, err := pc.client.Get(ctx, resourceGroupName, zoneName, opt)
	if err != nil {
		return err
	}

	return nil
}

type PublicTXTRecordSet struct {
	RS *dns.RecordSet
}

func (ps *PublicTXTRecordSet) GetETag() *string {
	if ps.RS == nil {
		return nil
	}
	return ps.RS.Etag
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

func (ps *PublicTXTRecordSet) SetTXTRecords(records [][]*string) {
	if ps.RS == nil || ps.RS.Properties == nil {
		ps.RS = &dns.RecordSet{
			Properties: &dns.RecordSetProperties{
				TTL:        to.Ptr[int64](60),
				TxtRecords: []*dns.TxtRecord{},
			},
			Etag: to.Ptr(""),
		}
	}

	var txtRecords []*dns.TxtRecord
	for _, r := range records {
		txtRecords = append(txtRecords, &dns.TxtRecord{
			Value: r,
		})
	}

	ps.RS.Properties.TxtRecords = txtRecords
}
