// +skip_license_check

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package route53

var ChangeResourceRecordSetsResponse = `<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
<ChangeInfo>
   <Id>/change/123456</Id>
   <Status>PENDING</Status>
   <SubmittedAt>2016-02-10T01:36:41.958Z</SubmittedAt>
</ChangeInfo>
</ChangeResourceRecordSetsResponse>`

var ListHostedZonesByNameResponse = `<?xml version="1.0" encoding="UTF-8"?>
<ListHostedZonesByNameResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
   <HostedZones>
      <HostedZone>
         <Id>/hostedzone/ABCDEFG</Id>
         <Name>example.com.</Name>
         <CallerReference>D2224C5B-684A-DB4A-BB9A-E09E3BAFEA7A</CallerReference>
         <Config>
            <Comment>Test comment</Comment>
            <PrivateZone>false</PrivateZone>
         </Config>
         <ResourceRecordSetCount>10</ResourceRecordSetCount>
      </HostedZone>
      <HostedZone>
         <Id>/hostedzone/HIJKLMN</Id>
         <Name>foo.example.com.</Name>
         <CallerReference>D2224C5B-684A-DB4A-BB9A-E09E3BAFEA7A</CallerReference>
         <Config>
            <Comment>Test comment</Comment>
            <PrivateZone>false</PrivateZone>
         </Config>
         <ResourceRecordSetCount>10</ResourceRecordSetCount>
      </HostedZone>
      <HostedZone>
         <Id>/hostedzone/OPQRSTU</Id>
         <Name>bar.example.com.</Name>
         <CallerReference>D2224C5B-684A-DB4A-BB9A-E09E3BAFEA7A</CallerReference>
         <Config>
            <Comment>Test comment</Comment>
            <PrivateZone>false</PrivateZone>
         </Config>
         <ResourceRecordSetCount>10</ResourceRecordSetCount>
      </HostedZone>
   </HostedZones>
   <IsTruncated>true</IsTruncated>
   <NextDNSName>example2.com</NextDNSName>
   <NextHostedZoneId>ZLT12321321124</NextHostedZoneId>
   <MaxItems>1</MaxItems>
</ListHostedZonesByNameResponse>`

// An example of an error returned by the ListHostedZonesByName API when the
// request contains an invalid domain name:
// - https://docs.aws.amazon.com/Route53/latest/APIReference/API_ListHostedZonesByName.html#API_ListHostedZonesByName_Errors
var ListHostedZonesByName400ResponseInvalidDomainName = `<?xml version="1.0" encoding="UTF-8"?>
<ErrorResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <Error>
	<Code>InvalidDomainName</Code>
	<Message>Simulated message</Message>
	<Resource></Resource>
	<RequestId>SOMEREQUESTID</RequestId>
  </Error>
</ErrorResponse>`

var GetChangeResponse = `<?xml version="1.0" encoding="UTF-8"?>
<GetChangeResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
   <ChangeInfo>
      <Id>123456</Id>
      <Status>INSYNC</Status>
      <SubmittedAt>2016-02-10T01:36:41.958Z</SubmittedAt>
   </ChangeInfo>
</GetChangeResponse>`

var ChangeResourceRecordSets403Response = `<?xml version="1.0"?>
<ErrorResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <Error>
    <Type>Sender</Type>
    <Code>AccessDenied</Code>
    <Message>User: arn:aws:iam::0123456789:user/test-cert-manager is not authorized to perform: route53:ChangeResourceRecordSets on resource: arn:aws:route53:::hostedzone/OPQRSTU</Message>
  </Error>
  <RequestId>SOMEREQUESTID</RequestId>
</ErrorResponse>`

// An example of an error returned by the ChangeResourceRecordSets API when the
// request refers to a record set that does not exist:
// - https://docs.aws.amazon.com/Route53/latest/APIReference/API_ChangeResourceRecordSets.html#API_ChangeResourceRecordSets_Errors
//
// This sample XML error was obtained by capturing an API response from AWS
// using `mitmproxy`, while running `HTTPS_PROXY=localhost:8080 go test ./pkg/issuer/acme/dns/route53/... - v -run Test_Cleanup`,
// with the following ad-hoc Go test:
//
//	func Test_Cleanup(t *testing.T) {
//		l := ktesting.NewLogger(t, ktesting.NewConfig(ktesting.Verbosity(10)))
//		ctx := logr.NewContext(context.Background(), l)
//		p, err := NewDNSProvider(ctx, "", "", "Z0984294TRL0R8AT3SQA", "", "", "", true, []string{}, "cert-manager/tests")
//		require.NoError(t, err)
//		err = p.CleanUp(ctx, "example.com", "www", "foo")
//		require.NoError(t, err)
//	}
//
// NB: This does not match the example in the following file, which may just be out-of-date:
// - https://github.com/aws/aws-sdk-go-v2/blob/f529add9a2cd0d97281fd81f711c620c1e95cfb8/service/route53/internal/customizations/doc.go#L16C1-L21C25
var ChangeResourceRecordSets400Response = `<?xml version="1.0"?>
<ErrorResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
  <Error>
    <Type>Sender</Type>
      <Code>InvalidChangeBatch</Code>
      <Message>Tried to delete resource record set [name='_acme-challenge.example.com.', type='TXT', set-identifier='"5CiRHXrp9tvpLNX8F9M8qbi8u9kwb3xnHrKdLNDlRQA"'] but it was not found</Message>
  </Error>
  <RequestId>SOMEREQUESTID</RequestId>
</ErrorResponse>`
