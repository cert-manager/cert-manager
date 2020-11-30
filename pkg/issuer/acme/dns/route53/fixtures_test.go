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
