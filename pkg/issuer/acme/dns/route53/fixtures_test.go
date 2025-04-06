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

/*
This file contains portions of code directly taken from the 'xenolf/lego' project.
A copy of the license for this code can be found in the file named LICENSE in
this directory.
*/

package route53

// https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRoleWithWebIdentity.html#API_AssumeRoleWithWebIdentity_Examples
var AssumeRoleWithWebIdentityResponse = `<?xml version="1.0" encoding="UTF-8"?>
<AssumeRoleWithWebIdentityResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleWithWebIdentityResult>
    <SubjectFromWebIdentityToken>amzn1.account.AF6RHO7KZU5XRVQJGXK6HB56KR2A</SubjectFromWebIdentityToken>
    <Audience>client.5498841531868486423.1548@apps.example.com</Audience>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/FederatedWebIdentityRole/app1</Arn>
      <AssumedRoleId>AROACLKWSDQRAOEXAMPLE:app1</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <SessionToken>AQoDYXdzEE0a8ANXXXXXXXXNO1ewxE5TijQyp+IEXAMPLE</SessionToken>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
      <Expiration>2014-10-24T23:00:23Z</Expiration>
      <AccessKeyId>ASgeIAIOSFODNN7EXAMPLE</AccessKeyId>
    </Credentials>
    <SourceIdentity>SourceIdentityValue</SourceIdentity>
    <Provider>www.amazon.com</Provider>
  </AssumeRoleWithWebIdentityResult>
  <ResponseMetadata>
    <RequestId>ad4156e9-bce1-11e2-82e6-6b6efEXAMPLE</RequestId>
  </ResponseMetadata>
</AssumeRoleWithWebIdentityResponse>`

// https://docs.aws.amazon.com/STS/latest/APIReference/CommonErrors.html
var AssumeRoleWithWebIdentity400Response = `<?xml version="1.0"?>
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
	<Type>Sender</Type>
	<Code>ValidationError</Code>
	<Message>Request ARN is invalid</Message>
  </Error>
  <RequestId>ad4156e9-bce1-11e2-82e6-6b6efEXAMPLE</RequestId>
</ErrorResponse>
`

// https://docs.aws.amazon.com/STS/latest/APIReference/API_AssumeRole.html#API_AssumeRole_Examples
var AssumeRoleResponse = `<?xml version="1.0"?>
<AssumeRoleResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <AssumeRoleResult>
  <SourceIdentity>Alice</SourceIdentity>
    <AssumedRoleUser>
      <Arn>arn:aws:sts::123456789012:assumed-role/demo/TestAR</Arn>
      <AssumedRoleId>ARO123EXAMPLE123:TestAR</AssumedRoleId>
    </AssumedRoleUser>
    <Credentials>
      <AccessKeyId>ASIAIOSFODNN7EXAMPLE</AccessKeyId>
      <SecretAccessKey>wJalrXUtnFEMI/K7MDENG/bPxRfiCYzEXAMPLEKEY</SecretAccessKey>
      <SessionToken>
       AQoDYXdzEPT//////////wEXAMPLEtc764bNrC9SAPBSM22wDOk4x4HIZ8j4FZTwdQW
       LWsKWHGBuFqwAeMicRXmxfpSPfIeoIYRqTflfKD8YUuwthAx7mSEI/qkPpKPi/kMcGd
       QrmGdeehM4IC1NtBmUpp2wUE8phUZampKsburEDy0KPkyQDYwT7WZ0wq5VSXDvp75YU
       9HFvlRd8Tx6q6fE8YQcHNVXAkiY9q6d+xo0rKwT38xVqr7ZD0u0iPPkUL64lIZbqBAz
       +scqKmlzm8FDrypNC9Yjc8fPOLn9FX9KSYvKTr4rvx3iSIlTJabIQwj2ICCR/oLxBA==
      </SessionToken>
      <Expiration>2019-11-09T13:34:41Z</Expiration>
    </Credentials>
    <PackedPolicySize>6</PackedPolicySize>
  </AssumeRoleResult>
  <ResponseMetadata>
    <RequestId>c6104cbe-af31-11e0-8154-cbc7ccf896c7</RequestId>
  </ResponseMetadata>
</AssumeRoleResponse>
`

// https://docs.aws.amazon.com/STS/latest/APIReference/CommonErrors.html
var AssumeRole403Response = `<?xml version="1.0"?>
<ErrorResponse xmlns="https://sts.amazonaws.com/doc/2011-06-15/">
  <Error>
	<Type>Sender</Type>
	<Code>InvalidClientTokenId</Code>
	<Message>The security token included in the request is invalid.</Message>
  </Error>
  <RequestId>ad4156e9-bce1-11e2-82e6-6b6efEXAMPLE</RequestId>
</ErrorResponse>
`

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
