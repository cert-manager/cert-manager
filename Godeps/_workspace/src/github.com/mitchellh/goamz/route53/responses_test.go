package route53

var CreateHostedZoneExample = `<?xml version="1.0" encoding="UTF-8"?>
<CreateHostedZoneResponse xmlns="https://route53.amazonaws.com/doc/
2013-04-01/">
   <HostedZone>
      <Id>/hostedzone/Z1PA6795UKMFR9</Id>
      <Name>example.com.</Name>
      <CallerReference>myUniqueIdentifier</CallerReference>
      <Config>
         <Comment>This is my first hosted zone.</Comment>
      </Config>
      <ResourceRecordSetCount>2</ResourceRecordSetCount>
   </HostedZone>
   <ChangeInfo>
      <Id>/change/C1PA6795UKMFR9</Id>
      <Status>PENDING</Status>
      <SubmittedAt>2012-03-15T01:36:41.958Z</SubmittedAt>
   </ChangeInfo>
   <DelegationSet>
      <NameServers>
         <NameServer>ns-2048.awsdns-64.com</NameServer>
         <NameServer>ns-2049.awsdns-65.net</NameServer>
         <NameServer>ns-2050.awsdns-66.org</NameServer>
         <NameServer>ns-2051.awsdns-67.co.uk</NameServer>
      </NameServers>
   </DelegationSet>
</CreateHostedZoneResponse>`

var DeleteHostedZoneExample = `<?xml version="1.0" encoding="UTF-8"?>
<DeleteHostedZoneResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
   <ChangeInfo>
      <Id>/change/C1PA6795UKMFR9</Id>
      <Status>PENDING</Status>
      <SubmittedAt>2012-03-10T01:36:41.958Z</SubmittedAt>
   </ChangeInfo>
</DeleteHostedZoneResponse>`

var GetHostedZoneExample = `<?xml version="1.0" encoding="UTF-8"?>
<GetHostedZoneResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
   <HostedZone>
      <Id>/hostedzone/Z1PA6795UKMFR9</Id>
      <Name>example.com.</Name>
      <CallerReference>myUniqueIdentifier</CallerReference>
      <Config>
         <Comment>This is my first hosted zone.</Comment>
      </Config>
      <ResourceRecordSetCount>17</ResourceRecordSetCount>
   </HostedZone>
   <DelegationSet>
      <NameServers>
         <NameServer>ns-2048.awsdns-64.com</NameServer>
         <NameServer>ns-2049.awsdns-65.net</NameServer>
         <NameServer>ns-2050.awsdns-66.org</NameServer>
         <NameServer>ns-2051.awsdns-67.co.uk</NameServer>
      </NameServers>
   </DelegationSet>
</GetHostedZoneResponse>`

var GetChangeExample = `<?xml version="1.0" encoding="UTF-8"?>
<GetChangeResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
   <ChangeInfo>
      <Id>C2682N5HXP0BZ4</Id>
      <Status>INSYNC</Status>
      <SubmittedAt>2011-09-10T01:36:41.958Z</SubmittedAt>
   </ChangeInfo>
</GetChangeResponse>`

var ChangeResourceRecordSetsExample = `<?xml version="1.0" encoding="UTF-8"?>
<ChangeResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
   <ChangeInfo>
      <Id>/change/asdf</Id>
      <Status>PENDING</Status>
      <SubmittedAt>2014</SubmittedAt>
   </ChangeInfo>
</ChangeResourceRecordSetsResponse>`

var ListResourceRecordSetsExample = `<?xml version="1.0" encoding="UTF-8"?>
<ListResourceRecordSetsResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
   <ResourceRecordSets>
      <ResourceRecordSet>
         <Name>example.com.</Name>
         <Type>SOA</Type>
         <TTL>900</TTL>
         <ResourceRecords>
            <ResourceRecord>
               <Value>ns-2048.awsdns-64.net. hostmaster.awsdns.com. 1 7200 900 1209600 86400</Value>
            </ResourceRecord>
         </ResourceRecords>
      </ResourceRecordSet>
   </ResourceRecordSets>
   <IsTruncated>true</IsTruncated>
   <MaxItems>1</MaxItems>
   <NextRecordName>testdoc2.example.com</NextRecordName>
   <NextRecordType>NS</NextRecordType>
</ListResourceRecordSetsResponse>`

var ListHostedZonesExample = `<?xml version="1.0" encoding="utf-8"?>
<ListHostedZonesResponse xmlns="https://route53.amazonaws.com/doc/2013-04-01/">
    <HostedZones>
        <HostedZone>
            <Id>/hostedzone/Z2K123214213123</Id>
            <Name>example.com.</Name>
            <CallerReference>D2224C5B-684A-DB4A-BB9A-E09E3BAFEA7A</CallerReference>
            <Config>
                <Comment>Test comment</Comment>
            </Config>
            <ResourceRecordSetCount>10</ResourceRecordSetCount>
        </HostedZone>
        <HostedZone>
            <Id>/hostedzone/ZLT12321321124</Id>
            <Name>sub.example.com.</Name>
            <CallerReference>A970F076-FCB1-D959-B395-96474CC84EB8</CallerReference>
            <Config>
                <Comment>Test comment for subdomain host</Comment>
            </Config>
            <ResourceRecordSetCount>4</ResourceRecordSetCount>
        </HostedZone>
    </HostedZones>
    <IsTruncated>false</IsTruncated>
    <MaxItems>100</MaxItems>
</ListHostedZonesResponse>`
