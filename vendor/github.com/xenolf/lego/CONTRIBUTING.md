# How to contribute to lego

Contributions in the form of patches and proposals are essential to keep lego great and to make it even better.
To ensure a great and easy experience for everyone, please review the few guidelines in this document.

## Bug reports

- Use the issue search to see if the issue has already been reported.
- Also look for closed issues to see if your issue has already been fixed.
- If both of the above do not apply create a new issue and include as much information as possible.

Bug reports should include all information a person could need to reproduce your problem without the need to
follow up for more information. If possible, provide detailed steps for us to reproduce it, the expected behaviour and the actual behaviour.

## Feature proposals and requests

Feature requests are welcome and should be discussed in an issue.
Please keep proposals focused on one thing at a time and be as detailed as possible.
It is up to you to make a strong point about your proposal and convince us of the merits and the added complexity of this feature.

## Pull requests

Patches, new features and improvements are a great way to help the project.
Please keep them focused on one thing and do not include unrelated commits.

All pull requests which alter the behaviour of the program, add new behaviour or somehow alter code in a non-trivial way should **always** include tests.

If you want to contribute a significant pull request (with a non-trivial workload for you) please **ask first**. We do not want you to spend
a lot of time on something the project's developers might not want to merge into the project.

**IMPORTANT**: By submitting a patch, you agree to allow the project
owners to license your work under the terms of the [MIT License](LICENSE).

## DNS Providers: API references

| DNS provider              | Code           | Documentation                                                                                                | Go client                                                         |
|---------------------------|----------------|--------------------------------------------------------------------------------------------------------------|-------------------------------------------------------------------|
| Acme DNS                  | `acmedns`      | [documentation](https://github.com/joohoi/acme-dns#api)                                                      | [Go client](https://github.com/cpu/goacmedns)                     |
| Alibaba Cloud             | `alidns`       | [documentation](https://www.alibabacloud.com/help/doc-detail/42875.htm)                                      | [Go client](https://github.com/aliyun/alibaba-cloud-sdk-go)       |
| Aurora DNS                | `auroradns`    | [documentation](https://libcloud.readthedocs.io/en/latest/dns/drivers/auroradns.html#api-docs)               | [Go client](https://github.com/edeckers/auroradnsclient)          |
| Azure                     | `azure`        | [documentation](https://docs.microsoft.com/en-us/go/azure/)                                                  | [Go client](https://github.com/Azure/azure-sdk-for-go)            |
| Bluecat                   | `bluecat`      | ?                                                                                                            | -                                                                 |
| Cloudflare                | `cloudflare`   | [documentation](https://api.cloudflare.com/)                                                                 | [Go client](https://github.com/cloudflare/cloudflare-go)          |
| CloudXNS                  | `cloudxns`     | [documentation](https://www.cloudxns.net/Public/Doc/CloudXNS_api2.0_doc_zh-cn.zip)                           | -                                                                 |
| ConoHa                    | `conoha`       | [documentation](https://www.conoha.jp/docs/)                                                                 | -                                                                 |
| Digital Ocean             | `digitalocean` | [documentation](https://developers.digitalocean.com/documentation/v2/#domain-records)                        | -                                                                 |
| DNSimple                  | `dnsimple`     | [documentation](https://developer.dnsimple.com/v2/)                                                          | [Go client](https://github.com/dnsimple/dnsimple-go)              |
| DNS Made Easy             | `dnsmadeeasy`  | [documentation](https://api-docs.dnsmadeeasy.com/)                                                           | -                                                                 |
| DNSPod                    | `dnspod`       | [documentation](https://www.dnspod.cn/docs/index.html)                                                       | [Go client](https://github.com/decker502/dnspod-go)               |
| DreamHost                 | `dreamhost`    | [documentation](https://help.dreamhost.com/hc/en-us/articles/217560167-API_overview)                         | -                                                                 |
| Duck DNS                  | `duckdns`      | [documentation](https://www.duckdns.org/spec.jsp)                                                            | -                                                                 |
| Dyn                       | `dyn`          | [documentation](https://help.dyn.com/rest/)                                                                  | -                                                                 |
| exec                      | `exec`         | -                                                                                                            | -                                                                 |
| Exoscale                  | `exoscale`     | [documentation](https://community.exoscale.com/documentation/dns/api/)                                       | [Go client](https://github.com/exoscale/egoscale)                 |
| FastDNS                   | `fastdns`      | [documentation](https://developer.akamai.com/api/web_performance/fast_dns_record_management/v1.html)         | [Go client](https://github.com/akamai/AkamaiOPEN-edgegrid-golang) |
| Gandi                     | `gandi`        | [documentation](http://doc.rpc.gandi.net/index.html)                                                         | -                                                                 |
| Gandi v5                  | `gandiv5`      | [documentation](http://doc.livedns.gandi.net)                                                                | -                                                                 |
| Google Cloud              | `gcloud`       | ?                                                                                                            | [Go client](https://github.com/googleapis/google-api-go-client)   |
| Glesys                    | `glesys`       | [documentation](https://github.com/GleSYS/API/wiki/API-Documentation)                                        | -                                                                 |
| Go Daddy                  | `godaddy`      | [documentation](https://developer.godaddy.com/doc/endpoint/domains)                                          | -                                                                 |
| hosting.de                | `hostingde`    | [documentation](https://www.hosting.de/api/#dns)                                                             | -                                                                 |
| Internet Initiative Japan | `iij`          | [documentation](http://manual.iij.jp/p2/pubapi/)                                                             | [Go client](https://github.com/iij/doapi)                         |
| INWX                      | `inwx`         | [documentation](https://www.inwx.de/en/help/apidoc)                                                          | [Go client](https://github.com/smueller18/goinwx)                 | 
| Lightsail                 | `lightsail`    | ?                                                                                                            | [Go client](https://github.com/aws/aws-sdk-go/aws)                |
| Linode (deprecated)       | `linode`       | [documentation](https://www.linode.com/api/dns)                                                              | [Go client](https://github.com/timewasted/linode)                 |
| Linodev4                  | `linodev4`     | [documentation](https://developers.linode.com/api/v4)                                                        | [Go client](https://github.com/linode/linodego)                   |
| Namecheap                 | `namecheap`    | [documentation](https://www.namecheap.com/support/api/methods.aspx)                                          | -                                                                 |
| Name.com                  | `namedotcom`   | [documentation](https://www.name.com/api-docs/DNS)                                                           | [Go client](https://github.com/namedotcom/go)                     |
| manual                    | `manual`       | -                                                                                                            | -                                                                 |
| Netcup                    | `netcup`       | [documentation](https://www.netcup-wiki.de/wiki/DNS_API)                                                     | -                                                                 |
| NIFCloud                  | `nifcloud`     | [documentation](https://mbaas.nifcloud.com/doc/current/rest/common/format.html)                              | -                                                                 |
| NS1                       | `ns1`          | [documentation](https://ns1.com/api)                                                                         | [Go client](https://github.com/ns1/ns1-go)                        |
| Open Telekom Cloud        | `otc`          | [documentation](https://docs.otc.t-systems.com/en-us/dns/index.html)                                         | -                                                                 |
| OVH                       | `ovh`          | [documentation](https://eu.api.ovh.com/)                                                                     | [Go client](https://github.com/ovh/go-ovh)                        |
| PowerDNS                  | `pdns`         | [documentation](https://doc.powerdns.com/md/httpapi/README/)                                                 | -                                                                 |
| Rackspace                 | `rackspace`    | [documentation](https://developer.rackspace.com/docs/cloud-dns/v1/)                                          | -                                                                 |
| RFC2136                   | `rfc2136`      | [documentation](https://tools.ietf.org/html/rfc2136)                                                         | -                                                                 |
| Route 53                  | `route53`      | [documentation](https://docs.aws.amazon.com/Route53/latest/APIReference/API_Operations_Amazon_Route_53.html) | [Go client](https://github.com/aws/aws-sdk-go/aws)                |
| Sakura Cloud              | `sakuracloud`  | [documentation](https://developer.sakura.ad.jp/cloud/api/1.1/)                                               | [Go client](https://github.com/sacloud/libsacloud)                |
| Selectel                  | `selectel`     | [documentation](https://kb.selectel.com/23136054.html)                                                          | -                                                                 |
| Stackpath                 | `stackpath`    | [documentation](https://developer.stackpath.com/en/api/dns/#tag/Zone)                                        | -                                                                 |
| VegaDNS                   | `vegadns`      | [documentation](https://github.com/shupp/VegaDNS-API)                                                        | [Go client](https://github.com/OpenDNS/vegadns2client)            |
| Vultr                     | `vultr`        | [documentation](https://www.vultr.com/api/#dns)                                                              | [Go client](https://github.com/JamesClonk/vultr)                  |
| Vscale                    | `vscale`       | [documentation](https://developers.vscale.io/documentation/api/v1/#api-Domains_Records)                      | -                                                                 |