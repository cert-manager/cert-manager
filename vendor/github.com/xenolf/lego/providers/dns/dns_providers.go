package dns

import (
	"fmt"

	"github.com/xenolf/lego/acme"
	"github.com/xenolf/lego/providers/dns/acmedns"
	"github.com/xenolf/lego/providers/dns/alidns"
	"github.com/xenolf/lego/providers/dns/auroradns"
	"github.com/xenolf/lego/providers/dns/azure"
	"github.com/xenolf/lego/providers/dns/bluecat"
	"github.com/xenolf/lego/providers/dns/cloudflare"
	"github.com/xenolf/lego/providers/dns/cloudxns"
	"github.com/xenolf/lego/providers/dns/conoha"
	"github.com/xenolf/lego/providers/dns/digitalocean"
	"github.com/xenolf/lego/providers/dns/dnsimple"
	"github.com/xenolf/lego/providers/dns/dnsmadeeasy"
	"github.com/xenolf/lego/providers/dns/dnspod"
	"github.com/xenolf/lego/providers/dns/dreamhost"
	"github.com/xenolf/lego/providers/dns/duckdns"
	"github.com/xenolf/lego/providers/dns/dyn"
	"github.com/xenolf/lego/providers/dns/exec"
	"github.com/xenolf/lego/providers/dns/exoscale"
	"github.com/xenolf/lego/providers/dns/fastdns"
	"github.com/xenolf/lego/providers/dns/gandi"
	"github.com/xenolf/lego/providers/dns/gandiv5"
	"github.com/xenolf/lego/providers/dns/gcloud"
	"github.com/xenolf/lego/providers/dns/glesys"
	"github.com/xenolf/lego/providers/dns/godaddy"
	"github.com/xenolf/lego/providers/dns/hostingde"
	"github.com/xenolf/lego/providers/dns/httpreq"
	"github.com/xenolf/lego/providers/dns/iij"
	"github.com/xenolf/lego/providers/dns/inwx"
	"github.com/xenolf/lego/providers/dns/lightsail"
	"github.com/xenolf/lego/providers/dns/linode"
	"github.com/xenolf/lego/providers/dns/linodev4"
	"github.com/xenolf/lego/providers/dns/mydnsjp"
	"github.com/xenolf/lego/providers/dns/namecheap"
	"github.com/xenolf/lego/providers/dns/namedotcom"
	"github.com/xenolf/lego/providers/dns/netcup"
	"github.com/xenolf/lego/providers/dns/nifcloud"
	"github.com/xenolf/lego/providers/dns/ns1"
	"github.com/xenolf/lego/providers/dns/otc"
	"github.com/xenolf/lego/providers/dns/ovh"
	"github.com/xenolf/lego/providers/dns/pdns"
	"github.com/xenolf/lego/providers/dns/rackspace"
	"github.com/xenolf/lego/providers/dns/rfc2136"
	"github.com/xenolf/lego/providers/dns/route53"
	"github.com/xenolf/lego/providers/dns/sakuracloud"
	"github.com/xenolf/lego/providers/dns/selectel"
	"github.com/xenolf/lego/providers/dns/stackpath"
	"github.com/xenolf/lego/providers/dns/transip"
	"github.com/xenolf/lego/providers/dns/vegadns"
	"github.com/xenolf/lego/providers/dns/vscale"
	"github.com/xenolf/lego/providers/dns/vultr"
)

// NewDNSChallengeProviderByName Factory for DNS providers
func NewDNSChallengeProviderByName(name string) (acme.ChallengeProvider, error) {
	switch name {
	case "acme-dns":
		return acmedns.NewDNSProvider()
	case "alidns":
		return alidns.NewDNSProvider()
	case "azure":
		return azure.NewDNSProvider()
	case "auroradns":
		return auroradns.NewDNSProvider()
	case "bluecat":
		return bluecat.NewDNSProvider()
	case "cloudflare":
		return cloudflare.NewDNSProvider()
	case "cloudxns":
		return cloudxns.NewDNSProvider()
	case "conoha":
		return conoha.NewDNSProvider()
	case "digitalocean":
		return digitalocean.NewDNSProvider()
	case "dnsimple":
		return dnsimple.NewDNSProvider()
	case "dnsmadeeasy":
		return dnsmadeeasy.NewDNSProvider()
	case "dnspod":
		return dnspod.NewDNSProvider()
	case "dreamhost":
		return dreamhost.NewDNSProvider()
	case "duckdns":
		return duckdns.NewDNSProvider()
	case "dyn":
		return dyn.NewDNSProvider()
	case "fastdns":
		return fastdns.NewDNSProvider()
	case "exec":
		return exec.NewDNSProvider()
	case "exoscale":
		return exoscale.NewDNSProvider()
	case "gandi":
		return gandi.NewDNSProvider()
	case "gandiv5":
		return gandiv5.NewDNSProvider()
	case "glesys":
		return glesys.NewDNSProvider()
	case "gcloud":
		return gcloud.NewDNSProvider()
	case "godaddy":
		return godaddy.NewDNSProvider()
	case "hostingde":
		return hostingde.NewDNSProvider()
	case "httpreq":
		return httpreq.NewDNSProvider()
	case "iij":
		return iij.NewDNSProvider()
	case "inwx":
		return inwx.NewDNSProvider()
	case "lightsail":
		return lightsail.NewDNSProvider()
	case "linode":
		return linode.NewDNSProvider()
	case "linodev4":
		return linodev4.NewDNSProvider()
	case "manual":
		return acme.NewDNSProviderManual()
	case "mydnsjp":
		return mydnsjp.NewDNSProvider()
	case "namecheap":
		return namecheap.NewDNSProvider()
	case "namedotcom":
		return namedotcom.NewDNSProvider()
	case "netcup":
		return netcup.NewDNSProvider()
	case "nifcloud":
		return nifcloud.NewDNSProvider()
	case "ns1":
		return ns1.NewDNSProvider()
	case "otc":
		return otc.NewDNSProvider()
	case "ovh":
		return ovh.NewDNSProvider()
	case "pdns":
		return pdns.NewDNSProvider()
	case "rackspace":
		return rackspace.NewDNSProvider()
	case "route53":
		return route53.NewDNSProvider()
	case "rfc2136":
		return rfc2136.NewDNSProvider()
	case "sakuracloud":
		return sakuracloud.NewDNSProvider()
	case "stackpath":
		return stackpath.NewDNSProvider()
	case "selectel":
		return selectel.NewDNSProvider()
	case "transip":
		return transip.NewDNSProvider()
	case "vegadns":
		return vegadns.NewDNSProvider()
	case "vultr":
		return vultr.NewDNSProvider()
	case "vscale":
		return vscale.NewDNSProvider()
	default:
		return nil, fmt.Errorf("unrecognised DNS provider: %s", name)
	}
}
