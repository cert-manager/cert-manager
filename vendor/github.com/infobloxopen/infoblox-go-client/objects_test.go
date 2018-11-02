package ibclient

import (
	. "github.com/onsi/ginkgo"
	. "github.com/onsi/gomega"

	"encoding/json"
)

var _ = Describe("Objects", func() {

	Context("Grid object", func() {

		tesNtpserver := NTPserver{
			Address:              "16.4.1.2",
			Burst:                true,
			EnableAuthentication: true,
			IBurst:               true,
			Preffered:            true,
		}
		grid := Grid{Name: "test", NTPSetting: &NTPSetting{EnableNTP: true,
			NTPAcl:     nil,
			NTPKeys:    nil,
			NTPKod:     false,
			NTPServers: []NTPserver{tesNtpserver},
		},
		}
		gridJSON := `{
			"name": "test",
			"ntp_setting": {
				"enable_ntp": true,
				"ntp_servers": [{
					"address": "16.4.1.2",
					"burst": true,
					"enable_authentication": true,
					"iburst": true,
					"preffered": true
					}]
				}
				}`

		Context("Marshalling", func() {
			Context("expected JSON is returned", func() {
				js, err := json.Marshal(grid)

				It("should not error", func() {
					Expect(err).NotTo(HaveOccurred())
				})

				It("should match json expected", func() {
					Expect(js).To(MatchJSON(gridJSON))
				})
			})
		})

		Context("Unmarshalling", func() {
			Context("expected object is returned", func() {
				var actualGrid Grid
				err := json.Unmarshal([]byte(gridJSON), &actualGrid)

				It("should not error", func() {
					Expect(err).NotTo(HaveOccurred())
				})

				It("should match object expected", func() {
					Expect(actualGrid).To(Equal(grid))
				})
			})
		})

	})

	Context("EA Object", func() {

		ea := EA{
			"Cloud API Owned":   Bool(true),
			"Tenant Name":       "Engineering01",
			"Maximum Wait Time": 120,
			"DNS Support":       Bool(false),
		}
		eaJSON := `{"Cloud API Owned":{"value":"True"},` +
			`"Tenant Name":{"value":"Engineering01"},` +
			`"Maximum Wait Time":{"value":120},` +
			`"DNS Support":{"value":"False"}}`

		Context("Marshalling", func() {
			Context("expected JSON is returned", func() {
				js, err := json.Marshal(ea)

				It("should not error", func() {
					Expect(err).NotTo(HaveOccurred())
				})

				It("should match json expected", func() {
					Expect(js).To(MatchJSON(eaJSON))
				})
			})
		})

		Context("Unmarshalling", func() {
			Context("expected object is returned", func() {
				var actualEA EA
				err := json.Unmarshal([]byte(eaJSON), &actualEA)

				It("should not error", func() {
					Expect(err).NotTo(HaveOccurred())
				})

				It("should match object expected", func() {
					Expect(actualEA).To(Equal(ea))
				})
			})
		})

	})

	Context("EA Search Object", func() {
		eas := EASearch{
			"Network Name": "Shared-Net",
			"Network View": "Global",
		}
		expectedJSON := `{"*Network Name" :"Shared-Net",` +
			`"*Network View" :"Global"}`

		Context("Marshalling", func() {
			Context("expected JSON is returned", func() {
				js, err := json.Marshal(eas)

				It("should not error", func() {
					Expect(err).NotTo(HaveOccurred())
				})

				It("should match json expected", func() {
					Expect(js).To(MatchJSON(expectedJSON))
				})
			})
		})
	})

	Context("EADefListValue Object", func() {
		var eadListVal EADefListValue = "Host Record"

		eadListValJSON := `{"value": "Host Record"}`

		Context("Marshalling", func() {
			Context("expected JSON is returned", func() {
				js, err := json.Marshal(eadListVal)

				It("should not error", func() {
					Expect(err).NotTo(HaveOccurred())
				})

				It("should match json expected", func() {
					Expect(js).To(MatchJSON(eadListValJSON))
				})
			})
		})

		Context("Unmarshalling", func() {
			Context("expected object is returned", func() {
				var actualEadListVal EADefListValue
				err := json.Unmarshal([]byte(eadListValJSON), &actualEadListVal)

				It("should not error", func() {
					Expect(err).NotTo(HaveOccurred())
				})

				It("should match object expected", func() {
					Expect(actualEadListVal).To(Equal(eadListVal))
				})
			})
		})

	})

	Context("Instantiation of", func() {
		Context("NetworkView object", func() {
			name := "myview"
			nv := NewNetworkView(NetworkView{Name: name})

			It("should set fields correctly", func() {
				Expect(nv.Name).To(Equal(name))
			})

			It("should set base fields correctly", func() {
				Expect(nv.ObjectType()).To(Equal("networkview"))
				Expect(nv.ReturnFields()).To(ConsistOf("extattrs", "name"))
			})
		})

		Context("Network object", func() {
			cidr := "123.0.0.0/24"
			netviewName := "localview"
			nw := NewNetwork(Network{Cidr: cidr, NetviewName: netviewName})
			searchEAs := EASearch{"Network Name": "shared-net"}
			nw.eaSearch = searchEAs

			It("should set fields correctly", func() {
				Expect(nw.Cidr).To(Equal(cidr))
				Expect(nw.NetviewName).To(Equal(netviewName))
			})

			It("should set base fields correctly", func() {
				Expect(nw.ObjectType()).To(Equal("network"))
				Expect(nw.ReturnFields()).To(ConsistOf("extattrs", "network", "network_view"))
				Expect(nw.EaSearch()).To(Equal(searchEAs))
			})
		})

		Context("NetworkContainer object", func() {
			cidr := "74.0.8.0/24"
			netviewName := "globalview"
			nwc := NewNetworkContainer(NetworkContainer{Cidr: cidr, NetviewName: netviewName})

			It("should set fields correctly", func() {
				Expect(nwc.Cidr).To(Equal(cidr))
				Expect(nwc.NetviewName).To(Equal(netviewName))
			})

			It("should set base fields correctly", func() {
				Expect(nwc.ObjectType()).To(Equal("networkcontainer"))
				Expect(nwc.ReturnFields()).To(ConsistOf("extattrs", "network", "network_view"))
			})
		})

		Context("FixedAddress object", func() {
			netviewName := "globalview"
			cidr := "25.0.7.0/24"
			ipAddress := "25.0.7.59/24"
			mac := "11:22:33:44:55:66"
			fixedAddr := NewFixedAddress(FixedAddress{
				NetviewName: netviewName,
				Cidr:        cidr,
				IPAddress:   ipAddress,
				Mac:         mac})

			It("should set fields correctly", func() {
				Expect(fixedAddr.NetviewName).To(Equal(netviewName))
				Expect(fixedAddr.Cidr).To(Equal(cidr))
				Expect(fixedAddr.IPAddress).To(Equal(ipAddress))
				Expect(fixedAddr.Mac).To(Equal(mac))
			})

			It("should set base fields correctly", func() {
				Expect(fixedAddr.ObjectType()).To(Equal("fixedaddress"))
				Expect(fixedAddr.ReturnFields()).To(ConsistOf("extattrs", "ipv4addr", "mac", "name", "network", "network_view"))
			})
		})

		Context("EADefinition object", func() {
			comment := "Test Extensible Attribute"
			flags := "CGV"
			listValues := []EADefListValue{"True", "False"}
			name := "Test EA"
			eaType := "string"
			allowedTypes := []string{"arecord", "aaarecord", "ptrrecord"}
			eaDef := NewEADefinition(EADefinition{
				Name:               name,
				Comment:            comment,
				Flags:              flags,
				ListValues:         listValues,
				Type:               eaType,
				AllowedObjectTypes: allowedTypes})

			It("should set fields correctly", func() {
				Expect(eaDef.Comment).To(Equal(comment))
				Expect(eaDef.Flags).To(Equal(flags))
				Expect(eaDef.ListValues).To(ConsistOf(listValues))
				Expect(eaDef.Name).To(Equal(name))
				Expect(eaDef.Type).To(Equal(eaType))
				Expect(eaDef.AllowedObjectTypes).To(ConsistOf(allowedTypes))
			})

			It("should set base fields correctly", func() {
				Expect(eaDef.ObjectType()).To(Equal("extensibleattributedef"))
				Expect(eaDef.ReturnFields()).To(ConsistOf("allowed_object_types", "comment", "flags", "list_values", "name", "type"))
			})
		})

		Context("UserProfile object", func() {
			userprofile := NewUserProfile(UserProfile{})

			It("should set base fields correctly", func() {
				Expect(userprofile.ObjectType()).To(Equal("userprofile"))
				Expect(userprofile.ReturnFields()).To(ConsistOf("name"))
			})
		})

		Context("RecordA object", func() {
			ipv4addr := "1.1.1.1"
			name := "bind_a.domain.com"
			view := "default"
			zone := "domain.com"

			ra := NewRecordA(RecordA{
				Ipv4Addr: ipv4addr,
				Name:     name,
				View:     view,
				Zone:     zone})

			It("should set fields correctly", func() {
				Expect(ra.Ipv4Addr).To(Equal(ipv4addr))
				Expect(ra.Name).To(Equal(name))
				Expect(ra.View).To(Equal(view))
				Expect(ra.Zone).To(Equal(zone))
			})

			It("should set base fields correctly", func() {
				Expect(ra.ObjectType()).To(Equal("record:a"))
				Expect(ra.ReturnFields()).To(ConsistOf("extattrs", "ipv4addr", "name", "view", "zone"))
			})
		})

		Context("RecordCNAME object", func() {
			canonical := "cname.domain.com"
			name := "bind_cname.domain.com"
			view := "default"
			zone := "domain.com"

			rc := NewRecordCNAME(RecordCNAME{
				Canonical: canonical,
				Name:      name,
				View:      view,
				Zone:      zone})

			It("should set fields correctly", func() {
				Expect(rc.Canonical).To(Equal(canonical))
				Expect(rc.Name).To(Equal(name))
				Expect(rc.View).To(Equal(view))
				Expect(rc.Zone).To(Equal(zone))
			})

			It("should set base fields correctly", func() {
				Expect(rc.ObjectType()).To(Equal("record:cname"))
				Expect(rc.ReturnFields()).To(ConsistOf("extattrs", "canonical", "name", "view", "zone"))
			})
		})

		Context("RecordHostIpv4Addr object", func() {
			netviewName := "globalview"
			cidr := "25.0.7.0/24"
			ipAddress := "25.0.7.59/24"
			mac := "11:22:33:44:55:66"
			hostAddr := NewHostRecordIpv4Addr(HostRecordIpv4Addr{
				View:     netviewName,
				Cidr:     cidr,
				Ipv4Addr: ipAddress,
				Mac:      mac})

			It("should set fields correctly", func() {
				Expect(hostAddr.View).To(Equal(netviewName))
				Expect(hostAddr.Cidr).To(Equal(cidr))
				Expect(hostAddr.Ipv4Addr).To(Equal(ipAddress))
				Expect(hostAddr.Mac).To(Equal(mac))
			})

			It("should set base fields correctly", func() {
				Expect(hostAddr.ObjectType()).To(Equal("record:host_ipv4addr"))
				//Expect(hostAddr.ReturnFields()).To(ConsistOf("configure_for_dhcp", "host", "ipv4addr", "mac"))
			})
		})

		Context("RecordHostIpv4Addr macaddress empty", func() {
			netviewName := "globalview"
			cidr := "25.0.7.0/24"
			ipAddress := "25.0.7.59/24"
			hostAddr := NewHostRecordIpv4Addr(HostRecordIpv4Addr{
				View:     netviewName,
				Cidr:     cidr,
				Ipv4Addr: ipAddress})

			It("should set fields correctly", func() {
				Expect(hostAddr.View).To(Equal(netviewName))
				Expect(hostAddr.Cidr).To(Equal(cidr))
				Expect(hostAddr.Ipv4Addr).To(Equal(ipAddress))
			})

			It("should set base fields correctly", func() {
				Expect(hostAddr.ObjectType()).To(Equal("record:host_ipv4addr"))
				//Expect(hostAddr.ReturnFields()).To(ConsistOf("configure_for_dhcp", "host", "ipv4addr", "mac"))
			})
		})
		Context("RecordHost object", func() {
			ipv4addrs := []HostRecordIpv4Addr{{Ipv4Addr: "1.1.1.1"}, {Ipv4Addr: "2.2.2.2"}}
			name := "bind_host.domain.com"
			view := "default"
			zone := "domain.com"

			rh := NewHostRecord(HostRecord{
				Ipv4Addrs: ipv4addrs,
				Name:      name,
				View:      view,
				Zone:      zone})

			It("should set fields correctly", func() {
				Expect(rh.Ipv4Addrs).To(Equal(ipv4addrs))
				Expect(rh.Name).To(Equal(name))
				Expect(rh.View).To(Equal(view))
				Expect(rh.Zone).To(Equal(zone))
			})

			It("should set base fields correctly", func() {
				Expect(rh.ObjectType()).To(Equal("record:host"))
				Expect(rh.ReturnFields()).To(ConsistOf("extattrs", "ipv4addrs", "name", "view", "zone"))
			})
		})

		Context("RecordTXT object", func() {
			name := "txt.domain.com"
			text := "this is text string"
			view := "default"
			zone := "domain.com"

			rt := NewRecordTXT(RecordTXT{
				Name: name,
				Text: text,
				View: view,
				Zone: zone})

			It("should set fields correctly", func() {
				Expect(rt.Name).To(Equal(name))
				Expect(rt.Text).To(Equal(text))
				Expect(rt.View).To(Equal(view))
				Expect(rt.Zone).To(Equal(zone))
			})

			It("should set base fields correctly", func() {
				Expect(rt.ObjectType()).To(Equal("record:txt"))
				Expect(rt.ReturnFields()).To(ConsistOf("extattrs", "name", "text", "view", "zone"))
			})
		})

		Context("ZoneAuth object", func() {
			fqdn := "domain.com"
			view := "default"

			za := NewZoneAuth(ZoneAuth{
				Fqdn: fqdn,
				View: view})

			It("should set fields correctly", func() {
				Expect(za.Fqdn).To(Equal(fqdn))
				Expect(za.View).To(Equal(view))
			})

			It("should set base fields correctly", func() {
				Expect(za.ObjectType()).To(Equal("zone_auth"))
				Expect(za.ReturnFields()).To(ConsistOf("extattrs", "fqdn", "view"))
			})
		})

	})

	Context("Unmarshalling malformed JSON", func() {
		Context("for EA", func() {
			badJSON := `""`
			var ea EA
			err := json.Unmarshal([]byte(badJSON), &ea)

			It("should return an error", func() {
				Expect(err).ToNot(BeNil())
			})
		})

		Context("for EADefListValue", func() {
			badJSON := `""`
			var ead EADefListValue
			err := json.Unmarshal([]byte(badJSON), &ead)

			It("should return an error", func() {
				Expect(err).ToNot(BeNil())
			})
		})

	})

})
