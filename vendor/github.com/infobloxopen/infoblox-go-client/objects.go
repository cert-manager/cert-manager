package ibclient

import (
	"bytes"
	"encoding/json"
	"reflect"
)

const MACADDR_ZERO = "00:00:00:00:00:00"

type Bool bool

type EA map[string]interface{}

type EASearch map[string]interface{}

type EADefListValue string

type IBBase struct {
	objectType   string
	returnFields []string
	eaSearch     EASearch
}

type IBObject interface {
	ObjectType() string
	ReturnFields() []string
	EaSearch() EASearch
	//SetReturnFields([]string)
}

func (obj *IBBase) ObjectType() string {
	return obj.objectType
}

func (obj *IBBase) ReturnFields() []string {
	return obj.returnFields
}

func (obj *IBBase) EaSearch() EASearch {
	return obj.eaSearch
}

type NetworkView struct {
	IBBase `json:"-"`
	Ref    string `json:"_ref,omitempty"`
	Name   string `json:"name,omitempty"`
	Ea     EA     `json:"extattrs,omitempty"`
}

func NewNetworkView(nv NetworkView) *NetworkView {
	res := nv
	res.objectType = "networkview"
	res.returnFields = []string{"extattrs", "name"}

	return &res
}

// UpgradeStatus object representation
type UpgradeStatus struct {
	IBBase           `json:"-"`
	Ref              string              `json:"_ref,omitempty"`
	Type             string              `json:"type"`
	SubElementStatus []SubElementsStatus `json:"subelements_status,omitempty"`
	UpgradeGroup     string              `json:"upgrade_group,omitempty"`
}

func NewUpgradeStatus(upgradeStatus UpgradeStatus) *UpgradeStatus {
	result := upgradeStatus
	returnFields := []string{"subelements_status", "type"}
	result.objectType = "upgradestatus"
	result.returnFields = returnFields
	return &result
}

// SubElementsStatus object representation
type SubElementsStatus struct {
	Ref            string `json:"_ref,omitempty"`
	CurrentVersion string `json:"current_version"`
	ElementStatus  string `json:"element_status"`
	Ipv4Address    string `json:"ipv4_address"`
	Ipv6Address    string `json:"ipv6_address"`
	StatusValue    string `json:"status_value"`
	StepsTotal     int    `json:"steps_total"`
	StepsCompleted int    `json:"steps_completed"`
	NodeType       string `json:"type"`
	Member         string `json:"member"`
}

type Network struct {
	IBBase
	Ref         string `json:"_ref,omitempty"`
	NetviewName string `json:"network_view,omitempty"`
	Cidr        string `json:"network,omitempty"`
	Ea          EA     `json:"extattrs,omitempty"`
}

func NewNetwork(nw Network) *Network {
	res := nw
	res.objectType = "network"
	res.returnFields = []string{"extattrs", "network", "network_view"}

	return &res
}

type ServiceStatus struct {
	Desciption string `json:"description,omitempty"`
	Service    string `json:"service,omitempty"`
	Status     string `json:"status,omitempty"`
}

type LanHaPortSetting struct {
	HAIpAddress    string              `json:"ha_ip_address,omitempty"`
	HaPortSetting  PhysicalPortSetting `json:"ha_port_setting,omitempty"`
	LanPortSetting PhysicalPortSetting `json:"lan_port_setting,omitempty"`
	MgmtIpv6addr   string              `json:"mgmt_ipv6addr,omitempty"`
	MgmtLan        string              `json:"mgmt_lan,omitempty"`
}

type PhysicalPortSetting struct {
	AutoPortSettingEnabled bool   `json:"auto_port_setting_enabled"`
	Duplex                 string `json:"duplex,omitempty"`
	Speed                  string `json:"speed,omitempty"`
}

type NetworkSetting struct {
	Address    string `json:"address"`
	Dscp       uint   `json:"dscp"`
	Gateway    string `json:"gateway"`
	Primary    bool   `json:"primary"`
	SubnetMask string `json:"subnet_mask"`
	UseDscp    bool   `json:"use_dscp,omiempty"`
	VlanId     uint   `json:"vlan_id,omitempty"`
}
type Ipv6Setting struct {
	AutoRouterConfigEnabled bool   `json:"auto_router_config_enabled"`
	CidrPrefix              uint   `json:"cidr_prefix,omitempty"`
	Dscp                    uint   `json:"dscp,omitempty"`
	Enabled                 bool   `json:"enabled,omitempty"`
	Gateway                 string `json:"gateway"`
	Primary                 string `json:"primary,omitempty"`
	VirtualIp               string `json:"virtual_ip"`
	VlanId                  uint   `json:"vlan_id,emitempty"`
	UseDscp                 bool   `json:"use_dscp,omitempty"`
}

type NodeInfo struct {
	HaStatus             string              `json:"ha_status,omitempty"`
	HwId                 string              `json:"hwid,omitempty"`
	HwModel              string              `json:"hwmodel,omitempty"`
	HwPlatform           string              `json:"hwplatform,omitempty"`
	HwType               string              `json:"hwtype,omitempty"`
	Lan2PhysicalSetting  PhysicalPortSetting `json:"lan2_physical_setting,omitempty"`
	LanHaPortSetting     LanHaPortSetting    `json:"lan_ha_Port_Setting,omitempty"`
	MgmtNetworkSetting   NetworkSetting      `json:"mgmt_network_setting,omitempty"`
	MgmtPhysicalSetting  PhysicalPortSetting `json:"mgmt_physical_setting,omitempty"`
	PaidNios             bool                `json:"paid_nios,omitempty"`
	PhysicalOid          string              `json:"physical_oid,omitempty"`
	ServiceStatus        []ServiceStatus     `json:"service_status,omitempty"`
	V6MgmtNetworkSetting Ipv6Setting         `json:"v6_mgmt_network_setting,omitempty"`
}

// Member represents NIOS member
type Member struct {
	IBBase                   `json:"-"`
	Ref                      string     `json:"_ref,omitempty"`
	HostName                 string     `json:"host_name,omitempty"`
	ConfigAddrType           string     `json:"config_addr_type,omitempty"`
	PLATFORM                 string     `json:"platform,omitempty"`
	ServiceTypeConfiguration string     `json:"service_type_configuration,omitempty"`
	Nodeinfo                 []NodeInfo `json:"node_info,omitempty"`
	TimeZone                 string     `json:"time_zone,omitempty"`
}

func NewMember(member Member) *Member {
	res := member
	res.objectType = "member"
	returnFields := []string{"host_name", "node_info", "time_zone"}
	res.returnFields = returnFields
	return &res
}

// License represents license wapi object
type License struct {
	IBBase           `json:"-"`
	Ref              string `json:"_ref,omitempty"`
	ExpirationStatus string `json:"expiration_status,omitempty"`
	ExpiryDate       int    `json:"expiry_date,omitempty"`
	HwID             string `json:"hwid,omitempty"`
	Key              string `json:"key,omitempty"`
	Kind             string `json:"kind,omitempty"`
	Limit            string `json:"limit,omitempty"`
	LimitContext     string `json:"limit_context,omitempty"`
	Licensetype      string `json:"type,omitempty"`
}

func NewGridLicense(license License) *License {
	result := license
	result.objectType = "license:gridwide"
	returnFields := []string{"expiration_status",
		"expiry_date",
		"key",
		"limit",
		"limit_context",
		"type"}
	result.returnFields = returnFields
	return &result
}

func NewLicense(license License) *License {
	result := license
	returnFields := []string{"expiration_status",
		"expiry_date",
		"hwid",
		"key",
		"kind",
		"limit",
		"limit_context",
		"type"}
	result.objectType = "member:license"
	result.returnFields = returnFields
	return &result
}

// CapacityReport represents capacityreport object
type CapacityReport struct {
	IBBase `json:"-"`
	Ref    string `json:"_ref,omitempty"`

	Name         string                   `json:"name,omitempty"`
	HardwareType string                   `json:"hardware_type,omitempty"`
	MaxCapacity  int                      `json:"max_capacity,omitempty"`
	ObjectCount  []map[string]interface{} `json:"object_counts,omitempty"`
	PercentUsed  int                      `json:"percent_used,omitempty"`
	Role         string                   `json:"role,omitempty"`
	TotalObjects int                      `json:"total_objects,omitempty"`
}

func NewCapcityReport(capReport CapacityReport) *CapacityReport {
	res := capReport
	returnFields := []string{"name", "hardware_type", "max_capacity", "object_counts", "percent_used", "role", "total_objects"}
	res.objectType = "capacityreport"
	res.returnFields = returnFields
	return &res
}

type NTPserver struct {
	Address              string `json:"address,omitempty"`
	Burst                bool   `json:"burst,omitempty"`
	EnableAuthentication bool   `json:"enable_authentication,omitempty"`
	IBurst               bool   `json:"iburst,omitempty"`
	NTPKeyNumber         uint   `json:"ntp_key_number,omitempty"`
	Preffered            bool   `json:"preffered,omitempty"`
}

type NTPSetting struct {
	EnableNTP  bool                   `json:"enable_ntp,omitempty"`
	NTPAcl     map[string]interface{} `json:"ntp_acl,omitempty"`
	NTPKeys    []string               `json:"ntp_keys,omitempty"`
	NTPKod     bool                   `json:"ntp_kod,omitempty"`
	NTPServers []NTPserver            `json:"ntp_servers,omitempty"`
}

type Grid struct {
	IBBase     `json:"-"`
	Ref        string      `json:"_ref,omitempty"`
	Name       string      `json:"name,omitempty"`
	NTPSetting *NTPSetting `json:"ntp_setting,omitempty"`
}

func NewGrid(grid Grid) *Grid {
	result := grid
	result.objectType = "grid"
	returnFields := []string{"name", "ntp_setting"}
	result.returnFields = returnFields
	return &result
}

type NetworkContainer struct {
	IBBase      `json:"-"`
	Ref         string `json:"_ref,omitempty"`
	NetviewName string `json:"network_view,omitempty"`
	Cidr        string `json:"network,omitempty"`
	Ea          EA     `json:"extattrs,omitempty"`
}

func NewNetworkContainer(nc NetworkContainer) *NetworkContainer {
	res := nc
	res.objectType = "networkcontainer"
	res.returnFields = []string{"extattrs", "network", "network_view"}

	return &res
}

type FixedAddress struct {
	IBBase      `json:"-"`
	Ref         string `json:"_ref,omitempty"`
	NetviewName string `json:"network_view,omitempty"`
	Cidr        string `json:"network,omitempty"`
	IPAddress   string `json:"ipv4addr,omitempty"`
	Mac         string `json:"mac,omitempty"`
	Name        string `json:"name,omitempty"`
	Ea          EA     `json:"extattrs,omitempty"`
}

/*This is a general struct to add query params used in makeRequest*/
type QueryParams struct {
	forceProxy bool
}

func NewFixedAddress(fixedAddr FixedAddress) *FixedAddress {
	res := fixedAddr
	res.objectType = "fixedaddress"
	res.returnFields = []string{"extattrs", "ipv4addr", "mac", "name", "network", "network_view"}

	return &res
}

type EADefinition struct {
	IBBase             `json:"-"`
	Ref                string           `json:"_ref,omitempty"`
	Comment            string           `json:"comment,omitempty"`
	Flags              string           `json:"flags,omitempty"`
	ListValues         []EADefListValue `json:"list_values,omitempty"`
	Name               string           `json:"name,omitempty"`
	Type               string           `json:"type,omitempty"`
	AllowedObjectTypes []string         `json:"allowed_object_types,omitempty"`
}

func NewEADefinition(eadef EADefinition) *EADefinition {
	res := eadef
	res.objectType = "extensibleattributedef"
	res.returnFields = []string{"allowed_object_types", "comment", "flags", "list_values", "name", "type"}

	return &res
}

type UserProfile struct {
	IBBase `json:"-"`
	Ref    string `json:"_ref,omitempty"`
	Name   string `json:"name,omitempty"`
}

func NewUserProfile(userprofile UserProfile) *UserProfile {
	res := userprofile
	res.objectType = "userprofile"
	res.returnFields = []string{"name"}

	return &res
}

type RecordA struct {
	IBBase   `json:"-"`
	Ref      string `json:"_ref,omitempty"`
	Ipv4Addr string `json:"ipv4addr,omitempty"`
	Name     string `json:"name,omitempty"`
	View     string `json:"view,omitempty"`
	Zone     string `json:"zone,omitempty"`
	Ea       EA     `json:"extattrs,omitempty"`
}

func NewRecordA(ra RecordA) *RecordA {
	res := ra
	res.objectType = "record:a"
	res.returnFields = []string{"extattrs", "ipv4addr", "name", "view", "zone"}

	return &res
}

type RecordCNAME struct {
	IBBase    `json:"-"`
	Ref       string `json:"_ref,omitempty"`
	Canonical string `json:"canonical,omitempty"`
	Name      string `json:"name,omitempty"`
	View      string `json:"view,omitempty"`
	Zone      string `json:"zone,omitempty"`
	Ea        EA     `json:"extattrs,omitempty"`
}

func NewRecordCNAME(rc RecordCNAME) *RecordCNAME {
	res := rc
	res.objectType = "record:cname"
	res.returnFields = []string{"extattrs", "canonical", "name", "view", "zone"}

	return &res
}

type HostRecordIpv4Addr struct {
	IBBase   `json:"-"`
	Ipv4Addr string `json:"ipv4addr,omitempty"`
	Ref      string `json:"_ref,omitempty"`
	Mac      string `json:"mac,omitempty"`
	View     string `json:"view,omitempty"`
	Cidr     string `json:"network,omitempty"`
}

func NewHostRecordIpv4Addr(hostAddr HostRecordIpv4Addr) *HostRecordIpv4Addr {
	res := hostAddr
	res.objectType = "record:host_ipv4addr"
	return &res
}

type HostRecord struct {
	IBBase      `json:"-"`
	Ref         string               `json:"_ref,omitempty"`
	Ipv4Addr    string               `json:"ipv4addr,omitempty"`
	Ipv4Addrs   []HostRecordIpv4Addr `json:"ipv4addrs,omitempty"`
	Name        string               `json:"name,omitempty"`
	View        string               `json:"view,omitempty"`
	Zone        string               `json:"zone,omitempty"`
	EnableDns   *bool                `json:"configure_for_dns,omitempty"`
	NetworkView string               `json:"network_view,omitempty"`
	Ea          EA                   `json:"extattrs,omitempty"`
}

func NewHostRecord(rh HostRecord) *HostRecord {
	res := rh
	res.objectType = "record:host"
	res.returnFields = []string{"extattrs", "ipv4addrs", "name", "view", "zone"}

	return &res
}

type RecordTXT struct {
	IBBase `json:"-"`
	Ref    string `json:"_ref,omitempty"`
	Name   string `json:"name,omitempty"`
	Text   string `json:"text,omitempty"`
	View   string `json:"view,omitempty"`
	Zone   string `json:"zone,omitempty"`
	Ea     EA     `json:"extattrs,omitempty"`
}

func NewRecordTXT(rt RecordTXT) *RecordTXT {
	res := rt
	res.objectType = "record:txt"
	res.returnFields = []string{"extattrs", "name", "text", "view", "zone"}

	return &res
}

type ZoneAuth struct {
	IBBase `json:"-"`
	Ref    string `json:"_ref,omitempty"`
	Fqdn   string `json:"fqdn,omitempty"`
	View   string `json:"view,omitempty"`
	Ea     EA     `json:"extattrs,omitempty"`
}

func NewZoneAuth(za ZoneAuth) *ZoneAuth {
	res := za
	res.objectType = "zone_auth"
	res.returnFields = []string{"extattrs", "fqdn", "view"}

	return &res
}

func (ea EA) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	for k, v := range ea {
		value := make(map[string]interface{})
		value["value"] = v
		m[k] = value
	}

	return json.Marshal(m)
}

func (eas EASearch) MarshalJSON() ([]byte, error) {
	m := make(map[string]interface{})
	for k, v := range eas {
		m["*"+k] = v
	}

	return json.Marshal(m)
}

func (v EADefListValue) MarshalJSON() ([]byte, error) {
	m := make(map[string]string)
	m["value"] = string(v)

	return json.Marshal(m)
}

func (b Bool) MarshalJSON() ([]byte, error) {
	if b {
		return json.Marshal("True")
	}

	return json.Marshal("False")
}

func (ea *EA) UnmarshalJSON(b []byte) (err error) {
	var m map[string]map[string]interface{}

	decoder := json.NewDecoder(bytes.NewBuffer(b))
	decoder.UseNumber()
	err = decoder.Decode(&m)
	if err != nil {
		return
	}

	*ea = make(EA)
	for k, v := range m {
		val := v["value"]
		if reflect.TypeOf(val).String() == "json.Number" {
			var i64 int64
			i64, err = val.(json.Number).Int64()
			val = int(i64)
		} else if val.(string) == "True" {
			val = Bool(true)
		} else if val.(string) == "False" {
			val = Bool(false)
		}

		(*ea)[k] = val
	}

	return
}

func (v *EADefListValue) UnmarshalJSON(b []byte) (err error) {
	var m map[string]string
	err = json.Unmarshal(b, &m)
	if err != nil {
		return
	}

	*v = EADefListValue(m["value"])
	return
}

type RequestBody struct {
	Data               map[string]interface{} `json:"data,omitempty"`
	Args               map[string]string      `json:"args,omitempty"`
	Method             string                 `json:"method"`
	Object             string                 `json:"object,omitempty"`
	EnableSubstitution bool                   `json:"enable_substitution,omitempty"`
	AssignState        map[string]string      `json:"assign_state,omitempty"`
	Discard            bool                   `json:"discard,omitempty"`
}

type SingleRequest struct {
	IBBase `json:"-"`
	Body   *RequestBody
}

type MultiRequest struct {
	IBBase `json:"-"`
	Body   []*RequestBody
}

func (r *MultiRequest) MarshalJSON() ([]byte, error) {
	return json.Marshal(r.Body)
}

func NewMultiRequest(body []*RequestBody) *MultiRequest {
	req := &MultiRequest{Body: body}
	req.objectType = "request"
	return req
}

func NewRequest(body *RequestBody) *SingleRequest {
	req := &SingleRequest{Body: body}
	req.objectType = "request"
	return req
}
