package sacloud

import (
	"encoding/json"
	"fmt"
	"strconv"
	"strings"
)

// MobileGateway モバイルゲートウェイ
type MobileGateway struct {
	*Appliance // アプライアンス共通属性

	Remark   *MobileGatewayRemark   `json:",omitempty"` // リマーク
	Settings *MobileGatewaySettings `json:",omitempty"` // モバイルゲートウェイ設定
}

// MobileGatewayRemark リマーク
type MobileGatewayRemark struct {
	*ApplianceRemarkBase
	// TODO Zone
	//Zone *Resource
}

// MobileGatewaySettings モバイルゲートウェイ設定
type MobileGatewaySettings struct {
	MobileGateway *MobileGatewaySetting `json:",omitempty"` // モバイルゲートウェイ設定リスト
}

// MobileGatewaySetting モバイルゲートウェイ設定
type MobileGatewaySetting struct {
	InternetConnection *MGWInternetConnection `json:",omitempty"` // インターネット接続
	Interfaces         []*MGWInterface        `json:",omitempty"` // インターフェース
	StaticRoutes       []*MGWStaticRoute      `json:",omitempty"` // スタティックルート
}

// HasStaticRoutes スタティックルートを保持しているか
func (m *MobileGatewaySetting) HasStaticRoutes() bool {
	return m.StaticRoutes != nil && len(m.StaticRoutes) > 0
}

// AddStaticRoute スタティックルート設定 追加
func (m *MobileGatewaySetting) AddStaticRoute(prefix string, nextHop string) (int, *MGWStaticRoute) {
	if m.StaticRoutes == nil {
		m.StaticRoutes = []*MGWStaticRoute{}
	}

	s := &MGWStaticRoute{
		Prefix:  prefix,
		NextHop: nextHop,
	}
	m.StaticRoutes = append(m.StaticRoutes, s)
	return len(m.StaticRoutes) - 1, s
}

// RemoveStaticRoute スタティックルート設定 削除
func (m *MobileGatewaySetting) RemoveStaticRoute(prefix string, nextHop string) {
	if m.StaticRoutes == nil {
		return
	}

	dest := []*MGWStaticRoute{}
	for _, s := range m.StaticRoutes {
		if s.Prefix != prefix || s.NextHop != nextHop {
			dest = append(dest, s)
		}
	}
	m.StaticRoutes = dest
}

// RemoveStaticRouteAt スタティックルート設定 削除
func (m *MobileGatewaySetting) RemoveStaticRouteAt(index int) {
	if m.StaticRoutes == nil {
		return
	}

	if index < len(m.StaticRoutes) {
		s := m.StaticRoutes[index]
		m.RemoveStaticRoute(s.Prefix, s.NextHop)
	}
}

// FindStaticRoute スタティックルート設定 検索
func (m *MobileGatewaySetting) FindStaticRoute(prefix string, nextHop string) (int, *MGWStaticRoute) {
	for i, s := range m.StaticRoutes {
		if s.Prefix == prefix && s.NextHop == nextHop {
			return i, s
		}
	}
	return -1, nil
}

// MGWInternetConnection インターネット接続
type MGWInternetConnection struct {
	Enabled string `json:",omitempty"`
}

// MGWInterface インターフェース
type MGWInterface struct {
	IPAddress      []string `json:",omitempty"`
	NetworkMaskLen int      `json:",omitempty"`
}

// MGWStaticRoute スタティックルート
type MGWStaticRoute struct {
	Prefix  string `json:",omitempty"`
	NextHop string `json:",omitempty"`
}

// MobileGatewayPlan モバイルゲートウェイプラン
type MobileGatewayPlan int

var (
	// MobileGatewayPlanStandard スタンダードプラン // TODO 正式名称不明なため暫定の名前
	MobileGatewayPlanStandard = MobileGatewayPlan(1)
)

// CreateMobileGatewayValue モバイルゲートウェイ作成用パラメーター
type CreateMobileGatewayValue struct {
	Name        string   // 名称
	Description string   // 説明
	Tags        []string // タグ
	IconID      int64    // アイコン
}

// CreateNewMobileGateway モバイルゲートウェイ作成
func CreateNewMobileGateway(values *CreateMobileGatewayValue, setting *MobileGatewaySetting) (*MobileGateway, error) {

	lb := &MobileGateway{
		Appliance: &Appliance{
			Class:           "mobilegateway",
			propName:        propName{Name: values.Name},
			propDescription: propDescription{Description: values.Description},
			propTags:        propTags{Tags: values.Tags},
			propPlanID:      propPlanID{Plan: &Resource{ID: int64(MobileGatewayPlanStandard)}},
			propIcon: propIcon{
				&Icon{
					Resource: NewResource(values.IconID),
				},
			},
		},
		Remark: &MobileGatewayRemark{
			ApplianceRemarkBase: &ApplianceRemarkBase{
				Switch: &ApplianceRemarkSwitch{
					propScope: propScope{
						Scope: "shared",
					},
				},
				Servers: []interface{}{
					nil,
				},
			},
		},
		Settings: &MobileGatewaySettings{
			MobileGateway: setting,
		},
	}

	return lb, nil
}

// SetPrivateInterface プライベート側NICの接続
func (m *MobileGateway) SetPrivateInterface(ip string, nwMaskLen int) {
	if len(m.Settings.MobileGateway.Interfaces) > 1 {
		m.Settings.MobileGateway.Interfaces[1].IPAddress = []string{ip}
		m.Settings.MobileGateway.Interfaces[1].NetworkMaskLen = nwMaskLen
	} else {
		nic := &MGWInterface{
			IPAddress:      []string{ip},
			NetworkMaskLen: nwMaskLen,
		}
		m.Settings.MobileGateway.Interfaces = append(m.Settings.MobileGateway.Interfaces, nic)
	}
}

// ClearPrivateInterface プライベート側NICの切断
func (m *MobileGateway) ClearPrivateInterface() {
	m.Settings.MobileGateway.Interfaces = []*MGWInterface{nil}
}

// HasSetting モバイルゲートウェイ設定を保持しているか
func (m *MobileGateway) HasSetting() bool {
	return m.Settings != nil && m.Settings.MobileGateway != nil
}

// HasStaticRoutes スタティックルートを保持しているか
func (m *MobileGateway) HasStaticRoutes() bool {
	return m.HasSetting() && m.Settings.MobileGateway.HasStaticRoutes()
}

// NewMobileGatewayResolver DNS登録用パラメータ作成
func NewMobileGatewayResolver(dns1, dns2 string) *MobileGatewayResolver {
	return &MobileGatewayResolver{
		SimGroup: &MobileGatewaySIMGroup{
			DNS1: dns1,
			DNS2: dns2,
		},
	}
}

// MobileGatewayResolver DNS登録用パラメータ
type MobileGatewayResolver struct {
	SimGroup *MobileGatewaySIMGroup `json:"sim_group,omitempty"`
}

// UnmarshalJSON JSONアンマーシャル(配列、オブジェクトが混在するためここで対応)
func (m *MobileGatewaySIMGroup) UnmarshalJSON(data []byte) error {
	targetData := strings.Replace(strings.Replace(string(data), " ", "", -1), "\n", "", -1)
	if targetData == `[]` {
		return nil
	}

	tmp := &struct {
		DNS1 string `json:"dns_1,omitempty"`
		DNS2 string `json:"dns_2,omitempty"`
	}{}
	if err := json.Unmarshal(data, &tmp); err != nil {
		return err
	}

	m.DNS1 = tmp.DNS1
	m.DNS2 = tmp.DNS2
	return nil
}

// MobileGatewaySIMGroup DNS登録用SIMグループ値
type MobileGatewaySIMGroup struct {
	DNS1 string `json:"dns_1,omitempty"`
	DNS2 string `json:"dns_2,omitempty"`
}

// MobileGatewaySIMRoute SIルート
type MobileGatewaySIMRoute struct {
	ICCID      string `json:"iccid,omitempty"`
	Prefix     string `json:"prefix,omitempty"`
	ResourceID string `json:"resource_id,omitempty"`
}

// MobileGatewaySIMRoutes SIMルート一覧
type MobileGatewaySIMRoutes struct {
	SIMRoutes []*MobileGatewaySIMRoute `json:"sim_routes"`
}

// AddSIMRoute SIMルート追加
func (m *MobileGatewaySIMRoutes) AddSIMRoute(simID int64, prefix string) (int, *MobileGatewaySIMRoute) {
	var exists bool
	for _, route := range m.SIMRoutes {
		if route.ResourceID == fmt.Sprintf("%d", simID) && route.Prefix == prefix {
			exists = true
			break
		}
	}
	if !exists {
		r := &MobileGatewaySIMRoute{
			ResourceID: fmt.Sprintf("%d", simID),
			Prefix:     prefix,
		}
		m.SIMRoutes = append(m.SIMRoutes, r)
		return len(m.SIMRoutes) - 1, r
	}
	return -1, nil
}

// DeleteSIMRoute SIMルート削除
func (m *MobileGatewaySIMRoutes) DeleteSIMRoute(simID int64, prefix string) bool {
	routes := []*MobileGatewaySIMRoute{} // nolint (JSONヘのMarshal時に要素が0の場合にNULLではなく[]とするため)
	var exists bool

	for _, route := range m.SIMRoutes {
		if route.ResourceID == fmt.Sprintf("%d", simID) && route.Prefix == prefix {
			exists = true
		} else {
			routes = append(routes, route)
		}
	}
	m.SIMRoutes = routes
	return exists
}

// DeleteSIMRouteAt SIMルート削除
func (m *MobileGatewaySIMRoutes) DeleteSIMRouteAt(index int) bool {
	if m.SIMRoutes == nil {
		return false
	}

	if index < len(m.SIMRoutes) {
		s := m.SIMRoutes[index]
		if simID, err := strconv.ParseInt(s.ResourceID, 10, 64); err == nil {
			return m.DeleteSIMRoute(simID, s.Prefix)
		}
	}
	return false
}

// FindSIMRoute SIMルート設定 検索
func (m *MobileGatewaySIMRoutes) FindSIMRoute(simID int64, prefix string) (int, *MobileGatewaySIMRoute) {
	for i, r := range m.SIMRoutes {
		if r.Prefix == prefix && r.ResourceID == fmt.Sprintf("%d", simID) {
			return i, r
		}
	}
	return -1, nil
}
