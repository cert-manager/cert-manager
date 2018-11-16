package sacloud

// VPCRouterStatus VPCルータのステータス情報
type VPCRouterStatus struct {
	FirewallReceiveLogs []string
	FirewallSendLogs    []string
	VPNLogs             []string
	DHCPServerLeases    []struct {
		IPAddress  string
		MACAddress string
	}
	L2TPIPsecServerSessions []struct {
		User      string
		IPAddress string
		TimeSec   string
	}
	PPTPServerSessions []struct {
		User      string
		IPAddress string
		TimeSec   string
	}
	SiteToSiteIPsecVPNPeers []struct {
		Status string
		Peer   string
	}
}
