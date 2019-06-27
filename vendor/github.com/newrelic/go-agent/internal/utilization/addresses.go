package utilization

import (
	"fmt"
	"net"
)

func nonlocalIPAddressesByInterface() (map[string][]string, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	ips := make(map[string][]string, len(ifaces))
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, addr := range addrs {
			var ip net.IP
			switch iptype := addr.(type) {
			case *net.IPAddr:
				ip = iptype.IP
			case *net.IPNet:
				ip = iptype.IP
			case *net.TCPAddr:
				ip = iptype.IP
			case *net.UDPAddr:
				ip = iptype.IP
			}
			if nil != ip && !ip.IsLoopback() && !ip.IsUnspecified() {
				ips[ifc.Name] = append(ips[ifc.Name], ip.String())
			}
		}
	}
	return ips, nil
}

// utilizationIPs gathers IP address which may help identify this entity. This
// code chooses all IPs from the interface which contains the IP of a UDP
// connection with NR.  This approach has the following advantages:
// * Matches the behavior of the Java agent.
// * Reports fewer IPs to lower linking burden on infrastructure backend.
// * The UDP connection interface is more likely to contain unique external IPs.
func utilizationIPs() ([]string, error) {
	// Port choice designed to match
	// https://source.datanerd.us/java-agent/java_agent/blob/master/newrelic-agent/src/main/java/com/newrelic/agent/config/Hostname.java#L110
	conn, err := net.Dial("udp", "newrelic.com:10002")
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	addr, ok := conn.LocalAddr().(*net.UDPAddr)

	if !ok || nil == addr || addr.IP.IsLoopback() || addr.IP.IsUnspecified() {
		return nil, fmt.Errorf("unexpected connection address: %v", conn.LocalAddr())
	}
	outboundIP := addr.IP.String()

	ipsByInterface, err := nonlocalIPAddressesByInterface()
	if err != nil {
		return nil, err
	}
	for _, ips := range ipsByInterface {
		for _, ip := range ips {
			if ip == outboundIP {
				return ips, nil
			}
		}
	}
	return nil, nil
}
