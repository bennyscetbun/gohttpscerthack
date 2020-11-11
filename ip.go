package gohttpscerthack

import (
	"net"
)

// GetLocalIPs is a helper to retrieve all the local ips
func GetLocalIPs() ([]net.IP, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	var ret []net.IP
	for _, i := range ifaces {
		addrs, err := i.Addrs()
		if err != nil {
			return nil, err
		}
		for _, a := range addrs {
			switch v := a.(type) {
			case *net.IPAddr:
				ret = append(ret, v.IP)
			case *net.IPNet:
				ret = append(ret, v.IP)
			}
		}
	}
	return ret, nil
}
