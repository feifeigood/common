package tuntap

import (
	"errors"
	"net"
	"unsafe"
)

func parse4(addr string) [4]byte {
	ip := net.ParseIP(addr).To4()
	return *(*[4]byte)(unsafe.Pointer(&ip[0]))
}

func parse6(addr string) [16]byte {
	ip := net.ParseIP(addr).To16()
	return *(*[16]byte)(unsafe.Pointer(&ip[0]))
}

func NewTun(name string) (*Tun, error) {
	return CreateTun(name, 1500)
}

func NewTunWithMTU(name string, mtu int) (*Tun, error) {
	return CreateTun(name, mtu)
}

// 192.168.1.11/24
// fe80:08ef:ae86:68ef::11/64
func (a *Tun) SetInterfaceAddress(addr string) error {
	if addr, mask, gw, err := getV4(addr); err == nil {
		return a.setInterfaceAddress4(addr, mask, gw)
	}

	if addr, mask, gw, err := getV6(addr); err == nil {
		return a.setInterfaceAddress6(addr, mask, gw)
	}
	return errors.New("invalid interface address")
}

func getV4(cidr string) (addr, mask, gw string, err error) {

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}

	ipv4 := ip.To4()
	if ipv4 == nil {
		err = errors.New("not ipv4 address")
		return
	}

	addr = ipv4.String()
	mask = net.IP(ipnet.Mask).String()
	ipv4 = ipnet.IP.To4()
	ipv4[net.IPv4len-1]++
	gw = ipv4.String()

	return
}

func getV6(cidr string) (addr, mask, gw string, err error) {

	ip, ipnet, err := net.ParseCIDR(cidr)
	if err != nil {
		return
	}

	ipv6 := ip.To16()
	if ipv6 == nil {
		err = errors.New("not ipv6 address")
		return
	}

	addr = ipv6.String()
	mask = net.IP(ipnet.Mask).String()
	ipv6 = ipnet.IP.To16()
	ipv6[net.IPv6len-1]++
	gw = ipv6.String()

	return
}

// 198.18.0.0/16
// 8.8.8.8/32
func (a *Tun) AddRouteEntry(cidr []string) error {
	cidr4 := make([]string, 0, len(cidr))
	cidr6 := make([]string, 0, len(cidr))
	for _, item := range cidr {
		ip, _, err := net.ParseCIDR(item)
		if err != nil {
			return err
		}
		if ip.To4() != nil {
			cidr4 = append(cidr4, item)
			continue
		}
		if ip.To16() != nil {
			cidr6 = append(cidr6, item)
			continue
		}
	}

	if len(cidr4) > 0 {
		if err := a.addRouteEntry4(cidr4); err != nil {
			return err
		}
	}
	if len(cidr6) > 0 {
		err := a.addRouteEntry6(cidr6)
		return err
	}

	return nil
}
