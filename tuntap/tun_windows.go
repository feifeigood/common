// +build windows

package tuntap

import (
	"bytes"
	"crypto/md5"
	"errors"
	"io"
	"net"
	"sort"
	"unsafe"

	"golang.org/x/crypto/hkdf"
	"golang.org/x/sys/windows"

	"golang.zx2c4.com/wireguard/tun"
	"golang.zx2c4.com/wireguard/windows/tunnel"
	"golang.zx2c4.com/wireguard/windows/tunnel/winipcfg"
)

// determineGUID is ...
// generate GUID from tun name
func determineGUID(name string) *windows.GUID {
	b := make([]byte, unsafe.Sizeof(windows.GUID{}))
	if _, err := io.ReadFull(hkdf.New(md5.New, []byte(name), nil, nil), b); err != nil {
		return nil
	}
	return (*windows.GUID)(unsafe.Pointer(&b[0]))
}

type Tun struct {
	*tun.NativeTun
	Name string
	MTU  int
}

func CreateTun(name string, mtu int) (adapter *Tun, err error) {
	adapter = &Tun{}
	device, err := tun.CreateTUNWithRequestedGUID(name, determineGUID(name), mtu)
	if err != nil {
		return
	}
	adapter.NativeTun = device.(*tun.NativeTun)
	if adapter.Name, err = adapter.NativeTun.Name(); err != nil {
		return
	}
	if adapter.MTU, err = adapter.NativeTun.MTU(); err != nil {
		return
	}
	return
}

func (a *Tun) DeviceType() string {
	return "WinTun"
}

func (a *Tun) GetMTU() int {
	return a.MTU
}

func (a *Tun) Write(buff []byte, offset int) (int, error) {
	return a.NativeTun.Write(b, 0)
}

func (a *Tun) Read(buff []byte, offset int) (int, error) {
	return a.NativeTun.Read(buff, 0)
}

func (a *Tun) setInterfaceAddress4(addr, mask, gw string) error {
	luid := winipcfg.LUID(d.NativeTun.LUID())

	addresses := append([]net.IPNet{}, net.IPNet{
		IP:   net.ParseIP(addr).To4(),
		Mask: net.IPMask(net.ParseIP(mask).To4()),
	})

	err := luid.SetIPAddressesForFamily(windows.AF_INET, addresses)
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		cleanupAddressesOnDisconnectedInterfaces(windows.AF_INET, addresses)
		err = luid.SetIPAddressesForFamily(windows.AF_INET, addresses)
	}
	if err != nil {
		return err
	}

	err = luid.SetDNS(windows.AF_INET, []net.IP{net.ParseIP(gw).To4()}, []string{})
	return err
}

func (a *Tun) setInterfaceAddress6(addr, mask, gw string) error {
	luid := winipcfg.LUID(d.NativeTun.LUID())

	addresses := append([]net.IPNet{}, net.IPNet{
		IP:   net.ParseIP(addr).To16(),
		Mask: net.IPMask(net.ParseIP(mask).To16()),
	})

	err := luid.SetIPAddressesForFamily(windows.AF_INET6, addresses)
	if errors.Is(err, windows.ERROR_OBJECT_ALREADY_EXISTS) {
		cleanupAddressesOnDisconnectedInterfaces(windows.AF_INET6, addresses)
		err = luid.SetIPAddressesForFamily(windows.AF_INET6, addresses)
	}
	if err != nil {
		return err
	}

	err = luid.SetDNS(windows.AF_INET6, []net.IP{net.ParseIP(gw).To16()}, []string{})
	return err
}

// addRouteEntry is ...
func (a *Tun) addRouteEntry4(cidr []string) error {
	luid := winipcfg.LUID(a.NativeTun.LUID())

	routes := make([]winipcfg.RouteData, 0, len(cidr))
	for _, item := range cidr {
		_, ipNet, err := net.ParseCIDR(item)
		if err != nil {
			return err
		}
		routes = append(routes, winipcfg.RouteData{
			Destination: *ipNet,
			NextHop:     net.IPv4zero,
			Metric:      0,
		})
	}

	deduplicatedRoutes := make([]*winipcfg.RouteData, 0, len(routes))
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Metric != routes[j].Metric {
			return routes[i].Metric < routes[j].Metric
		}
		if c := bytes.Compare(routes[i].NextHop, routes[j].NextHop); c != 0 {
			return c < 0
		}
		if c := bytes.Compare(routes[i].Destination.IP, routes[j].Destination.IP); c != 0 {
			return c < 0
		}
		if c := bytes.Compare(routes[i].Destination.Mask, routes[j].Destination.Mask); c != 0 {
			return c < 0
		}
		return false
	})
	for i := 0; i < len(routes); i++ {
		if i > 0 && routes[i].Metric == routes[i-1].Metric &&
			bytes.Equal(routes[i].NextHop, routes[i-1].NextHop) &&
			bytes.Equal(routes[i].Destination.IP, routes[i-1].Destination.IP) &&
			bytes.Equal(routes[i].Destination.Mask, routes[i-1].Destination.Mask) {
			continue
		}
		deduplicatedRoutes = append(deduplicatedRoutes, &routes[i])
	}

	return luid.SetRoutesForFamily(windows.AF_INET, deduplicatedRoutes)
}

// addRouteEntry6 is ...
func (a *Tun) addRouteEntry6(cidr []string) error {
	luid := winipcfg.LUID(a.NativeTun.LUID())

	routes := make([]winipcfg.RouteData, 0, len(cidr))
	for _, item := range cidr {
		_, ipNet, err := net.ParseCIDR(item)
		if err != nil {
			return err
		}
		routes = append(routes, winipcfg.RouteData{
			Destination: *ipNet,
			NextHop:     net.IPv6zero,
			Metric:      0,
		})
	}

	deduplicatedRoutes := make([]*winipcfg.RouteData, 0, len(routes))
	sort.Slice(routes, func(i, j int) bool {
		if routes[i].Metric != routes[j].Metric {
			return routes[i].Metric < routes[j].Metric
		}
		if c := bytes.Compare(routes[i].NextHop, routes[j].NextHop); c != 0 {
			return c < 0
		}
		if c := bytes.Compare(routes[i].Destination.IP, routes[j].Destination.IP); c != 0 {
			return c < 0
		}
		if c := bytes.Compare(routes[i].Destination.Mask, routes[j].Destination.Mask); c != 0 {
			return c < 0
		}
		return false
	})
	for i := 0; i < len(routes); i++ {
		if i > 0 && routes[i].Metric == routes[i-1].Metric &&
			bytes.Equal(routes[i].NextHop, routes[i-1].NextHop) &&
			bytes.Equal(routes[i].Destination.IP, routes[i-1].Destination.IP) &&
			bytes.Equal(routes[i].Destination.Mask, routes[i-1].Destination.Mask) {
			continue
		}
		deduplicatedRoutes = append(deduplicatedRoutes, &routes[i])
	}

	return luid.SetRoutesForFamily(windows.AF_INET6, deduplicatedRoutes)
}

// use golang.zx2c4.com/wireguard/windows/tunnel
var _ = tunnel.UseFixedGUIDInsteadOfDeterministic

// cleanupAddressesOnDisconnectedInterfaces is ...
// https://github.com/WireGuard/wireguard-windows/blob/master/tunnel/addressconfig.go#L22
//
//go:linkname cleanupAddressesOnDisconnectedInterfaces golang.zx2c4.com/wireguard/windows/tunnel.cleanupAddressesOnDisconnectedInterfaces
func cleanupAddressesOnDisconnectedInterfaces(family winipcfg.AddressFamily, addresses []net.IPNet)
