// +build darwin linux

package tuntap

import (
	"golang.zx2c4.com/wireguard/tun"
)

type Tun struct {
	*tun.NativeTun
	Name     string
	MTU      int
	Gateway4 [4]byte
	Gateway6 [16]byte
}

func CreateTun(name string, mtu int) (adapter *Tun, err error) {
	adapter = &Tun{}
	device, err := tun.CreateTUN(name, mtu)
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
	return "UnixTun"
}

func (a *Tun) GetMTU() int {
	return a.MTU
}
