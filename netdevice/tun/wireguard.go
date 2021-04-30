// build !linux

package tun

import (
	"fmt"

	"github.com/feifeigood/common/netdevice"
	"github.com/feifeigood/common/netdevice/rwbased"
	"golang.zx2c4.com/wireguard/tun"
)

type TUN struct {
	*rwbased.Endpoint

	nt   *tun.NativeTun
	mtu  uint32
	name string
}

func Open(opts ...Option) (netdevice.Device, error) {
	tundevice := &TUN{}

	for _, fn := range opts {
		fn(tundevice)
	}

	mtu := defaultMTU
	if tundevice.mtu > 0 {
		mtu = int(tundevice.mtu)
	}

	nt, err := tun.CreateTUN(tundevice.name, mtu)
	if err != nil {
		return nil, fmt.Errorf("create tun: %s", err)
	}

	tundevice.nt = nt.(*tun.NativeTun)

	mtu, err = tundevice.nt.MTU()
	if err != nil {
		return nil, fmt.Errorf("get mtu: %s", err)
	}
	tundevice.mtu = uint32(mtu)

	ep, err := rwbased.New(tundevice, tundevice.mtu)
	if err != nil {
		return nil, fmt.Errorf("create endpoint: %s", err)
	}
	tundevice.Endpoint = ep

	return tundevice, nil
}

func (t *TUN) Name() string {
	name, _ := t.nt.Name()
	return name
}

func (t *TUN) Close() error {
	return t.nt.Close()
}

func (t *TUN) Type() string {
	return "tun"
}
