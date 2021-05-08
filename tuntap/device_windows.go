// +build windows

package tuntap

import "golang.zx2c4.com/wireguard/tun"

const (
	offset = 0

	defaultMTU = 0 /* auto */
)

type device struct {
	ifce *tun.NativeTun
}

func (d *device) Name() string {
	name, _ := d.ifce.Name()
	return name
}
func (d *device) Close() error { return d.ifce.Close() }
func (d *device) Read(p []byte) (n int, err error) {
	return d.ifce.Read(p, offset)
}
func (d *device) Write(p []byte) (n int, err error) {
	return d.ifce.Write(p, offset)
}
func (d *device) String() string {
	return "TUN"
}

func newTUN(name string) (Interface, error) {
	// TODO: https://github.com/WireGuard/wireguard-go implement by wintun
	return nil, ErrUnsupported
}

func newTAP(name string) (Interface, error) {
	return nil, ErrUnsupported
}
