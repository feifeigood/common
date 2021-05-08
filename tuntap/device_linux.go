// +build linux

package tuntap

import "github.com/songgao/water"

type device struct {
	ifce *water.Interface
}

func (d *device) Name() string { return d.ifce.Name() }
func (d *device) Close() error { return d.ifce.Close() }
func (d *device) Read(p []byte) (n int, err error) {
	return d.ifce.Read(p)
}
func (d *device) Write(p []byte) (n int, err error) {
	return d.ifce.Write(p)
}
func (d *device) String() string {
	if d.ifce.IsTAP() {
		return "TAP"
	}
	return "TUN"
}

func newTUN(name string) (Interface, error) {
	return nil, ErrUnsupported
}

func newTAP(name string) (Interface, error) {
	cfg := water.Config{
		DeviceType: water.TAP,
	}
	cfg.Name = name
	ifce, err := water.New(cfg)

	if err != nil {
		return nil, err
	}

	return &device{ifce: ifce}, nil
}
